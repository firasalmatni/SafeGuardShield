import ctypes
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.request
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import mss
import numpy as np
import onnxruntime as ort
import pystray
import tkinter as tk
from PIL import Image, ImageDraw, ImageFilter, ImageTk
from tkinter import messagebox, simpledialog

# ثوابت نظام ويندوز
WDA_EXCLUDEFROMCAPTURE = 0x00000011
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0x00000000

APP_NAME = "SafeGuardShield"
REG_PATH = r"Software\SafeGuardShield"
EXIT_EVENT_NAME = "Local\\SafeGuardShield_AuthorizedExit_v2"
MAIN_MUTEX_NAME = "Local\\SafeGuardShield_SingleInstance_v2"
HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_START_MARKER = "# >>> SAFEGUARD_SHIELD_BLOCKLIST_START"
HOSTS_END_MARKER = "# <<< SAFEGUARD_SHIELD_BLOCKLIST_END"

# الترتيب الرسمي الدقيق لفئات NudeNet v3 (640m.onnx / 320n.onnx)
NUDENET_LABELS = [
    "FEMALE_GENITALIA_COVERED",
    "FACE_FEMALE",
    "BUTTOCKS_EXPOSED",
    "FEMALE_BREAST_EXPOSED",
    "FEMALE_GENITALIA_EXPOSED",
    "MALE_BREAST_EXPOSED",
    "ANUS_EXPOSED",
    "FEET_EXPOSED",
    "BELLY_COVERED",
    "FEET_COVERED",
    "ARMPITS_COVERED",
    "ARMPITS_EXPOSED",
    "FACE_MALE",
    "BELLY_EXPOSED",
    "MALE_GENITALIA_EXPOSED",
    "ANUS_COVERED",
    "FEMALE_BREAST_COVERED",
    "BUTTOCKS_COVERED",
]

# مزودو DNS الآمن لحجب المواقع الإباحية
DNS_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare Family (1.1.1.3)",
        "ipv4": ("1.1.1.3", "1.0.0.3"),
        "ipv6": ("2606:4700:4700::1113", "2606:4700:4700::1003"),
    },
    "cleanbrowsing": {
        "name": "CleanBrowsing Adult Filter",
        "ipv4": ("185.228.168.168", "185.228.169.168"),
        "ipv6": ("2a0d:2a00:1::1", "2a0d:2a00:2::1"),
    },
}

# مصادر قوائم حجب المواقع الإباحية المحدثة (مفتوحة المصدر)
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
]

# كلمات مفتاحية لحماية استباقية فورية لعناوين تبويبات المتصفح
SUSPICIOUS_TITLE_TOKENS = (
    "pornhub", "xvideos", "xnxx", "xhamster", "redtube", "youporn",
    "brazzers", "onlyfans", "chaturbate", "stripchat", "spankbang",
    "eporner", "hentai", "rule34", "nsfw", "سكس", "افلام اباحية", "أفلام إباحية",
)


# ==============================================================================
# 1. إعدادات النظام المخزنة بأمان في سجل ويندوز (Registry)
# ==============================================================================
@dataclass
class ShieldConfig:
    enabled: bool = True
    full_screen_blur: bool = False
    strict_mode: bool = False
    dns_lock_provider: str = ""          # "", "cloudflare", "cleanbrowsing"
    title_guard_enabled: bool = True
    box_padding: int = 44
    hold_seconds: float = 1.4
    frame_diff_threshold: float = 1.5
    min_skin_ratio: float = 0.012        # تخطي فحص الـ AI إذا كانت الشاشة نصية خالصة (توفير 80% من المعالج)
    pin_hash: Optional[str] = None

    base_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "FEMALE_GENITALIA_EXPOSED": 0.36,
            "MALE_GENITALIA_EXPOSED": 0.36,
            "FEMALE_BREAST_EXPOSED": 0.42,
            "BUTTOCKS_EXPOSED": 0.48,
            "ANUS_EXPOSED": 0.38,
        }
    )

    strict_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "FEMALE_BREAST_COVERED": 0.58,
            "FEMALE_GENITALIA_COVERED": 0.58,
            "BUTTOCKS_COVERED": 0.60,
            "BELLY_EXPOSED": 0.70,
        }
    )

    def active_thresholds(self) -> Dict[str, float]:
        merged = dict(self.base_thresholds)
        if self.strict_mode:
            merged.update(self.strict_thresholds)
        return merged

    def load_from_registry(self) -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
                for attr, reg_type in [
                    ("full_screen_blur", int),
                    ("strict_mode", int),
                    ("title_guard_enabled", int),
                    ("dns_lock_provider", str),
                    ("pin_hash", str),
                ]:
                    try:
                        val, _ = winreg.QueryValueEx(key, attr)
                        if reg_type is int:
                            setattr(self, attr, bool(val))
                        else:
                            setattr(self, attr, val if val else (None if attr == "pin_hash" else ""))
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            pass

    def save_to_registry(self) -> None:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
                winreg.SetValueEx(key, "full_screen_blur", 0, winreg.REG_DWORD, int(self.full_screen_blur))
                winreg.SetValueEx(key, "strict_mode", 0, winreg.REG_DWORD, int(self.strict_mode))
                winreg.SetValueEx(key, "title_guard_enabled", 0, winreg.REG_DWORD, int(self.title_guard_enabled))
                winreg.SetValueEx(key, "dns_lock_provider", 0, winreg.REG_SZ, self.dns_lock_provider or "")
                winreg.SetValueEx(key, "pin_hash", 0, winreg.REG_SZ, self.pin_hash or "")
        except Exception:
            pass


# ==============================================================================
# 2. أدوات حماية النظام: DNS + Hosts + مقاومة DoH + التشغيل التلقائي
# ==============================================================================
class SystemGuardian:
    @staticmethod
    def is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def relaunch_as_admin() -> bool:
        """إعادة تشغيل التطبيق بصلاحيات المسؤول لتعديل DNS وملف hosts."""
        try:
            if getattr(sys, "frozen", False):
                exe = sys.executable
                params = ""
            else:
                exe = sys.executable
                params = f'"{os.path.abspath(__file__)}"'
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            return ret > 32
        except Exception:
            return False

    @staticmethod
    def _run_hidden(cmd: List[str], timeout: int = 20) -> Tuple[int, str]:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.returncode, (proc.stdout + "\n" + proc.stderr).strip()

    @classmethod
    def get_active_interfaces(cls) -> List[str]:
        """استخراج أسماء جميع كروت الشبكة المتصلة حالياً على ويندوز."""
        ps_cmd = (
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
            "Select-Object -ExpandProperty Name"
        )
        code, out = cls._run_hidden(["powershell", "-NoProfile", "-Command", ps_cmd])
        if code == 0 and out.strip():
            return [line.strip() for line in out.splitlines() if line.strip()]
        return ["Wi-Fi", "Ethernet"]

    @classmethod
    def apply_safe_dns(cls, provider_key: str = "cloudflare") -> Tuple[bool, str]:
        if not cls.is_admin():
            return False, "تحتاج هذه الميزة لصلاحيات المسؤول (Run as Administrator)."
        if provider_key not in DNS_PROVIDERS:
            return False, "مزود DNS غير معروف."

        provider = DNS_PROVIDERS[provider_key]
        ipv4_1, ipv4_2 = provider["ipv4"]
        ipv6_1, ipv6_2 = provider["ipv6"]
        interfaces = cls.get_active_interfaces()

        applied = 0
        for iface in interfaces:
            c1, _ = cls._run_hidden(
                ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={iface}", "source=static", f"address={ipv4_1}", "validate=no"]
            )
            cls._run_hidden(
                ["netsh", "interface", "ipv4", "add", "dnsservers", f"name={iface}", f"address={ipv4_2}", "index=2", "validate=no"]
            )
            cls._run_hidden(
                ["netsh", "interface", "ipv6", "set", "dnsservers", f"name={iface}", "source=static", f"address={ipv6_1}", "validate=no"]
            )
            cls._run_hidden(
                ["netsh", "interface", "ipv6", "add", "dnsservers", f"name={iface}", f"address={ipv6_2}", "index=2", "validate=no"]
            )
            if c1 == 0:
                applied += 1

        # منع Chrome و Edge من تجاوز DNS النظام عبر DNS-over-HTTPS
        cls._set_browser_doh_policy(disable_doh=True)
        cls._run_hidden(["ipconfig", "/flushdns"])

        if applied > 0:
            return True, f"تم تفعيل {provider['name']} على ({applied}) شبكة بنجاح."
        return False, "لم يتم العثور على واجهة شبكة نشطة لتطبيق DNS."

    @classmethod
    def restore_dhcp_dns(cls) -> Tuple[bool, str]:
        if not cls.is_admin():
            return False, "تحتاج هذه الميزة لصلاحيات المسؤول."
        for iface in cls.get_active_interfaces():
            cls._run_hidden(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={iface}", "source=dhcp"])
            cls._run_hidden(["netsh", "interface", "ipv6", "set", "dnsservers", f"name={iface}", "source=dhcp"])
        cls._set_browser_doh_policy(disable_doh=False)
        cls._run_hidden(["ipconfig", "/flushdns"])
        return True, "تمت إعادة إعدادات DNS للوضع التلقائي."

    @staticmethod
    def _set_browser_doh_policy(disable_doh: bool) -> None:
        policies = [
            r"SOFTWARE\Policies\Google\Chrome",
            r"SOFTWARE\Policies\Microsoft\Edge",
            r"SOFTWARE\Policies\BraveSoftware\Brave",
        ]
        for path in policies:
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    if disable_doh:
                        winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
                    else:
                        try:
                            winreg.DeleteValue(key, "DnsOverHttpsMode")
                        except FileNotFoundError:
                            pass
            except Exception:
                pass

    @classmethod
    def sync_hosts_blocklist(cls) -> Tuple[bool, str]:
        """سحب قائمة حجب المواقع الإباحية الشاملة ودمجها بأمان في ملف hosts."""
        if not cls.is_admin():
            return False, "يلزم تشغيل التطبيق كمسؤول لتحديث ملف hosts."

        raw_text = None
        for url in BLOCKLIST_URLS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SafeGuardShield/2.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw_text = resp.read().decode("utf-8", errors="ignore")
                if raw_text and "0.0.0.0" in raw_text:
                    break
            except Exception:
                continue

        if not raw_text:
            return False, "تعذر تحميل قائمة الحجب من الإنترنت. تحقق من الاتصال."

        domains = set()
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                dom = parts[1].lower().strip()
                if dom and dom not in ("0.0.0.0", "localhost", "localhost.localdomain", "broadcasthost"):
                    domains.add(dom)

        if not domains:
            return False, "القائمة المحمّلة لا تحتوي نطاقات صالحة."

        try:
            existing = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
            cleaned = cls._strip_managed_hosts_section(existing)
            block_lines = [HOSTS_START_MARKER] + [f"0.0.0.0 {d}" for d in sorted(domains)] + [HOSTS_END_MARKER]
            new_content = cleaned.rstrip() + "\n\n" + "\n".join(block_lines) + "\n"
            HOSTS_PATH.write_text(new_content, encoding="utf-8")
            cls._run_hidden(["ipconfig", "/flushdns"])
            return True, f"تم حجب {len(domains):,} موقع إباحي داخل ملف hosts بنجاح."
        except Exception as exc:
            return False, f"فشل تعديل ملف hosts: {exc}"

    @classmethod
    def clear_hosts_blocklist(cls) -> Tuple[bool, str]:
        if not cls.is_admin():
            return False, "يلزم تشغيل التطبيق كمسؤول."
        try:
            if HOSTS_PATH.exists():
                existing = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
                cleaned = cls._strip_managed_hosts_section(existing)
                HOSTS_PATH.write_text(cleaned.rstrip() + "\n", encoding="utf-8")
                cls._run_hidden(["ipconfig", "/flushdns"])
            return True, "تمت إزالة قائمة الحجب من ملف hosts."
        except Exception as exc:
            return False, f"فشل التعديل: {exc}"

    @staticmethod
    def _strip_managed_hosts_section(content: str) -> str:
        lines = content.splitlines()
        result = []
        inside = False
        for line in lines:
            if line.strip() == HOSTS_START_MARKER:
                inside = True
                continue
            if line.strip() == HOSTS_END_MARKER:
                inside = False
                continue
            if not inside:
                result.append(line)
        return "\n".join(result)

    @classmethod
    def install_system_autostart(cls) -> Tuple[bool, str]:
        """تثبيت التشغيل التلقائي عبر مجدول مهام ويندوز (بأعلى صلاحية) أو سجل التشغيل."""
        if getattr(sys, "frozen", False):
            target = f'"{sys.executable}"'
        else:
            target = f'"{sys.executable}" "{os.path.abspath(__file__)}"'

        if cls.is_admin():
            code, out = cls._run_hidden([
                "schtasks", "/Create",
                "/TN", f"{APP_NAME}_AutoProtect",
                "/TR", target,
                "/SC", "ONLOGON",
                "/RL", "HIGHEST",
                "/F",
            ])
            if code == 0:
                return True, "تم التثبيت كخدمة تلقائية مع إقلاع ويندوز (بصلاحيات المسؤول)."

        # بديل في حال التشغيل بدون صلاحيات مسؤول
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, target)
            return True, "تم تفعيل التشغيل التلقائي مع بداية ويندوز."
        except Exception as exc:
            return False, f"تعذر التثبيت التلقائي: {exc}"


# ==============================================================================
# 3. نظام الحارس المزدوج (Watchdog) لمقاومة الإنهاء من Task Manager
# ==============================================================================
class WatchdogSystem:
    @staticmethod
    def create_exit_event():
        return ctypes.windll.kernel32.CreateEventW(None, True, False, EXIT_EVENT_NAME)

    @staticmethod
    def signal_authorized_exit(event_handle) -> None:
        if event_handle:
            ctypes.windll.kernel32.SetEvent(event_handle)

    @staticmethod
    def is_authorized_exit_set() -> bool:
        evt = ctypes.windll.kernel32.OpenEventW(SYNCHRONIZE, False, EXIT_EVENT_NAME)
        if not evt:
            return False
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(evt, 0) == WAIT_OBJECT_0
        finally:
            ctypes.windll.kernel32.CloseHandle(evt)

    @staticmethod
    def spawn_command(extra_args: List[str]) -> List[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable] + extra_args
        return [sys.executable, os.path.abspath(__file__)] + extra_args

    @classmethod
    def run_watchdog_loop(cls, target_pid: int) -> None:
        """عملية الحارس الثانية: تراقب التطبيق الرئيسي وتعيد تشغيله فوراً إن أُغلق عنوة."""
        kernel32 = ctypes.windll.kernel32
        current_pid = target_pid

        while True:
            if cls.is_authorized_exit_set():
                return

            h_proc = kernel32.OpenProcess(SYNCHRONIZE, False, current_pid)
            if not h_proc:
                # العملية الرئيسية اختفت بدون إذن
                if cls.is_authorized_exit_set():
                    return
                proc = subprocess.Popen(
                    cls.spawn_command([]),
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                current_pid = proc.pid
                time.sleep(1.0)
                continue

            try:
                while True:
                    res = kernel32.WaitForSingleObject(h_proc, 400)
                    if cls.is_authorized_exit_set():
                        return
                    if res == WAIT_OBJECT_0:
                        # تم إنهاء التطبيق الرئيسي من Task Manager -> إعادة تشغيل فورية
                        time.sleep(0.3)
                        if cls.is_authorized_exit_set():
                            return
                        proc = subprocess.Popen(
                            cls.spawn_command([]),
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        current_pid = proc.pid
                        break
            finally:
                kernel32.CloseHandle(h_proc)


# ==============================================================================
# 4. محرك الذكاء الاصطناعي NudeNet 640m المباشر (بدون OpenCV لتقليص الحجم)
# ==============================================================================
class NudeNet640Engine:
    def __init__(self, status_callback: Callable[[str], None]):
        self.status_callback = status_callback
        self.session: Optional[ort.InferenceSession] = None
        self.input_name: str = ""
        self.input_w: int = 640
        self.input_h: int = 640
        self.active_provider: str = "CPU"

    @staticmethod
    def get_model_path() -> Path:
        # 1. التحقق إن كان النموذج مدمجاً داخل الـ EXE
        if hasattr(sys, "_MEIPASS"):
            bundled = Path(sys._MEIPASS) / "640m.onnx"
            if bundled.exists() and bundled.stat().st_size > 5_000_000:
                return bundled

        # 2. التحقق إن كان بجانب ملف الـ EXE
        local_dir = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
        beside = local_dir / "640m.onnx"
        if beside.exists() and beside.stat().st_size > 5_000_000:
            return beside

        # 3. مسار الكاش الدائم في AppData (يعمل أوفلاين بعد أول تحميل)
        cache_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / "640m.onnx"

    def ensure_model_downloaded(self) -> Path:
        model_path = self.get_model_path()
        if model_path.exists() and model_path.stat().st_size > 10_000_000:
            return model_path

        self.status_callback("أول تشغيل: جاري تحميل نموذج الذكاء الاصطناعي 640m.onnx...")
        download_url = self._resolve_640m_url()
        temp_path = model_path.with_suffix(".onnx.part")

        req = urllib.request.Request(download_url, headers={"User-Agent": "SafeGuardShield/2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            last_report = 0.0
            with open(temp_path, "wb") as f:
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    now = time.perf_counter()
                    if total > 0 and (now - last_report) >= 1.0:
                        pct = int((downloaded / total) * 100)
                        self.status_callback(f"جاري تحميل نموذج 640m.onnx ({pct}%)...")
                        last_report = now

        temp_path.replace(model_path)
        return model_path

    @staticmethod
    def _resolve_640m_url() -> str:
        fallback = "https://github.com/notAI-tech/NudeNet/releases/download/v3.4-weights/640m.onnx"
        try:
            api_url = "https://api.github.com/repos/notAI-tech/NudeNet/releases"
            req = urllib.request.Request(api_url, headers={"User-Agent": "SafeGuardShield/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                releases = json.loads(resp.read().decode("utf-8"))
            for rel in releases:
                for asset in rel.get("assets", []):
                    if "640m.onnx" in asset.get("name", "").lower():
                        return asset["browser_download_url"]
        except Exception:
            pass
        return fallback

    def load(self) -> None:
        model_path = self.ensure_model_downloaded()
        self.status_callback("جاري تهيئة محرك 640m (GPU/CPU)...")

        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = max(2, min(6, (os.cpu_count() or 4) // 2))

        available = ort.get_available_providers()
        preferred = [
            p for p in ("CUDAExecutionProvider", "DmlExecutionProvider", "CPUExecutionProvider")
            if p in available
        ]
        if not preferred:
            preferred = ["CPUExecutionProvider"]

        self.session = ort.InferenceSession(str(model_path), sess_options=opts, providers=preferred)
        inp = self.session.get_inputs()[0]
        self.input_name = inp.name
        self.input_h = int(inp.shape[2]) if isinstance(inp.shape[2], int) else 640
        self.input_w = int(inp.shape[3]) if isinstance(inp.shape[3], int) else 640
        used = self.session.get_providers()[0]
        self.active_provider = "GPU" if "CPU" not in used else "CPU"
        self.status_callback(f"الحماية نشطة — نموذج 640m ({self.active_provider})")

    @staticmethod
    def has_sufficient_skin(rgb_thumb: np.ndarray, min_ratio: float) -> bool:
        """فلتر ذكي سريع في فضاء YCbCr لتخطي الشاشات النصية والبرمجية بدون استهلاك المعالج."""
        r = rgb_thumb[:, :, 0].astype(np.float32)
        g = rgb_thumb[:, :, 1].astype(np.float32)
        b = rgb_thumb[:, :, 2].astype(np.float32)
        cb = 128.0 - 0.168736 * r - 0.331264 * g + 0.5 * b
        cr = 128.0 + 0.5 * r - 0.418688 * g - 0.081312 * b
        skin_mask = (cb >= 77.0) & (cb <= 127.0) & (cr >= 133.0) & (cr <= 173.0)
        return float(np.mean(skin_mask)) >= min_ratio

    @staticmethod
    def _nms_numpy(boxes: np.ndarray, scores: np.ndarray, iou_thresh: float = 0.45) -> List[int]:
        if len(boxes) == 0:
            return []
        x1, y1, x2, y2 = boxes[:, 0], boxes[:, 1], boxes[:, 2], boxes[:, 3]
        areas = np.maximum(0.0, x2 - x1) * np.maximum(0.0, y2 - y1)
        order = scores.argsort()[::-1]
        keep = []
        while order.size > 0:
            i = int(order[0])
            keep.append(i)
            if order.size == 1:
                break
            xx1 = np.maximum(x1[i], x1[order[1:]])
            yy1 = np.maximum(y1[i], y1[order[1:]])
            xx2 = np.minimum(x2[i], x2[order[1:]])
            yy2 = np.minimum(y2[i], y2[order[1:]])
            inter = np.maximum(0.0, xx2 - xx1) * np.maximum(0.0, yy2 - yy1)
            iou = inter / (areas[i] + areas[order[1:]] - inter + 1e-6)
            inds = np.where(iou <= iou_thresh)[0]
            order = order[inds + 1]
        return keep

    def detect(self, pil_rgb: Image.Image, min_conf: float = 0.30) -> List[dict]:
        """استدلال كامل لنموذج YOLOv8 640m مع معالجة مسبقة ولاحقة بـ NumPy."""
        orig_w, orig_h = pil_rgb.size
        max_dim = max(orig_w, orig_h)

        # تجهيز مربع Padding مطابق لتدريب NudeNet v3 تماماً
        square = Image.new("RGB", (max_dim, max_dim), (0, 0, 0))
        square.paste(pil_rgb, (0, 0))
        resized = square.resize((self.input_w, self.input_h), Image.Resampling.BILINEAR)

        arr = np.asarray(resized, dtype=np.float32) / 255.0
        blob = np.transpose(arr, (2, 0, 1))[np.newaxis, ...]

        outputs = self.session.run(None, {self.input_name: blob})
        preds = np.squeeze(outputs[0]).T  # الشكل: (8400, 22)

        class_scores = preds[:, 4:]
        class_ids = np.argmax(class_scores, axis=1)
        max_scores = class_scores[np.arange(len(preds)), class_ids]

        mask = max_scores >= min_conf
        if not np.any(mask):
            return []

        preds = preds[mask]
        class_ids = class_ids[mask]
        max_scores = max_scores[mask]

        x_factor = max_dim / float(self.input_w)
        y_factor = max_dim / float(self.input_h)

        cx = preds[:, 0] * x_factor
        cy = preds[:, 1] * y_factor
        bw = preds[:, 2] * x_factor
        bh = preds[:, 3] * y_factor

        x1 = np.clip(cx - bw / 2.0, 0, orig_w)
        y1 = np.clip(cy - bh / 2.0, 0, orig_h)
        x2 = np.clip(cx + bw / 2.0, 0, orig_w)
        y2 = np.clip(cy + bh / 2.0, 0, orig_h)

        boxes = np.stack([x1, y1, x2, y2], axis=1)
        keep_indices = self._nms_numpy(boxes, max_scores, iou_thresh=0.45)

        results = []
        for idx in keep_indices:
            cid = int(class_ids[idx])
            if 0 <= cid < len(NUDENET_LABELS):
                bx1, by1, bx2, by2 = boxes[idx]
                results.append({
                    "class": NUDENET_LABELS[cid],
                    "score": float(max_scores[idx]),
                    "box": (int(bx1), int(by1), int(bx2), int(by2)),
                })
        return results


# ==============================================================================
# 5. خيط المراقبة الذكي (التقاط + فلتر بشرة + 640m + حارس عناوين)
# ==============================================================================
class ScreenMonitorWorker(threading.Thread):
    def __init__(
        self,
        config: ShieldConfig,
        overlay_queue: queue.Queue,
        status_cb: Callable[[str], None],
        notify_cb: Callable[[str, str], None],
    ):
        super().__init__(daemon=True)
        self.config = config
        self.overlay_queue = overlay_queue
        self.status_cb = status_cb
        self.notify_cb = notify_cb

        self.engine = NudeNet640Engine(status_cb)
        self._running = True
        self._prev_gray: Optional[np.ndarray] = None
        self._last_nsfw_time = 0.0
        self._was_active = False
        self._last_notify_time = 0.0
        self._last_dns_enforce = 0.0

    def force_rescan(self) -> None:
        self._prev_gray = None

    def stop(self) -> None:
        self._running = False

    @staticmethod
    def _get_foreground_title() -> str:
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return ""
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            return buf.value.lower()
        except Exception:
            return ""

    @staticmethod
    def _create_heavy_blur(pil_crop: Image.Image) -> Image.Image:
        w, h = pil_crop.size
        if w < 2 or h < 2:
            return pil_crop
        sw = max(8, w // 18)
        sh = max(8, h // 18)
        small = pil_crop.resize((sw, sh), Image.Resampling.BILINEAR)
        small = small.filter(ImageFilter.GaussianBlur(radius=2.5))
        return small.resize((w, h), Image.Resampling.BILINEAR)

    @staticmethod
    def _merge_boxes(boxes: List[Tuple[int, int, int, int]], gap: int = 24) -> List[Tuple[int, int, int, int]]:
        if not boxes:
            return []
        rects = [list(b) for b in boxes]
        merged = True
        while merged:
            merged = False
            out = []
            while rects:
                curr = rects.pop(0)
                i = 0
                while i < len(rects):
                    other = rects[i]
                    if not (
                        curr[2] + gap < other[0]
                        or other[2] + gap < curr[0]
                        or curr[3] + gap < other[1]
                        or other[3] + gap < curr[1]
                    ):
                        curr = [
                            min(curr[0], other[0]),
                            min(curr[1], other[1]),
                            max(curr[2], other[2]),
                            max(curr[3], other[3]),
                        ]
                        rects.pop(i)
                        merged = True
                    else:
                        i += 1
                out.append(curr)
            rects = out
        return [(r[0], r[1], r[2], r[3]) for r in rects]

    @staticmethod
    def _box_overlap_ratio(a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]) -> float:
        ix1, iy1 = max(a[0], b[0]), max(a[1], b[1])
        ix2, iy2 = min(a[2], b[2]), min(a[3], b[3])
        if ix2 <= ix1 or iy2 <= iy1:
            return 0.0
        inter = (ix2 - ix1) * (iy2 - iy1)
        area_a = max(1, (a[2] - a[0]) * (a[3] - a[1]))
        return inter / area_a

    def _emit_overlay(self, patches: List[Tuple[Tuple[int, int, int, int], Image.Image]], active: bool, reason: str = "") -> None:
        # إبقاء أحدث إطار فقط في الطابور لمنع تراكم الذاكرة
        while not self.overlay_queue.empty():
            try:
                self.overlay_queue.get_nowait()
            except queue.Empty:
                break
        self.overlay_queue.put((patches, active, reason))

    def _maybe_notify(self, title: str, msg: str) -> None:
        now = time.perf_counter()
        if now - self._last_notify_time >= 8.0:
            self._last_notify_time = now
            self.notify_cb(title, msg)

    def run(self) -> None:
        try:
            self.engine.load()
        except Exception as exc:
            self.status_cb(f"فشل تحميل نموذج 640m: {exc}")
            return

        with mss.mss() as sct:
            while self._running:
                loop_start = time.perf_counter()

                # إعادة تأكيد قفل DNS كل 90 ثانية في الخلفية
                if self.config.dns_lock_provider and SystemGuardian.is_admin():
                    if loop_start - self._last_dns_enforce > 90.0:
                        self._last_dns_enforce = loop_start
                        SystemGuardian.apply_safe_dns(self.config.dns_lock_provider)

                if not self.config.enabled:
                    if self._was_active:
                        self._was_active = False
                        self._emit_overlay([], False)
                    time.sleep(0.35)
                    continue

                try:
                    monitor = sct.monitors[0]
                    raw = sct.grab(monitor)
                    pil_rgb = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
                    orig_w, orig_h = pil_rgb.size
                    now = time.perf_counter()

                    # 1. الحماية الاستباقية الفورية لعناوين المتصفح
                    if self.config.title_guard_enabled:
                        fg_title = self._get_foreground_title()
                        if fg_title and any(tok in fg_title for tok in SUSPICIOUS_TITLE_TOKENS):
                            self._last_nsfw_time = now
                            blurred_full = self._create_heavy_blur(pil_rgb)
                            self._emit_overlay([((0, 0, orig_w, orig_h), blurred_full)], True, "عنوان موقع غير لائق")
                            if not self._was_active:
                                self._maybe_notify("تم إيجاد مواد إباحية", "تم حجب صفحة تحتوي على عنوان غير لائق تلقائياً.")
                            self._was_active = True
                            time.sleep(0.35)
                            continue

                    # 2. كشف التغير في الشاشة + فلتر البشرة الذكي
                    thumb = np.asarray(pil_rgb.resize((160, 90), Image.Resampling.BILINEAR), dtype=np.uint8)
                    gray = (0.299 * thumb[:, :, 0] + 0.587 * thumb[:, :, 1] + 0.114 * thumb[:, :, 2]).astype(np.float32)

                    changed = True
                    if self._prev_gray is not None:
                        diff = float(np.mean(np.abs(self._prev_gray - gray)))
                        if diff < self.config.frame_diff_threshold:
                            changed = False
                    if changed:
                        self._prev_gray = gray

                    if not changed:
                        time.sleep(0.35)
                        continue

                    # إذا لم توجد نسبة بشرة كافية -> الشاشة نصية/كود -> تخطي 640m فوراً
                    if not self.engine.has_sufficient_skin(thumb, self.config.min_skin_ratio):
                        if self._was_active and (now - self._last_nsfw_time) > self.config.hold_seconds:
                            self._was_active = False
                            self._emit_overlay([], False)
                        time.sleep(0.35)
                        continue

                    # 3. فحص الذكاء الاصطناعي عالي الدقة 640m.onnx
                    thresholds = self.config.active_thresholds()
                    min_conf = min(thresholds.values())
                    detections = self.engine.detect(pil_rgb, min_conf=min_conf)

                    # استخراج مربعات الوجوه لمنع الإنذارات الكاذبة على الوجه
                    face_boxes = [
                        d["box"] for d in detections
                        if d["class"] in ("FACE_FEMALE", "FACE_MALE") and d["score"] >= 0.65
                    ]

                    raw_boxes: List[Tuple[int, int, int, int]] = []
                    pad = self.config.box_padding
                    for d in detections:
                        cls_name = d["class"]
                        score = d["score"]
                        if cls_name in thresholds and score >= thresholds[cls_name]:
                            bx1, by1, bx2, by2 = d["box"]
                            # استبعاد أي إنذار منخفض الثقة متداخل بشدة مع وجه طبيعي
                            if score < 0.62 and any(self._box_overlap_ratio(d["box"], fb) > 0.65 for fb in face_boxes):
                                continue
                            x1 = max(0, bx1 - pad)
                            y1 = max(0, by1 - pad)
                            x2 = min(orig_w, bx2 + pad)
                            y2 = min(orig_h, by2 + pad)
                            if x2 > x1 and y2 > y1:
                                raw_boxes.append((x1, y1, x2, y2))

                    if raw_boxes:
                        self._last_nsfw_time = now
                        merged = self._merge_boxes(raw_boxes)
                        patches: List[Tuple[Tuple[int, int, int, int], Image.Image]] = []

                        if self.config.full_screen_blur:
                            patches.append(((0, 0, orig_w, orig_h), self._create_heavy_blur(pil_rgb)))
                        else:
                            for x1, y1, x2, y2 in merged:
                                crop = pil_rgb.crop((x1, y1, x2, y2))
                                patches.append(((x1, y1, x2, y2), self._create_heavy_blur(crop)))

                        self._emit_overlay(patches, True, f"تم حجب {len(merged)} منطقة")
                        if not self._was_active:
                            self._maybe_notify(
                                "تم إيجاد مواد إباحية",
                                f"تم اكتشاف وحجب ({len(merged)}) منطقة غير لائقة تلقائياً بنموذج 640m.",
                            )
                        self._was_active = True
                    else:
                        if self._was_active and (now - self._last_nsfw_time) > self.config.hold_seconds:
                            self._was_active = False
                            self._emit_overlay([], False)

                except Exception as exc:
                    self.status_cb(f"تنبيه أثناء الفحص: {exc}")

                # معدل فحص تكيفي (أسرع عند وجود حركة/محتوى، وأخف عند السكون)
                target_interval = 0.28 if self._was_active else 0.42
                elapsed = time.perf_counter() - loop_start
                if elapsed < target_interval:
                    time.sleep(target_interval - elapsed)


# ==============================================================================
# 6. طبقة التمويه الخفيفة الأصلية (Tkinter + Win32 بدون PyQt6)
# ==============================================================================
class NativeOverlayWindow:
    TRANSPARENT_KEY = "#010203"

    def __init__(self, overlay_queue: queue.Queue, ui_action_queue: queue.Queue):
        self.overlay_queue = overlay_queue
        self.ui_action_queue = ui_action_queue
        self._tk_refs: List[ImageTk.PhotoImage] = []
        self._visible = False
        self._win32_configured = False

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.attributes("-transparentcolor", self.TRANSPARENT_KEY)
        self.root.configure(bg=self.TRANSPARENT_KEY)

        # أبعاد سطح المكتب الافتراضي الكامل (يشمل تعدد الشاشات بدقة البكسل الحقيقية)
        user32 = ctypes.windll.user32
        self.vx = user32.GetSystemMetrics(76)
        self.vy = user32.GetSystemMetrics(77)
        self.vw = user32.GetSystemMetrics(78)
        self.vh = user32.GetSystemMetrics(79)
        self.primary_w = user32.GetSystemMetrics(0)
        self.primary_h = user32.GetSystemMetrics(1)

        self.root.geometry(f"{self.vw}x{self.vh}+{self.vx}+{self.vy}")
        self.canvas = tk.Canvas(
            self.root,
            width=self.vw,
            height=self.vh,
            bg=self.TRANSPARENT_KEY,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.root.after(45, self._poll_queues)

    def _apply_win32_flags(self) -> None:
        if self._win32_configured:
            return
        self.root.update_idletasks()
        user32 = ctypes.windll.user32
        wid = self.root.winfo_id()
        hwnd = user32.GetParent(wid) or wid

        ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        user32.SetWindowLongW(
            hwnd,
            GWL_EXSTYLE,
            ex_style | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        )
        # إخفاء نافذة التمويه عن محرك الالتقاط لمنع الوميض 100%
        user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        self._win32_configured = True

    def _poll_queues(self) -> None:
        # 1. معالجة أوامر الواجهة القادمة من أيقونة شريط المهام (Thread-Safe)
        while not self.ui_action_queue.empty():
            try:
                fn = self.ui_action_queue.get_nowait()
                fn()
            except queue.Empty:
                break
            except Exception:
                pass

        # 2. معالجة تحديثات التمويه
        try:
            patches, active, _reason = self.overlay_queue.get_nowait()
            self._render(patches, active)
        except queue.Empty:
            pass

        self.root.after(45, self._poll_queues)

    def _render(self, patches: List[Tuple[Tuple[int, int, int, int], Image.Image]], active: bool) -> None:
        if not active or not patches:
            if self._visible:
                self.canvas.delete("all")
                self._tk_refs.clear()
                self.root.withdraw()
                self._visible = False
            return

        if not self._visible:
            self.root.deiconify()
            self._apply_win32_flags()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self._visible = True

        self.canvas.delete("all")
        self._tk_refs.clear()

        for (x1, y1, x2, y2), pil_img in patches:
            tk_img = ImageTk.PhotoImage(pil_img)
            self._tk_refs.append(tk_img)
            self.canvas.create_image(x1, y1, anchor=tk.NW, image=tk_img)
            self.canvas.create_rectangle(x1, y1, x2, y2, outline="#EF4444", width=3)
            if (x2 - x1) >= 190 and (y2 - y1) >= 64:
                cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                self.canvas.create_rectangle(cx - 115, cy - 20, cx + 115, cy + 20, fill="#1E293B", outline="#EF4444", width=1)
                self.canvas.create_text(
                    cx, cy,
                    text="تم حجب محتوى غير لائق",
                    fill="#FFFFFF",
                    font=("Segoe UI", 12, "bold"),
                )

        # شريط التنبيه الرئيسي أعلى الشاشة الأساسية
        banner_w, banner_h = 540, 62
        offset_x = max(0, -self.vx)
        offset_y = max(0, -self.vy)
        bx1 = offset_x + (self.primary_w - banner_w) // 2
        by1 = offset_y + 26
        bx2, by2 = bx1 + banner_w, by1 + banner_h

        self.canvas.create_rectangle(bx1, by1, bx2, by2, fill="#B91C1C", outline="#FECACA", width=2)
        self.canvas.create_text(
            (bx1 + bx2) // 2,
            (by1 + by2) // 2,
            text="⚠ تم إيجاد مواد إباحية — تم التمويه تلقائياً",
            fill="#FFFFFF",
            font=("Segoe UI", 15, "bold"),
        )

    def run_mainloop(self) -> None:
        self.root.mainloop()

    def quit(self) -> None:
        self.root.quit()


# ==============================================================================
# 7. التطبيق الرئيسي وأيقونة شريط المهام وإدارة الحارس
# ==============================================================================
class SafeGuardApp:
    def __init__(self):
        self.config = ShieldConfig()
        self.config.load_from_registry()

        self.overlay_queue: queue.Queue = queue.Queue(maxsize=2)
        self.ui_action_queue: queue.Queue = queue.Queue()
        self.exit_event = WatchdogSystem.create_exit_event()
        self._watchdog_proc: Optional[subprocess.Popen] = None
        self._status_text = "جاري التهيئة..."

        self.overlay = NativeOverlayWindow(self.overlay_queue, self.ui_action_queue)
        self.worker = ScreenMonitorWorker(
            self.config,
            self.overlay_queue,
            self._set_status,
            self._tray_notify,
        )

        self.tray = pystray.Icon(
            APP_NAME,
            self._draw_tray_icon(True),
            "درع العفة 640m — الحماية الشاملة",
            menu=self._build_menu(),
        )

    @staticmethod
    def _draw_tray_icon(active: bool) -> Image.Image:
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        color = (16, 185, 129, 255) if active else (100, 116, 139, 255)
        draw.rounded_rectangle((6, 6, 58, 58), radius=14, fill=color, outline=(255, 255, 255, 255), width=3)
        if active:
            draw.line([(20, 34), (29, 43), (45, 23)], fill=(255, 255, 255, 255), width=5)
        else:
            draw.rectangle((22, 20, 29, 44), fill=(255, 255, 255, 255))
            draw.rectangle((35, 20, 42, 44), fill=(255, 255, 255, 255))
        return img

    def _set_status(self, text: str) -> None:
        self._status_text = text
        try:
            self.tray.title = f"درع العفة — {text[:55]}"
            self.tray.update_menu()
        except Exception:
            pass

    def _tray_notify(self, title: str, message: str) -> None:
        try:
            self.tray.notify(message, title)
        except Exception:
            pass

    def _dispatch_ui(self, fn: Callable[[], None]) -> None:
        self.ui_action_queue.put(fn)

    def _verify_pin_on_ui_thread(self) -> bool:
        if not self.config.pin_hash:
            return True
        entered = simpledialog.askstring(
            "التحقق من الهوية",
            "أدخل رمز القفل (PIN) للمتابعة:",
            show="*",
            parent=self.overlay.root,
        )
        if entered is None:
            return False
        if hashlib.sha256(entered.encode("utf-8")).hexdigest() != self.config.pin_hash:
            messagebox.showwarning("رمز خاطئ", "رمز القفل غير صحيح. تبقى الحماية مفعّلة.", parent=self.overlay.root)
            return False
        return True

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(lambda _: self._status_text, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _: "إيقاف الحماية مؤقتاً" if self.config.enabled else "تفعيل الحماية",
                lambda _icon, _item: self._dispatch_ui(self._toggle_protection),
            ),
            pystray.MenuItem(
                "نمط التمويه",
                pystray.Menu(
                    pystray.MenuItem(
                        "تمويه المنطقة المخالفة فقط (ذكي)",
                        lambda _i, _it: self._set_blur_mode(False),
                        checked=lambda _: not self.config.full_screen_blur,
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "تمويه الشاشة بالكامل",
                        lambda _i, _it: self._set_blur_mode(True),
                        checked=lambda _: self.config.full_screen_blur,
                        radio=True,
                    ),
                ),
            ),
            pystray.MenuItem(
                "الوضع الصارم (حساسية أعلى)",
                lambda _i, _it: self._dispatch_ui(self._toggle_strict),
                checked=lambda _: self.config.strict_mode,
            ),
            pystray.MenuItem(
                "الحماية الاستباقية لعناوين المتصفح",
                lambda _i, _it: self._dispatch_ui(self._toggle_title_guard),
                checked=lambda _: self.config.title_guard_enabled,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "الحماية الشبكية (حجب المواقع)",
                pystray.Menu(
                    pystray.MenuItem(
                        "تفعيل DNS عائلي — Cloudflare (1.1.1.3)",
                        lambda _i, _it: self._apply_dns_async("cloudflare"),
                        checked=lambda _: self.config.dns_lock_provider == "cloudflare",
                    ),
                    pystray.MenuItem(
                        "تفعيل DNS عائلي — CleanBrowsing",
                        lambda _i, _it: self._apply_dns_async("cleanbrowsing"),
                        checked=lambda _: self.config.dns_lock_provider == "cleanbrowsing",
                    ),
                    pystray.MenuItem(
                        "تحديث وحجب قائمة المواقع الإباحية (Hosts)",
                        lambda _i, _it: self._sync_hosts_async(),
                    ),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(
                        "إزالة حجب DNS و Hosts",
                        lambda _i, _it: self._dispatch_ui(self._remove_network_blocks),
                    ),
                ),
            ),
            pystray.MenuItem(
                "تثبيت التشغيل التلقائي مع ويندوز",
                lambda _i, _it: self._install_autostart_async(),
            ),
            pystray.MenuItem(
                "تشغيل كمسؤول (لتفعيل DNS و Hosts)",
                lambda _i, _it: self._dispatch_ui(self._elevate_now),
                visible=lambda _: not SystemGuardian.is_admin(),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "تعيين / تغيير رمز القفل PIN",
                lambda _i, _it: self._dispatch_ui(self._configure_pin),
            ),
            pystray.MenuItem(
                "إغلاق التطبيق نهائياً",
                lambda _i, _it: self._dispatch_ui(self._authorized_exit),
            ),
        )

    def _toggle_protection(self) -> None:
        if self.config.enabled and not self._verify_pin_on_ui_thread():
            return
        self.config.enabled = not self.config.enabled
        self.tray.icon = self._draw_tray_icon(self.config.enabled)
        self.worker.force_rescan()
        self.tray.update_menu()

    def _set_blur_mode(self, full: bool) -> None:
        self.config.full_screen_blur = full
        self.config.save_to_registry()
        self.worker.force_rescan()
        self.tray.update_menu()

    def _toggle_strict(self) -> None:
        if self.config.strict_mode and not self._verify_pin_on_ui_thread():
            return
        self.config.strict_mode = not self.config.strict_mode
        self.config.save_to_registry()
        self.worker.force_rescan()
        self.tray.update_menu()

    def _toggle_title_guard(self) -> None:
        if self.config.title_guard_enabled and not self._verify_pin_on_ui_thread():
            return
        self.config.title_guard_enabled = not self.config.title_guard_enabled
        self.config.save_to_registry()
        self.tray.update_menu()

    def _configure_pin(self) -> None:
        if not self._verify_pin_on_ui_thread():
            return
        new_pin = simpledialog.askstring(
            "تعيين رمز القفل",
            "أدخل رمز PIN جديد (اتركه فارغاً لإلغاء القفل):",
            show="*",
            parent=self.overlay.root,
        )
        if new_pin is None:
            return
        self.config.pin_hash = hashlib.sha256(new_pin.strip().encode("utf-8")).hexdigest() if new_pin.strip() else None
        self.config.save_to_registry()
        self._tray_notify("درع العفة", "تم تحديث رمز القفل وحفظه بأمان.")

    def _apply_dns_async(self, provider: str) -> None:
        def job():
            ok, msg = SystemGuardian.apply_safe_dns(provider)
            if ok:
                self.config.dns_lock_provider = provider
                self.config.save_to_registry()
                self.tray.update_menu()
            self._tray_notify("الحماية الشبكية (DNS)", msg)
        threading.Thread(target=job, daemon=True).start()

    def _sync_hosts_async(self) -> None:
        def job():
            self._tray_notify("جاري التحديث", "جاري تحميل قائمة المواقع الإباحية وتحديث ملف hosts...")
            ok, msg = SystemGuardian.sync_hosts_blocklist()
            self._tray_notify("قائمة حجب المواقع (Hosts)", msg)
        threading.Thread(target=job, daemon=True).start()

    def _remove_network_blocks(self) -> None:
        if not self._verify_pin_on_ui_thread():
            return
        def job():
            self.config.dns_lock_provider = ""
            self.config.save_to_registry()
            _, m1 = SystemGuardian.restore_dhcp_dns()
            _, m2 = SystemGuardian.clear_hosts_blocklist()
            self.tray.update_menu()
            self._tray_notify("إعدادات الشبكة", f"{m1}\n{m2}")
        threading.Thread(target=job, daemon=True).start()

    def _install_autostart_async(self) -> None:
        def job():
            _, msg = SystemGuardian.install_system_autostart()
            self._tray_notify("التشغيل التلقائي", msg)
        threading.Thread(target=job, daemon=True).start()

    def _elevate_now(self) -> None:
        WatchdogSystem.signal_authorized_exit(self.exit_event)
        if SystemGuardian.relaunch_as_admin():
            self.worker.stop()
            self.tray.stop()
            self.overlay.quit()
        else:
            ctypes.windll.kernel32.ResetEvent(self.exit_event)

    def _authorized_exit(self) -> None:
        if not self._verify_pin_on_ui_thread():
            return
        WatchdogSystem.signal_authorized_exit(self.exit_event)
        self.worker.stop()
        self.tray.stop()
        self.overlay.quit()

    def _watchdog_keeper_loop(self) -> None:
        """يضمن بقاء عملية الحارس الثانية حية؛ وإن أُنهيت يعيد تشغيلها فوراً."""
        my_pid = str(os.getpid())
        while not WatchdogSystem.is_authorized_exit_set():
            if self._watchdog_proc is None or self._watchdog_proc.poll() is not None:
                try:
                    self._watchdog_proc = subprocess.Popen(
                        WatchdogSystem.spawn_command(["--watchdog", my_pid]),
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                except Exception:
                    pass
            time.sleep(1.2)

    def run(self) -> None:
        self.worker.start()
        threading.Thread(target=self._watchdog_keeper_loop, daemon=True).start()
        self.tray.run_detached()
        self.overlay.run_mainloop()


def main() -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

    # وضع الحارس الثاني (Watchdog)
    if len(sys.argv) >= 3 and sys.argv[1] == "--watchdog":
        WatchdogSystem.run_watchdog_loop(int(sys.argv[2]))
        return

    # منع تشغيل نسختين من التطبيق الرئيسي معاً
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, MAIN_MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return

    app = SafeGuardApp()
    app.run()


if __name__ == "__main__":
    main()
