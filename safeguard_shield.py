import ctypes
import ctypes.wintypes as wintypes
import datetime
import hashlib
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import winreg
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import mss
import numpy as np
import onnxruntime as ort
import tkinter as tk
from tkinter import messagebox, simpledialog

# ==============================================================================
# ثوابت نظام ويندوز وهياكل Win32 الأصلية (بدون أي مكتبات خارجية)
# ==============================================================================
APP_NAME = "SafeGuardShield"
HKLM_REG_PATH = r"SOFTWARE\SafeGuardShield"
HKCU_REG_PATH = r"Software\SafeGuardShield"
EXIT_EVENT_NAME = "Local\\SafeGuardShield_AuthorizedExit_v3"
MAIN_MUTEX_NAME = "Local\\SafeGuardShield_SingleInstance_v3"
HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_START_MARKER = "# >>> SAFEGUARD_SHIELD_BLOCKLIST_START"
HOSTS_END_MARKER = "# <<< SAFEGUARD_SHIELD_BLOCKLIST_END"

# ثوابت النوافذ وإخفاء الالتقاط
WDA_EXCLUDEFROMCAPTURE = 0x00000011
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000
SW_MINIMIZE = 6

# ثوابت العمليات والملفات
SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_OBJECT_0 = 0x00000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ثوابت أيقونة شريط المهام واختصار الطوارئ
WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_HOTKEY = 0x0312
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 20
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010
NIIF_INFO = 0x00000001
NIIF_WARNING = 0x00000002
MF_STRING = 0x00000000
MF_GRAYED = 0x00000001
MF_SEPARATOR = 0x00000800
TPM_LEFTALIGN = 0x0000
TPM_BOTTOMALIGN = 0x0020
TPM_RIGHTBUTTON = 0x0002
TPM_RETURNCMD = 0x0100
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_NOREPEAT = 0x4000
HOTKEY_ID_PANIC = 9001

# ثوابت لوحة المفاتيح (SendInput)
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
VK_CONTROL = 0x11
VK_W = 0x57
VK_VOLUME_MUTE = 0xAD

# أسماء فئات نموذج 640m.onnx بالترتيب الرسمي
MODEL_LABELS = (
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
)

# برامج العمل والدراسة المستثناة تلقائياً لتوفير المعالج والبطارية
EXCLUDED_WORK_APPS = frozenset({
    "code.exe",
    "pycharm64.exe",
    "devenv.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
})

# المتصفحات المدعومة للإغلاق التلقائي للتبويب المخالف
BROWSER_PROCESSES = frozenset({
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "opera_gx.exe",
    "vivaldi.exe",
    "waterfox.exe",
})

# نوافذ الإعدادات الحساسة المراقبة عند تفعيل الرقم السري
TAMPER_PROCESSES = frozenset({"regedit.exe"})
TAMPER_TITLES = (
    "registry editor",
    "محرر السجل",
    "network connections",
    "اتصالات الشبكة",
    "ncpa.cpl",
)

# الكلمات الافتراضية المحظورة في عناوين المتصفح
DEFAULT_BLOCKED_KEYWORDS = (
    "pornhub", "xvideos", "xnxx", "xhamster", "redtube", "youporn",
    "brazzers", "onlyfans", "chaturbate", "stripchat", "spankbang",
    "eporner", "hentai", "rule34", "nsfw", "سكس", "افلام اباحية", "أفلام إباحية",
)

BLOCKLIST_URLS = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
)

SAFE_DNS_V4 = ("1.1.1.3", "1.0.0.3")
SAFE_DNS_V6 = ("2606:4700:4700::1113", "2606:4700:4700::1003")


# ==============================================================================
# هياكل ctypes متوافقة 100% مع 64-bit و 32-bit
# ==============================================================================
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, text: str) -> "GUID":
        cleaned = text.strip("{}")
        parts = cleaned.split("-")
        d1 = int(parts[0], 16)
        d2 = int(parts[1], 16)
        d3 = int(parts[2], 16)
        tail = bytes.fromhex(parts[3] + parts[4])
        return cls(d1, d2, d3, (ctypes.c_ubyte * 8)(*tail))


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT),
    ]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("type", wintypes.DWORD),
        ("u", _INPUT_UNION),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", ctypes.c_size_t),
        ("lParam", ctypes.c_ssize_t),
        ("time", wintypes.DWORD),
        ("pt", POINT),
    ]


user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32
gdi32 = ctypes.windll.gdi32

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t]
user32.DefWindowProcW.restype = ctypes.c_ssize_t
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.CreateFileW.restype = ctypes.c_void_p


# ==============================================================================
# 1. إعدادات التطبيق والتخزين الآمن في سجل ويندوز (HKLM مع احتياطي HKCU)
# ==============================================================================
@dataclass
class ShieldConfig:
    enabled: bool = True
    web_block_enabled: bool = False
    auto_close_enabled: bool = True
    night_mode_enabled: bool = True
    cooldown_lock_enabled: bool = False
    full_screen_blur: bool = False
    strict_mode: bool = False
    pin_hash: Optional[str] = None
    clean_start_ts: float = field(default_factory=time.time)
    blocked_count: int = 0
    custom_keywords: List[str] = field(default_factory=list)
    pending_action: str = ""
    pending_execute_at: float = 0.0
    box_padding: int = 44
    hold_seconds: float = 1.4
    frame_diff_threshold: float = 1.5
    min_skin_ratio: float = 0.012

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

    def is_night_active(self) -> bool:
        if not self.night_mode_enabled:
            return False
        hour = datetime.datetime.now().hour
        return hour >= 23 or hour < 6

    def effective_strict(self) -> bool:
        return self.strict_mode or self.is_night_active()

    def effective_full_blur(self) -> bool:
        return self.full_screen_blur or self.is_night_active()

    def active_thresholds(self) -> Dict[str, float]:
        merged = dict(self.base_thresholds)
        if self.effective_strict():
            merged.update(self.strict_thresholds)
        return merged

    def all_blocked_keywords(self) -> Tuple[str, ...]:
        combined = list(DEFAULT_BLOCKED_KEYWORDS)
        for kw in self.custom_keywords:
            clean = kw.strip().lower()
            if clean and clean not in combined:
                combined.append(clean)
        return tuple(combined)

    def clean_duration_parts(self) -> Tuple[int, int]:
        elapsed = max(0.0, time.time() - self.clean_start_ts)
        days = int(elapsed // 86400)
        hours = int((elapsed % 86400) // 3600)
        return days, hours

    def load(self) -> None:
        loaded = False
        for hive, path in ((winreg.HKEY_LOCAL_MACHINE, HKLM_REG_PATH), (winreg.HKEY_CURRENT_USER, HKCU_REG_PATH)):
            try:
                with winreg.OpenKey(hive, path) as key:
                    self._read_key(key)
                    loaded = True
                    break
            except OSError:
                continue
        if not loaded:
            self.clean_start_ts = time.time()
            self.save()

    def _read_key(self, key) -> None:
        bool_fields = (
            "web_block_enabled",
            "auto_close_enabled",
            "night_mode_enabled",
            "cooldown_lock_enabled",
            "full_screen_blur",
            "strict_mode",
        )
        for name in bool_fields:
            try:
                val, _ = winreg.QueryValueEx(key, name)
                setattr(self, name, bool(val))
            except FileNotFoundError:
                pass
        try:
            val, _ = winreg.QueryValueEx(key, "pin_hash")
            self.pin_hash = str(val) if val else None
        except FileNotFoundError:
            pass
        try:
            val, _ = winreg.QueryValueEx(key, "clean_start_ts")
            ts = float(val)
            if ts > 0:
                self.clean_start_ts = ts
        except (FileNotFoundError, ValueError):
            pass
        try:
            val, _ = winreg.QueryValueEx(key, "blocked_count")
            self.blocked_count = max(0, int(val))
        except (FileNotFoundError, ValueError):
            pass
        try:
            val, _ = winreg.QueryValueEx(key, "custom_keywords")
            parsed = json.loads(val)
            if isinstance(parsed, list):
                self.custom_keywords = [str(x) for x in parsed if str(x).strip()]
        except (FileNotFoundError, ValueError):
            pass
        try:
            val, _ = winreg.QueryValueEx(key, "pending_action")
            self.pending_action = str(val) if val else ""
        except FileNotFoundError:
            pass
        try:
            val, _ = winreg.QueryValueEx(key, "pending_execute_at")
            self.pending_execute_at = float(val)
        except (FileNotFoundError, ValueError):
            pass

    def save(self) -> None:
        targets = (
            [(winreg.HKEY_LOCAL_MACHINE, HKLM_REG_PATH), (winreg.HKEY_CURRENT_USER, HKCU_REG_PATH)]
            if SystemGuardian.is_admin()
            else [(winreg.HKEY_CURRENT_USER, HKCU_REG_PATH)]
        )
        for hive, path in targets:
            try:
                with winreg.CreateKey(hive, path) as key:
                    winreg.SetValueEx(key, "web_block_enabled", 0, winreg.REG_DWORD, int(self.web_block_enabled))
                    winreg.SetValueEx(key, "auto_close_enabled", 0, winreg.REG_DWORD, int(self.auto_close_enabled))
                    winreg.SetValueEx(key, "night_mode_enabled", 0, winreg.REG_DWORD, int(self.night_mode_enabled))
                    winreg.SetValueEx(key, "cooldown_lock_enabled", 0, winreg.REG_DWORD, int(self.cooldown_lock_enabled))
                    winreg.SetValueEx(key, "full_screen_blur", 0, winreg.REG_DWORD, int(self.full_screen_blur))
                    winreg.SetValueEx(key, "strict_mode", 0, winreg.REG_DWORD, int(self.strict_mode))
                    winreg.SetValueEx(key, "pin_hash", 0, winreg.REG_SZ, self.pin_hash or "")
                    winreg.SetValueEx(key, "clean_start_ts", 0, winreg.REG_SZ, str(self.clean_start_ts))
                    winreg.SetValueEx(key, "blocked_count", 0, winreg.REG_DWORD, int(self.blocked_count))
                    winreg.SetValueEx(key, "custom_keywords", 0, winreg.REG_SZ, json.dumps(self.custom_keywords, ensure_ascii=False))
                    winreg.SetValueEx(key, "pending_action", 0, winreg.REG_SZ, self.pending_action or "")
                    winreg.SetValueEx(key, "pending_execute_at", 0, winreg.REG_SZ, str(self.pending_execute_at))
            except OSError:
                pass


# ==============================================================================
# 2. قفل ملف hosts في الخلفية لمنع التعديل أو الحذف اليدوي
# ==============================================================================
class HostsLockManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._handle: Optional[int] = None

    def acquire_lock(self) -> None:
        with self._lock:
            if self._handle is not None:
                return
            if not HOSTS_PATH.exists():
                return
            h = kernel32.CreateFileW(
                str(HOSTS_PATH),
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if h and h != INVALID_HANDLE_VALUE:
                self._handle = h

    def release_lock(self) -> None:
        with self._lock:
            if self._handle is not None:
                kernel32.CloseHandle(self._handle)
                self._handle = None

    @contextmanager
    def unlocked_for_update(self, relock: bool = True):
        self.release_lock()
        try:
            yield
        finally:
            if relock:
                self.acquire_lock()


# ==============================================================================
# 3. أدوات التحكم بصوت النظام + اختصارات لوحة المفاتيح + معلومات النوافذ
# ==============================================================================
class WindowsHelper:
    @staticmethod
    def send_ctrl_w() -> None:
        """إرسال اختصار Ctrl + W لإغلاق التبويب المخالف فوراً عبر SendInput."""
        def make_key(vk: int, flags: int = 0) -> INPUT:
            inp = INPUT()
            inp.type = INPUT_KEYBOARD
            inp.ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=0)
            return inp

        seq = (INPUT * 4)(
            make_key(VK_CONTROL, 0),
            make_key(VK_W, 0),
            make_key(VK_W, KEYEVENTF_KEYUP),
            make_key(VK_CONTROL, KEYEVENTF_KEYUP),
        )
        user32.SendInput(4, seq, ctypes.sizeof(INPUT))

    @staticmethod
    def mute_system_audio() -> None:
        """كتم صوت النظام بشكل حتمي عبر Core Audio COM مع بديل احتياطي آمن."""
        try:
            ole32 = ctypes.windll.ole32
            ole32.CoInitialize(None)
            try:
                clsid_enum = GUID.from_str("{BCDE0395-E52F-467C-8E3D-C4579291692E}")
                iid_enum = GUID.from_str("{A95664D2-9614-4F35-A746-DE8DB63617E6}")
                iid_vol = GUID.from_str("{5CDF2C82-841E-4546-9722-0CF74078229A}")

                p_enum = ctypes.c_void_p()
                hr = ole32.CoCreateInstance(
                    ctypes.byref(clsid_enum), None, 1,
                    ctypes.byref(iid_enum), ctypes.byref(p_enum)
                )
                if hr == 0 and p_enum.value:
                    try:
                        vt_enum = ctypes.cast(
                            ctypes.cast(p_enum, ctypes.POINTER(ctypes.c_void_p)).contents.value,
                            ctypes.POINTER(ctypes.c_void_p),
                        )
                        get_default = ctypes.WINFUNCTYPE(
                            ctypes.c_long, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                            ctypes.POINTER(ctypes.c_void_p)
                        )(vt_enum[4])
                        p_dev = ctypes.c_void_p()
                        if get_default(p_enum, 0, 1, ctypes.byref(p_dev)) == 0 and p_dev.value:
                            try:
                                vt_dev = ctypes.cast(
                                    ctypes.cast(p_dev, ctypes.POINTER(ctypes.c_void_p)).contents.value,
                                    ctypes.POINTER(ctypes.c_void_p),
                                )
                                activate = ctypes.WINFUNCTYPE(
                                    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID),
                                    wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
                                )(vt_dev[3])
                                p_vol = ctypes.c_void_p()
                                if activate(p_dev, ctypes.byref(iid_vol), 23, None, ctypes.byref(p_vol)) == 0 and p_vol.value:
                                    try:
                                        vt_vol = ctypes.cast(
                                            ctypes.cast(p_vol, ctypes.POINTER(ctypes.c_void_p)).contents.value,
                                            ctypes.POINTER(ctypes.c_void_p),
                                        )
                                        set_mute = ctypes.WINFUNCTYPE(
                                            ctypes.c_long, ctypes.c_void_p, wintypes.BOOL, ctypes.c_void_p
                                        )(vt_vol[14])
                                        set_mute(p_vol, True, None)
                                        return
                                    finally:
                                        release_v = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vt_vol[2])
                                        release_v(p_vol)
                            finally:
                                release_d = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vt_dev[2])
                                release_d(p_dev)
                    finally:
                        release_e = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vt_enum[2])
                        release_e(p_enum)
            finally:
                ole32.CoUninitialize()
        except Exception:
            pass

        # بديل احتياطي عبر زر كتم الصوت
        seq = (INPUT * 2)(
            INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(wVk=VK_VOLUME_MUTE, dwFlags=0)),
            INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(wVk=VK_VOLUME_MUTE, dwFlags=KEYEVENTF_KEYUP)),
        )
        user32.SendInput(2, seq, ctypes.sizeof(INPUT))

    @staticmethod
    def get_foreground_info() -> Tuple[int, str, str, Tuple[int, int, int, int]]:
        """إرجاع (hwnd, title_lower, exe_name_lower, (left, top, right, bottom))."""
        try:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return 0, "", "", (0, 0, 0, 0)

            # العنوان
            tlen = user32.GetWindowTextLengthW(hwnd)
            title = ""
            if tlen > 0:
                buf = ctypes.create_unicode_buffer(tlen + 1)
                user32.GetWindowTextW(hwnd, buf, tlen + 1)
                title = buf.value.lower()

            # اسم البرنامج عبر QueryFullProcessImageNameW
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            exe_name = ""
            if pid.value:
                h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
                if h_proc:
                    try:
                        size = wintypes.DWORD(512)
                        pbuf = ctypes.create_unicode_buffer(512)
                        if kernel32.QueryFullProcessImageNameW(h_proc, 0, pbuf, ctypes.byref(size)):
                            exe_name = os.path.basename(pbuf.value).lower()
                    finally:
                        kernel32.CloseHandle(h_proc)

            # إحداثيات النافذة النشطة
            rect = RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                coords = (rect.left, rect.top, rect.right, rect.bottom)
            else:
                coords = (0, 0, 0, 0)

            return int(hwnd), title, exe_name, coords
        except Exception:
            return 0, "", "", (0, 0, 0, 0)

    @staticmethod
    def minimize_window(hwnd: int) -> None:
        if hwnd:
            user32.ShowWindow(hwnd, SW_MINIMIZE)


# ==============================================================================
# 4. حماية الشبكة والمتصفحات والبحث الآمن والتشغيل التلقائي
# ==============================================================================
class SystemGuardian:
    @staticmethod
    def is_admin() -> bool:
        try:
            return bool(shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def _run_hidden(cmd: List[str], timeout: int = 25) -> Tuple[int, str]:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=si,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.returncode, (proc.stdout + "\n" + proc.stderr).strip()

    @classmethod
    def _get_active_interfaces(cls) -> List[str]:
        ps = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"
        code, out = cls._run_hidden(["powershell", "-NoProfile", "-Command", ps])
        if code == 0 and out.strip():
            return [line.strip() for line in out.splitlines() if line.strip()]
        return ["Wi-Fi", "Ethernet"]

    @staticmethod
    def _apply_browser_policies(enable: bool) -> None:
        """تفعيل البحث الآمن الإجباري في جوجل ويوتيوب وتعطيل التصفح الخفي وحساب الضيف."""
        browser_keys = (
            r"SOFTWARE\Policies\Google\Chrome",
            r"SOFTWARE\Policies\Microsoft\Edge",
            r"SOFTWARE\Policies\BraveSoftware\Brave",
        )
        for path in browser_keys:
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    if enable:
                        winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
                        winreg.SetValueEx(key, "ForceGoogleSafeSearch", 0, winreg.REG_DWORD, 1)
                        winreg.SetValueEx(key, "ForceYouTubeRestrict", 0, winreg.REG_DWORD, 2)
                        winreg.SetValueEx(key, "IncognitoModeAvailability", 0, winreg.REG_DWORD, 1)
                        winreg.SetValueEx(key, "BrowserGuestModeEnabled", 0, winreg.REG_DWORD, 0)
                        if "Edge" in path:
                            winreg.SetValueEx(key, "InPrivateModeAvailability", 0, winreg.REG_DWORD, 1)
                            winreg.SetValueEx(key, "ForceBingSafeSearch", 0, winreg.REG_DWORD, 2)
                    else:
                        for name in (
                            "DnsOverHttpsMode",
                            "ForceGoogleSafeSearch",
                            "ForceYouTubeRestrict",
                            "IncognitoModeAvailability",
                            "BrowserGuestModeEnabled",
                            "InPrivateModeAvailability",
                            "ForceBingSafeSearch",
                        ):
                            try:
                                winreg.DeleteValue(key, name)
                            except FileNotFoundError:
                                pass
            except OSError:
                pass

    @staticmethod
    def _resolve_ip_safe(host: str, fallback: str) -> str:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(4.0)
        try:
            ip = socket.gethostbyname(host)
            return ip if ip else fallback
        except Exception:
            return fallback
        finally:
            socket.setdefaulttimeout(old_timeout)

    @classmethod
    def _build_safesearch_hosts_lines(cls) -> List[str]:
        """تحويلات البحث الآمن لجميع المتصفحات بما فيها Firefox."""
        google_ip = cls._resolve_ip_safe("forcesafesearch.google.com", "216.239.38.120")
        bing_ip = cls._resolve_ip_safe("strict.bing.com", "204.79.197.220")
        yt_ip = cls._resolve_ip_safe("restrict.youtube.com", "216.239.38.119")

        lines = [
            f"{google_ip} www.google.com",
            f"{google_ip} google.com",
            f"{google_ip} www.google.com.sa",
            f"{google_ip} www.google.ae",
            f"{google_ip} www.google.com.eg",
            f"{google_ip} www.google.jo",
            f"{google_ip} www.google.com.sy",
            f"{google_ip} www.google.co.uk",
            f"{bing_ip} www.bing.com",
            f"{bing_ip} bing.com",
            f"{yt_ip} www.youtube.com",
            f"{yt_ip} m.youtube.com",
            f"{yt_ip} youtubei.googleapis.com",
            f"{yt_ip} youtube.googleapis.com",
            f"{yt_ip} www.youtube-nocookie.com",
        ]
        return lines

    @staticmethod
    def _strip_managed_hosts(content: str) -> str:
        out = []
        inside = False
        for line in content.splitlines():
            s = line.strip()
            if s == HOSTS_START_MARKER:
                inside = True
                continue
            if s == HOSTS_END_MARKER:
                inside = False
                continue
            if not inside:
                out.append(line)
        return "\n".join(out)

    @classmethod
    def enable_web_protection(cls, hosts_lock: HostsLockManager) -> Tuple[bool, str]:
        if not cls.is_admin():
            return False, "يرجى تشغيل البرنامج كمسؤول لتفعيل حجب المواقع الضارة."

        # 1. ضبط الحماية الشبكية الآمنة على جميع كروت الشبكة
        for iface in cls._get_active_interfaces():
            cls._run_hidden([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={iface}", "source=static", f"address={SAFE_DNS_V4[0]}", "validate=no",
            ])
            cls._run_hidden([
                "netsh", "interface", "ipv4", "add", "dnsservers",
                f"name={iface}", f"address={SAFE_DNS_V4[1]}", "index=2", "validate=no",
            ])
            cls._run_hidden([
                "netsh", "interface", "ipv6", "set", "dnsservers",
                f"name={iface}", "source=static", f"address={SAFE_DNS_V6[0]}", "validate=no",
            ])
            cls._run_hidden([
                "netsh", "interface", "ipv6", "add", "dnsservers",
                f"name={iface}", f"address={SAFE_DNS_V6[1]}", "index=2", "validate=no",
            ])

        # 2. فرض البحث الآمن وتعطيل التصفح الخفي في المتصفحات
        cls._apply_browser_policies(True)

        # 3. تحديث قائمة الحجب الشاملة + تحويلات البحث الآمن داخل ملف النظام وقفل الملف
        domains = set()
        for url in BLOCKLIST_URLS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SafeGuardShield/3.0"})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    text = resp.read().decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                        dom = parts[1].lower().strip()
                        if dom and dom not in ("0.0.0.0", "localhost", "localhost.localdomain", "broadcasthost"):
                            domains.add(dom)
                if domains:
                    break
            except Exception:
                continue

        safe_lines = cls._build_safesearch_hosts_lines()
        try:
            with hosts_lock.unlocked_for_update(relock=True):
                existing = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
                cleaned = cls._strip_managed_hosts(existing)
                block_section = (
                    [HOSTS_START_MARKER]
                    + safe_lines
                    + [f"0.0.0.0 {d}" for d in sorted(domains)]
                    + [HOSTS_END_MARKER]
                )
                HOSTS_PATH.write_text(cleaned.rstrip() + "\n\n" + "\n".join(block_section) + "\n", encoding="utf-8")
            cls._run_hidden(["ipconfig", "/flushdns"])
            if domains:
                return True, f"تم تفعيل حجب المواقع الضارة والبحث الآمن ({len(domains):,} موقع محجوب)."
            return True, "تم تفعيل الحماية الشبكية والبحث الآمن بنجاح."
        except Exception as exc:
            return False, f"تعذر تحديث قائمة الحجب: {exc}"

    @classmethod
    def disable_web_protection(cls, hosts_lock: HostsLockManager) -> Tuple[bool, str]:
        if not cls.is_admin():
            return False, "يرجى تشغيل البرنامج كمسؤول."

        for iface in cls._get_active_interfaces():
            cls._run_hidden(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={iface}", "source=dhcp"])
            cls._run_hidden(["netsh", "interface", "ipv6", "set", "dnsservers", f"name={iface}", "source=dhcp"])

        cls._apply_browser_policies(False)
        try:
            with hosts_lock.unlocked_for_update(relock=False):
                if HOSTS_PATH.exists():
                    existing = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
                    cleaned = cls._strip_managed_hosts(existing)
                    HOSTS_PATH.write_text(cleaned.rstrip() + "\n", encoding="utf-8")
            cls._run_hidden(["ipconfig", "/flushdns"])
            return True, "تم إيقاف حجب المواقع وإعادة الاتصال للوضع العادي."
        except Exception as exc:
            return False, f"تعذر إزالة الحجب: {exc}"

    @classmethod
    def refresh_dns_only(cls) -> None:
        if not cls.is_admin():
            return
        for iface in cls._get_active_interfaces():
            cls._run_hidden([
                "netsh", "interface", "ipv4", "set", "dnsservers",
                f"name={iface}", "source=static", f"address={SAFE_DNS_V4[0]}", "validate=no",
            ])
            cls._run_hidden([
                "netsh", "interface", "ipv4", "add", "dnsservers",
                f"name={iface}", f"address={SAFE_DNS_V4[1]}", "index=2", "validate=no",
            ])

    @classmethod
    def install_autostart(cls) -> Tuple[bool, str]:
        target = f'"{sys.executable}"' if getattr(sys, "frozen", False) else f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        if cls.is_admin():
            code, _ = cls._run_hidden([
                "schtasks", "/Create",
                "/TN", f"{APP_NAME}_AutoProtect",
                "/TR", target,
                "/SC", "ONLOGON",
                "/RL", "HIGHEST",
                "/F",
            ])
            if code == 0:
                return True, "تم تفعيل التشغيل التلقائي مع بداية الويندوز."
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, target)
            return True, "تم تفعيل التشغيل التلقائي مع بداية الويندوز."
        except Exception as exc:
            return False, f"تعذر التفعيل التلقائي: {exc}"


# ==============================================================================
# 5. نظام الحارس المزدوج لإعادة التشغيل الفوري عند الإغلاق القسري
# ==============================================================================
class WatchdogSystem:
    @staticmethod
    def create_exit_event():
        return kernel32.CreateEventW(None, True, False, EXIT_EVENT_NAME)

    @staticmethod
    def signal_authorized_exit(event_handle) -> None:
        if event_handle:
            kernel32.SetEvent(event_handle)

    @staticmethod
    def is_authorized_exit_set() -> bool:
        evt = kernel32.OpenEventW(SYNCHRONIZE, False, EXIT_EVENT_NAME)
        if not evt:
            return False
        try:
            return kernel32.WaitForSingleObject(evt, 0) == WAIT_OBJECT_0
        finally:
            kernel32.CloseHandle(evt)

    @staticmethod
    def spawn_command(extra_args: List[str]) -> List[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable] + extra_args
        return [sys.executable, os.path.abspath(__file__)] + extra_args

    @classmethod
    def run_watchdog_loop(cls, target_pid: int) -> None:
        current_pid = target_pid
        while True:
            if cls.is_authorized_exit_set():
                return
            h_proc = kernel32.OpenProcess(SYNCHRONIZE, False, current_pid)
            if not h_proc:
                if cls.is_authorized_exit_set():
                    return
                proc = subprocess.Popen(cls.spawn_command([]), creationflags=subprocess.CREATE_NO_WINDOW)
                current_pid = proc.pid
                time.sleep(1.0)
                continue
            try:
                while True:
                    res = kernel32.WaitForSingleObject(h_proc, 400)
                    if cls.is_authorized_exit_set():
                        return
                    if res == WAIT_OBJECT_0:
                        time.sleep(0.3)
                        if cls.is_authorized_exit_set():
                            return
                        proc = subprocess.Popen(cls.spawn_command([]), creationflags=subprocess.CREATE_NO_WINDOW)
                        current_pid = proc.pid
                        break
            finally:
                kernel32.CloseHandle(h_proc)


# ==============================================================================
# 6. معالجة الصور والتمويه الخام بـ NumPy فقط (بدون PIL / OpenCV)
# ==============================================================================
class FastImageOps:
    @staticmethod
    def resize_nn(rgb: np.ndarray, out_w: int, out_h: int) -> np.ndarray:
        """تغيير حجم فائق السرعة بـ NumPy."""
        h, w = rgb.shape[:2]
        if h == out_h and w == out_w:
            return rgb
        y_idx = np.linspace(0, h - 1, out_h).astype(np.int32)
        x_idx = np.linspace(0, w - 1, out_w).astype(np.int32)
        return rgb[y_idx[:, None], x_idx[None, :]]

    @staticmethod
    def _box_blur_3x3(arr: np.ndarray) -> np.ndarray:
        f = arr.astype(np.float32)
        p = np.pad(f, ((1, 1), (1, 1), (0, 0)), mode="edge")
        out = (
            p[0:-2, 0:-2] + p[0:-2, 1:-1] + p[0:-2, 2:]
            + p[1:-1, 0:-2] + p[1:-1, 1:-1] + p[1:-1, 2:]
            + p[2:, 0:-2] + p[2:, 1:-1] + p[2:, 2:]
        ) / 9.0
        return np.clip(out, 0, 255).astype(np.uint8)

    @classmethod
    def heavy_blur_to_ppm(cls, rgb_crop: np.ndarray, target_w: int, target_h: int) -> Tuple[bytes, int]:
        """تطبيق تمويه/بكسلة ثقيلة غير قابلة للاسترجاع وتحويلها لصيغة PPM المباشرة لـ Tkinter."""
        # استخدام zoom=2 للمناطق الكبيرة لتسريع الرسم داخل Tkinter بـ 4 أضعاف
        zoom = 2 if (target_w >= 800 or target_h >= 600) else 1
        out_w = max(4, target_w // zoom)
        out_h = max(4, target_h // zoom)

        sw = max(6, out_w // 14)
        sh = max(6, out_h // 14)
        small = cls.resize_nn(rgb_crop, sw, sh)
        small = cls._box_blur_3x3(small)
        small = cls._box_blur_3x3(small)

        # تكبير ناعم بالتمويه مع تعتيم خفيف لإخفاء كامل التفاصيل
        up = cls.resize_nn(small, out_w, out_h)
        up = (up.astype(np.uint16) * 7 // 10).astype(np.uint8)

        header = f"P6\n{out_w} {out_h}\n255\n".encode("ascii")
        return header + np.ascontiguousarray(up).tobytes(), zoom


# ==============================================================================
# 7. محرك الذكاء الاصطناعي المحلي عالي الدقة (640m.onnx) بـ NumPy فقط
# ==============================================================================
class SmartVisionEngine:
    def __init__(self, status_cb: Callable[[str], None]):
        self.status_cb = status_cb
        self.session: Optional[ort.InferenceSession] = None
        self.input_name: str = ""
        self.input_w: int = 640
        self.input_h: int = 640

    @staticmethod
    def get_model_path() -> Path:
        if hasattr(sys, "_MEIPASS"):
            bundled = Path(sys._MEIPASS) / "640m.onnx"
            if bundled.exists() and bundled.stat().st_size > 5_000_000:
                return bundled
        local_dir = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
        beside = local_dir / "640m.onnx"
        if beside.exists() and beside.stat().st_size > 5_000_000:
            return beside
        cache_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / "640m.onnx"

    @staticmethod
    def _resolve_model_url() -> str:
        fallback = "https://github.com/notAI-tech/NudeNet/releases/download/v3.4-weights/640m.onnx"
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/notAI-tech/NudeNet/releases",
                headers={"User-Agent": "SafeGuardShield/3.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                releases = json.loads(resp.read().decode("utf-8"))
            for rel in releases:
                for asset in rel.get("assets", []):
                    if "640m.onnx" in asset.get("name", "").lower():
                        return asset["browser_download_url"]
        except Exception:
            pass
        return fallback

    def ensure_model(self) -> Path:
        path = self.get_model_path()
        if path.exists() and path.stat().st_size > 10_000_000:
            return path

        self.status_cb("جاري تجهيز ملف الحماية الذكية لأول مرة...")
        url = self._resolve_model_url()
        tmp = path.with_suffix(".part")
        req = urllib.request.Request(url, headers={"User-Agent": "SafeGuardShield/3.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            got = 0
            last = 0.0
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
                    now = time.perf_counter()
                    if total > 0 and (now - last) >= 1.0:
                        pct = int((got / total) * 100)
                        self.status_cb(f"جاري تجهيز الحماية الذكية ({pct}%)...")
                        last = now
        tmp.replace(path)
        return path

    def load(self) -> None:
        model_path = self.ensure_model()
        self.status_cb("جاري تشغيل الفحص الذكي...")
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = max(2, min(6, (os.cpu_count() or 4) // 2))
        avail = ort.get_available_providers()
        providers = [p for p in ("CUDAExecutionProvider", "DmlExecutionProvider", "CPUExecutionProvider") if p in avail]
        if not providers:
            providers = ["CPUExecutionProvider"]

        self.session = ort.InferenceSession(str(model_path), sess_options=opts, providers=providers)
        inp = self.session.get_inputs()[0]
        self.input_name = inp.name
        self.input_h = int(inp.shape[2]) if isinstance(inp.shape[2], int) else 640
        self.input_w = int(inp.shape[3]) if isinstance(inp.shape[3], int) else 640
        self.status_cb("الحماية الذكية تعمل بنجاح")

    @staticmethod
    def has_skin_tones(rgb_thumb: np.ndarray, min_ratio: float) -> bool:
        r = rgb_thumb[:, :, 0].astype(np.float32)
        g = rgb_thumb[:, :, 1].astype(np.float32)
        b = rgb_thumb[:, :, 2].astype(np.float32)
        cb = 128.0 - 0.168736 * r - 0.331264 * g + 0.5 * b
        cr = 128.0 + 0.5 * r - 0.418688 * g - 0.081312 * b
        mask = (cb >= 77.0) & (cb <= 127.0) & (cr >= 133.0) & (cr <= 173.0)
        return float(np.mean(mask)) >= min_ratio

    @staticmethod
    def _nms(boxes: np.ndarray, scores: np.ndarray, iou_thresh: float = 0.45) -> List[int]:
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
            order = order[np.where(iou <= iou_thresh)[0] + 1]
        return keep

    def detect(self, rgb: np.ndarray, min_conf: float = 0.32) -> List[dict]:
        orig_h, orig_w = rgb.shape[:2]
        if orig_h < 16 or orig_w < 16 or self.session is None:
            return []

        max_dim = max(orig_w, orig_h)
        scale = self.input_w / float(max_dim)
        rw = max(1, int(round(orig_w * scale)))
        rh = max(1, int(round(orig_h * scale)))

        resized = FastImageOps.resize_nn(rgb, rw, rh)
        canvas = np.zeros((self.input_h, self.input_w, 3), dtype=np.float32)
        canvas[:rh, :rw, :] = resized.astype(np.float32) / 255.0
        blob = np.transpose(canvas, (2, 0, 1))[np.newaxis, ...]

        outputs = self.session.run(None, {self.input_name: blob})
        preds = np.squeeze(outputs[0]).T

        class_scores = preds[:, 4:]
        class_ids = np.argmax(class_scores, axis=1)
        max_scores = class_scores[np.arange(len(preds)), class_ids]

        mask = max_scores >= min_conf
        if not np.any(mask):
            return []

        preds = preds[mask]
        class_ids = class_ids[mask]
        max_scores = max_scores[mask]

        factor = max_dim / float(self.input_w)
        cx = preds[:, 0] * factor
        cy = preds[:, 1] * factor
        bw = preds[:, 2] * factor
        bh = preds[:, 3] * factor

        x1 = np.clip(cx - bw / 2.0, 0, orig_w)
        y1 = np.clip(cy - bh / 2.0, 0, orig_h)
        x2 = np.clip(cx + bw / 2.0, 0, orig_w)
        y2 = np.clip(cy + bh / 2.0, 0, orig_h)

        boxes = np.stack([x1, y1, x2, y2], axis=1)
        keep = self._nms(boxes, max_scores, 0.45)

        results = []
        for idx in keep:
            cid = int(class_ids[idx])
            if 0 <= cid < len(MODEL_LABELS):
                bx1, by1, bx2, by2 = boxes[idx]
                results.append({
                    "class": MODEL_LABELS[cid],
                    "score": float(max_scores[idx]),
                    "box": (int(bx1), int(by1), int(bx2), int(by2)),
                })
        return results


# ==============================================================================
# 8. خيط المراقبة الذكي (استثناء برامج الدراسة + فحص النافذة النشطة + الإغلاق التلقائي)
# ==============================================================================
class ScreenMonitorWorker(threading.Thread):
    def __init__(
        self,
        config: ShieldConfig,
        overlay_queue: queue.Queue,
        status_cb: Callable[[str], None],
        notify_cb: Callable[[str, str], None],
        on_block_event: Callable[[], None],
        on_tamper_detected: Callable[[int, str], None],
    ):
        super().__init__(daemon=True)
        self.config = config
        self.overlay_queue = overlay_queue
        self.status_cb = status_cb
        self.notify_cb = notify_cb
        self.on_block_event = on_block_event
        self.on_tamper_detected = on_tamper_detected

        self.engine = SmartVisionEngine(status_cb)
        self._running = True
        self._panic_active = False
        self._prev_gray: Optional[np.ndarray] = None
        self._last_nsfw_time = 0.0
        self._was_active = False
        self._last_notify_time = 0.0
        self._last_dns_enforce = 0.0
        self._last_autoclose_time = 0.0
        self._continuous_hwnd = 0
        self._continuous_start = 0.0
        self._last_tamper_time = 0.0
        self._tamper_grace_until = 0.0

    def force_rescan(self) -> None:
        self._prev_gray = None

    def set_panic_mode(self, active: bool) -> None:
        self._panic_active = active
        if active:
            self._emit_panic_screen()
        else:
            self._was_active = False
            self._prev_gray = None
            self._emit_overlay([], False, "")

    def grant_tamper_grace(self, seconds: float = 120.0) -> None:
        self._tamper_grace_until = time.perf_counter() + seconds

    def stop(self) -> None:
        self._running = False

    def _emit_panic_screen(self) -> None:
        try:
            with mss.mss() as sct:
                mon = sct.monitors[0]
                raw = sct.grab(mon)
                bgra = np.frombuffer(raw.bgra, dtype=np.uint8).reshape(raw.height, raw.width, 4)
                rgb = bgra[:, :, 2::-1]
                ppm, zoom = FastImageOps.heavy_blur_to_ppm(rgb, raw.width, raw.height)
                self._emit_overlay([((0, 0, raw.width, raw.height), ppm, zoom)], True, "وضع الطوارئ السريع (اضغط Ctrl+Alt+B للإلغاء)")
        except Exception:
            pass

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
    def _overlap_ratio(a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]) -> float:
        ix1, iy1 = max(a[0], b[0]), max(a[1], b[1])
        ix2, iy2 = min(a[2], b[2]), min(a[3], b[3])
        if ix2 <= ix1 or iy2 <= iy1:
            return 0.0
        inter = (ix2 - ix1) * (iy2 - iy1)
        area_a = max(1, (a[2] - a[0]) * (a[3] - a[1]))
        return inter / area_a

    def _emit_overlay(self, patches: List[Tuple[Tuple[int, int, int, int], bytes, int]], active: bool, banner: str) -> None:
        while not self.overlay_queue.empty():
            try:
                self.overlay_queue.get_nowait()
            except queue.Empty:
                break
        self.overlay_queue.put((patches, active, banner))

    def _maybe_notify(self, title: str, msg: str) -> None:
        now = time.perf_counter()
        if now - self._last_notify_time >= 8.0:
            self._last_notify_time = now
            self.notify_cb(title, msg)

    def _filter_detections(
        self,
        detections: List[dict],
        thresholds: Dict[str, float],
        offset_x: int,
        offset_y: int,
        orig_w: int,
        orig_h: int,
    ) -> List[Tuple[int, int, int, int]]:
        face_boxes = [
            d["box"] for d in detections
            if d["class"] in ("FACE_FEMALE", "FACE_MALE") and d["score"] >= 0.65
        ]
        pad = self.config.box_padding
        boxes: List[Tuple[int, int, int, int]] = []
        for d in detections:
            cls_name = d["class"]
            score = d["score"]
            if cls_name in thresholds and score >= thresholds[cls_name]:
                if score < 0.62 and any(self._overlap_ratio(d["box"], fb) > 0.65 for fb in face_boxes):
                    continue
                bx1, by1, bx2, by2 = d["box"]
                x1 = max(0, offset_x + bx1 - pad)
                y1 = max(0, offset_y + by1 - pad)
                x2 = min(orig_w, offset_x + bx2 + pad)
                y2 = min(orig_h, offset_y + by2 + pad)
                if x2 > x1 and y2 > y1:
                    boxes.append((x1, y1, x2, y2))
        return boxes

    def run(self) -> None:
        try:
            self.engine.load()
        except Exception:
            self.status_cb("تعذر تحميل ملف الحماية — تحقق من الإنترنت")
            return

        with mss.mss() as sct:
            while self._running:
                loop_start = time.perf_counter()

                # الحفاظ على الحماية الشبكية كل 90 ثانية إذا كانت مفعلة
                if self.config.web_block_enabled and (loop_start - self._last_dns_enforce) > 90.0:
                    self._last_dns_enforce = loop_start
                    SystemGuardian.refresh_dns_only()

                # وضع الطوارئ السريع (Ctrl+Alt+B)
                if self._panic_active:
                    time.sleep(0.25)
                    continue

                hwnd, fg_title, fg_exe, fg_rect = WindowsHelper.get_foreground_info()

                # 1. الحماية من التلاعب بمحرر السجل وإعدادات الشبكة عند وجود رقم سري
                if self.config.pin_hash and loop_start > self._tamper_grace_until:
                    is_tamper = (fg_exe in TAMPER_PROCESSES) or any(t in fg_title for t in TAMPER_TITLES)
                    if is_tamper:
                        WindowsHelper.minimize_window(hwnd)
                        if loop_start - self._last_tamper_time > 4.0:
                            self._last_tamper_time = loop_start
                            self.on_tamper_detected(hwnd, fg_title)
                        time.sleep(0.3)
                        continue

                if not self.config.enabled:
                    if self._was_active:
                        self._was_active = False
                        self._continuous_start = 0.0
                        self._emit_overlay([], False, "")
                    time.sleep(0.35)
                    continue

                # 2. استثناء برامج البرمجة والدراسة تلقائياً لتوفير المعالج والبطارية
                if fg_exe in EXCLUDED_WORK_APPS:
                    if self._was_active and (loop_start - self._last_nsfw_time) > self.config.hold_seconds:
                        self._was_active = False
                        self._continuous_start = 0.0
                        self._emit_overlay([], False, "")
                    time.sleep(0.55)
                    continue

                try:
                    mon = sct.monitors[0]
                    raw = sct.grab(mon)
                    bgra = np.frombuffer(raw.bgra, dtype=np.uint8).reshape(raw.height, raw.width, 4)
                    rgb = bgra[:, :, 2::-1]
                    orig_h, orig_w = rgb.shape[:2]
                    now = time.perf_counter()

                    # 3. فحص عنوان المتصفح ضد الكلمات المحظورة (الافتراضية + المخصصة)
                    blocked_kws = self.config.all_blocked_keywords()
                    if fg_title and any(tok in fg_title for tok in blocked_kws):
                        self._last_nsfw_time = now
                        ppm, zoom = FastImageOps.heavy_blur_to_ppm(rgb, orig_w, orig_h)
                        self._emit_overlay(
                            [((0, 0, orig_w, orig_h), ppm, zoom)],
                            True,
                            "تم حجب صفحة غير لائقة تلقائياً",
                        )
                        if not self._was_active:
                            self.on_block_event()
                            self._maybe_notify("تم صد صفحة غير لائقة", "تم تمويه الصفحة المخالفة لحمايتك.")
                        self._was_active = True

                        if self.config.auto_close_enabled and fg_exe in BROWSER_PROCESSES:
                            if now - self._last_autoclose_time >= 2.5:
                                self._last_autoclose_time = now
                                WindowsHelper.send_ctrl_w()
                        time.sleep(0.35)
                        continue

                    # 4. كشف تغير الشاشة وفلتر لون البشرة السريع
                    thumb = FastImageOps.resize_nn(rgb, 160, 90)
                    gray = (0.299 * thumb[:, :, 0] + 0.587 * thumb[:, :, 1] + 0.114 * thumb[:, :, 2]).astype(np.float32)

                    changed = True
                    if self._prev_gray is not None:
                        if float(np.mean(np.abs(self._prev_gray - gray))) < self.config.frame_diff_threshold:
                            changed = False
                    if changed:
                        self._prev_gray = gray

                    if not changed:
                        # استمرار مراقبة عداد الإغلاق التلقائي حتى لو ثبتت الصورة المخالفة
                        if self._was_active and self.config.auto_close_enabled and fg_exe in BROWSER_PROCESSES:
                            if self._continuous_start > 0 and hwnd == self._continuous_hwnd:
                                if (now - self._continuous_start) >= 2.5 and (now - self._last_autoclose_time) >= 3.0:
                                    self._last_autoclose_time = now
                                    self._continuous_start = 0.0
                                    WindowsHelper.send_ctrl_w()
                        time.sleep(0.35)
                        continue

                    if not self.engine.has_skin_tones(thumb, self.config.min_skin_ratio):
                        self._continuous_start = 0.0
                        if self._was_active and (now - self._last_nsfw_time) > self.config.hold_seconds:
                            self._was_active = False
                            self._emit_overlay([], False, "")
                        time.sleep(0.35)
                        continue

                    # 5. الفحص المزدوج عالي الدقة: الشاشة الكاملة + النافذة النشطة بدقتها الأصلية
                    thresholds = self.config.active_thresholds()
                    min_conf = min(thresholds.values())
                    raw_boxes: List[Tuple[int, int, int, int]] = []

                    # (أ) فحص النافذة النشطة (للتقاط الصور المصغرة والفيديوهات الصغيرة بدقة عالية)
                    wx1, wy1, wx2, wy2 = fg_rect
                    rx1 = max(0, wx1 - mon["left"])
                    ry1 = max(0, wy1 - mon["top"])
                    rx2 = min(orig_w, wx2 - mon["left"])
                    ry2 = min(orig_h, wy2 - mon["top"])
                    roi_w, roi_h = rx2 - rx1, ry2 - ry1
                    roi_is_distinct = (
                        roi_w >= 160 and roi_h >= 160
                        and (roi_w * roi_h) < int(orig_w * orig_h * 0.88)
                    )
                    if roi_is_distinct:
                        roi_crop = rgb[ry1:ry2, rx1:rx2]
                        roi_dets = self.engine.detect(roi_crop, min_conf=min_conf)
                        raw_boxes.extend(
                            self._filter_detections(roi_dets, thresholds, rx1, ry1, orig_w, orig_h)
                        )

                    # (ب) فحص الشاشة الكاملة
                    full_dets = self.engine.detect(rgb, min_conf=min_conf)
                    raw_boxes.extend(
                        self._filter_detections(full_dets, thresholds, 0, 0, orig_w, orig_h)
                    )

                    if raw_boxes:
                        self._last_nsfw_time = now
                        merged = self._merge_boxes(raw_boxes)
                        patches: List[Tuple[Tuple[int, int, int, int], bytes, int]] = []

                        if self.config.effective_full_blur():
                            ppm, zoom = FastImageOps.heavy_blur_to_ppm(rgb, orig_w, orig_h)
                            patches.append(((0, 0, orig_w, orig_h), ppm, zoom))
                        else:
                            for x1, y1, x2, y2 in merged:
                                crop = rgb[y1:y2, x1:x2]
                                ppm, zoom = FastImageOps.heavy_blur_to_ppm(crop, x2 - x1, y2 - y1)
                                patches.append(((x1, y1, x2, y2), ppm, zoom))

                        banner_text = (
                            "الحماية الليلية المضاعفة — تم إخفاء محتوى غير لائق"
                            if self.config.is_night_active()
                            else "تم إيجاد مواد غير لائقة — تم التمويه تلقائياً"
                        )
                        self._emit_overlay(patches, True, banner_text)

                        if not self._was_active:
                            self.on_block_event()
                            self._maybe_notify("تم حجب محتوى غير لائق", "تم إخفاء المحتوى المخالف عن الشاشة تلقائياً.")
                        self._was_active = True

                        # حساب المدة المتواصلة للإغلاق التلقائي بعد 2.5 ثانية
                        if hwnd == self._continuous_hwnd and self._continuous_start > 0:
                            if (
                                self.config.auto_close_enabled
                                and fg_exe in BROWSER_PROCESSES
                                and (now - self._continuous_start) >= 2.5
                                and (now - self._last_autoclose_time) >= 3.0
                            ):
                                self._last_autoclose_time = now
                                self._continuous_start = 0.0
                                WindowsHelper.send_ctrl_w()
                        else:
                            self._continuous_hwnd = hwnd
                            self._continuous_start = now
                    else:
                        self._continuous_start = 0.0
                        if self._was_active and (now - self._last_nsfw_time) > self.config.hold_seconds:
                            self._was_active = False
                            self._emit_overlay([], False, "")

                except Exception:
                    pass

                target_interval = 0.28 if self._was_active else 0.42
                elapsed = time.perf_counter() - loop_start
                if elapsed < target_interval:
                    time.sleep(target_interval - elapsed)


# ==============================================================================
# 9. أيقونة شريط المهام الأصلية (Win32 ctypes فقط) + اختصار الطوارئ Ctrl+Alt+B
# ==============================================================================
class NativeTrayController(threading.Thread):
    CMD_OPEN = 1001
    CMD_TOGGLE = 1002
    CMD_EXIT = 1003

    def __init__(
        self,
        get_status_label: Callable[[], str],
        is_enabled: Callable[[], bool],
        on_open_dashboard: Callable[[], None],
        on_toggle_protection: Callable[[], None],
        on_exit: Callable[[], None],
        on_panic_hotkey: Callable[[], None],
    ):
        super().__init__(daemon=True)
        self._get_status_label = get_status_label
        self._is_enabled = is_enabled
        self._on_open_dashboard = on_open_dashboard
        self._on_toggle_protection = on_toggle_protection
        self._on_exit = on_exit
        self._on_panic_hotkey = on_panic_hotkey

        self.hwnd: int = 0
        self._hicon_on: int = 0
        self._hicon_off: int = 0
        self._wndproc_ref = None
        self._ready = threading.Event()

    @staticmethod
    def _create_shield_hicon(active: bool) -> int:
        """رسم أيقونة 32×32 في الذاكرة مباشرة بـ NumPy وWin32 بدون PIL."""
        size = 32
        img = np.zeros((size, size, 4), dtype=np.uint8)  # BGRA
        # خلفية دائرية/مربعة بزوايا ناعمة
        bg = (129, 185, 16, 255) if active else (68, 68, 239, 255)  # أخضر أو أحمر (BGRA)
        white = (255, 255, 255, 255)
        img[3:29, 3:29] = bg
        # تقليم الزوايا
        for y, x in ((3, 3), (3, 28), (28, 3), (28, 28)):
            img[y, x] = (0, 0, 0, 0)
        # إطار أبيض
        img[3, 5:27] = white
        img[28, 5:27] = white
        img[5:27, 3] = white
        img[5:27, 28] = white

        if active:
            # علامة صح بيضاء
            pts = [(17, 9), (18, 10), (19, 11), (20, 12), (21, 13), (20, 14), (19, 15),
                   (18, 16), (17, 17), (16, 18), (15, 19), (14, 20), (13, 21), (12, 22)]
            for y, x in pts:
                img[y - 1:y + 2, x - 1:x + 2] = white
        else:
            # علامة إيقاف مؤقت
            img[10:22, 11:15] = white
            img[10:22, 17:21] = white

        # قلب الصورة عمودياً للـ DIB (bottom-up)
        buf = np.ascontiguousarray(img[::-1, :, :])

        bmi = BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.biWidth = size
        bmi.biHeight = size
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = 0  # BI_RGB

        bits_ptr = ctypes.c_void_p()
        hdc = user32.GetDC(0)
        hbm_color = gdi32.CreateDIBSection(hdc, ctypes.byref(bmi), 0, ctypes.byref(bits_ptr), None, 0)
        user32.ReleaseDC(0, hdc)
        if not hbm_color or not bits_ptr.value:
            return user32.LoadIconW(None, 32512)

        ctypes.memmove(bits_ptr.value, buf.ctypes.data, buf.nbytes)
        hbm_mask = gdi32.CreateBitmap(size, size, 1, 1, None)

        ii = ICONINFO()
        ii.fIcon = True
        ii.hbmMask = hbm_mask
        ii.hbmColor = hbm_color
        hicon = user32.CreateIconIndirect(ctypes.byref(ii))

        gdi32.DeleteObject(hbm_color)
        if hbm_mask:
            gdi32.DeleteObject(hbm_mask)
        return hicon if hicon else user32.LoadIconW(None, 32512)

    def _build_nid(self, flags: int, tip: str = "", info_title: str = "", info_msg: str = "", info_flags: int = NIIF_INFO) -> NOTIFYICONDATAW:
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._hicon_on if self._is_enabled() else self._hicon_off
        if tip:
            nid.szTip = tip[:127]
        if info_msg:
            nid.szInfoTitle = info_title[:63]
            nid.szInfo = info_msg[:255]
            nid.dwInfoFlags = info_flags
        return nid

    def update_icon(self, tip: str) -> None:
        if not self.hwnd:
            return
        nid = self._build_nid(NIF_ICON | NIF_TIP, tip=tip)
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def notify(self, title: str, msg: str, warning: bool = False) -> None:
        if not self.hwnd:
            return
        flags = NIIF_WARNING if warning else NIIF_INFO
        nid = self._build_nid(NIF_INFO, info_title=title, info_msg=msg, info_flags=flags)
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def stop(self) -> None:
        if self.hwnd:
            user32.UnregisterHotKey(self.hwnd, HOTKEY_ID_PANIC)
            nid = self._build_nid(0)
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            user32.PostMessageW(self.hwnd, WM_DESTROY, 0, 0)

    def _show_context_menu(self) -> None:
        """قائمة مختصرة جداً (4 خيارات فقط)."""
        hmenu = user32.CreatePopupMenu()
        status_text = self._get_status_label()
        toggle_text = "إيقاف الحماية" if self._is_enabled() else "تفعيل الحماية"

        user32.AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, status_text)
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(hmenu, MF_STRING, self.CMD_OPEN, "فتح لوحة التحكم")
        user32.AppendMenuW(hmenu, MF_STRING, self.CMD_TOGGLE, toggle_text)
        user32.AppendMenuW(hmenu, MF_STRING, self.CMD_EXIT, "خروج")

        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)
        cmd = user32.TrackPopupMenu(
            hmenu,
            TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
            pt.x,
            pt.y,
            0,
            self.hwnd,
            None,
        )
        user32.DestroyMenu(hmenu)

        if cmd == self.CMD_OPEN:
            self._on_open_dashboard()
        elif cmd == self.CMD_TOGGLE:
            self._on_toggle_protection()
        elif cmd == self.CMD_EXIT:
            self._on_exit()

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON:
            event = lparam & 0xFFFF
            if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                self._on_open_dashboard()
            elif event == WM_RBUTTONUP:
                self._show_context_menu()
            return 0
        if msg == WM_HOTKEY and wparam == HOTKEY_ID_PANIC:
            self._on_panic_hotkey()
            return 0
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def run(self) -> None:
        hinst = kernel32.GetModuleHandleW(None)
        cls_name = f"{APP_NAME}_TrayWindow"
        self._wndproc_ref = WNDPROC(self._wnd_proc)

        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = cls_name
        user32.RegisterClassW(ctypes.byref(wc))

        self.hwnd = user32.CreateWindowExW(
            0, cls_name, APP_NAME, 0, 0, 0, 0, 0, None, None, hinst, None
        )
        self._hicon_on = self._create_shield_hicon(True)
        self._hicon_off = self._create_shield_hicon(False)

        nid = self._build_nid(NIF_MESSAGE | NIF_ICON | NIF_TIP, tip="درع الحماية الشاملة")
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

        # تسجيل اختصار الطوارئ العالمي Ctrl + Alt + B
        user32.RegisterHotKey(self.hwnd, HOTKEY_ID_PANIC, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 0x42)
        self._ready.set()

        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        if self._hicon_on:
            user32.DestroyIcon(self._hicon_on)
        if self._hicon_off:
            user32.DestroyIcon(self._hicon_off)


# ==============================================================================
# 10. طبقة التمويه الشفافة فوق الشاشة (PPM خام بدون PIL)
# ==============================================================================
class ProtectionOverlay:
    TRANSPARENT_KEY = "#010203"

    def __init__(self, master: tk.Tk):
        self.win = tk.Toplevel(master)
        self.win.withdraw()
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.attributes("-transparentcolor", self.TRANSPARENT_KEY)
        self.win.configure(bg=self.TRANSPARENT_KEY)

        self.vx = user32.GetSystemMetrics(76)
        self.vy = user32.GetSystemMetrics(77)
        self.vw = user32.GetSystemMetrics(78)
        self.vh = user32.GetSystemMetrics(79)
        self.primary_w = user32.GetSystemMetrics(0)
        self.primary_h = user32.GetSystemMetrics(1)

        self.win.geometry(f"{self.vw}x{self.vh}+{self.vx}+{self.vy}")
        self.canvas = tk.Canvas(
            self.win,
            width=self.vw,
            height=self.vh,
            bg=self.TRANSPARENT_KEY,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self._photo_refs: List[tk.PhotoImage] = []
        self._visible = False
        self._flags_applied = False

    def _apply_win32_flags(self) -> None:
        if self._flags_applied:
            return
        self.win.update_idletasks()
        wid = self.win.winfo_id()
        hwnd = user32.GetParent(wid) or wid
        ex = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        user32.SetWindowLongW(
            hwnd,
            GWL_EXSTYLE,
            ex | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        )
        user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        self._flags_applied = True

    def render(self, patches: List[Tuple[Tuple[int, int, int, int], bytes, int]], active: bool, banner: str) -> None:
        if not active or not patches:
            if self._visible:
                self.canvas.delete("all")
                self._photo_refs.clear()
                self.win.withdraw()
                self._visible = False
            return

        if not self._visible:
            self.win.deiconify()
            self._apply_win32_flags()
            self.win.lift()
            self.win.attributes("-topmost", True)
            self._visible = True

        self.canvas.delete("all")
        self._photo_refs.clear()

        for (x1, y1, x2, y2), ppm_bytes, zoom in patches:
            photo = tk.PhotoImage(data=ppm_bytes)
            if zoom > 1:
                photo = photo.zoom(zoom, zoom)
            self._photo_refs.append(photo)
            self.canvas.create_image(x1, y1, anchor=tk.NW, image=photo)
            self.canvas.create_rectangle(x1, y1, x2, y2, outline="#EF4444", width=3)
            if (x2 - x1) >= 200 and (y2 - y1) >= 64:
                cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                self.canvas.create_rectangle(cx - 115, cy - 20, cx + 115, cy + 20, fill="#1E293B", outline="#EF4444")
                self.canvas.create_text(cx, cy, text="تم إخفاء محتوى غير لائق", fill="#FFFFFF", font=("Segoe UI", 12, "bold"))

        banner_w, banner_h = 560, 60
        offset_x = max(0, -self.vx)
        offset_y = max(0, -self.vy)
        bx1 = offset_x + (self.primary_w - banner_w) // 2
        by1 = offset_y + 24
        bx2, by2 = bx1 + banner_w, by1 + banner_h
        self.canvas.create_rectangle(bx1, by1, bx2, by2, fill="#B91C1C", outline="#FECACA", width=2)
        self.canvas.create_text(
            (bx1 + bx2) // 2,
            (by1 + by2) // 2,
            text=banner or "تم إيجاد مواد غير لائقة — تم التمويه تلقائياً",
            fill="#FFFFFF",
            font=("Segoe UI", 14, "bold"),
        )


# ==============================================================================
# 11. لوحة التحكم الرئيسية البسيطة + نافذة الخيارات المتقدمة
# ==============================================================================
class SimpleDashboard:
    def __init__(self, master: tk.Tk, app: "SafeGuardApp"):
        self.app = app
        self.win = tk.Toplevel(master)
        self.win.title("درع الحماية الشاملة")
        self.win.geometry("500x670")
        self.win.resizable(False, False)
        self.win.configure(bg="#F8FAFC")
        self.win.protocol("WM_DELETE_WINDOW", self.hide)
        self._adv_win: Optional[tk.Toplevel] = None
        self._kw_listbox: Optional[tk.Listbox] = None

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # 1. بطاقة الحالة الكبرى (أخضر = محمي | أحمر = متوقف)
        self.status_card = tk.Frame(self.win, bg="#10B981", padx=18, pady=16)
        self.status_card.pack(fill=tk.X, padx=18, pady=(16, 10))

        self.lbl_status_main = tk.Label(
            self.status_card,
            text="جهازك محمي الآن",
            font=("Segoe UI", 18, "bold"),
            fg="#FFFFFF",
            bg="#10B981",
        )
        self.lbl_status_main.pack()

        self.lbl_status_sub = tk.Label(
            self.status_card,
            text="الحماية الذكية تعمل تلقائياً في الخلفية",
            font=("Segoe UI", 10),
            fg="#ECFDF5",
            bg="#10B981",
        )
        self.lbl_status_sub.pack(pady=(4, 0))

        # 2. سطر العداد التشجيعي للأيام النظيفة
        self.counter_card = tk.Frame(self.win, bg="#FFFFFF", bd=1, relief=tk.SOLID, padx=12, pady=10)
        self.counter_card.pack(fill=tk.X, padx=18, pady=(0, 10))

        self.lbl_counter = tk.Label(
            self.counter_card,
            text="أنت ملتزم منذ: 0 يوم و 0 ساعة  |  تم صد: 0 محاولة",
            font=("Segoe UI", 11, "bold"),
            fg="#0F172A",
            bg="#FFFFFF",
        )
        self.lbl_counter.pack()

        # 3. شريط العد التنازلي لقفل الـ 30 دقيقة (يظهر فقط عند وجود طلب إيقاف مؤجل)
        self.cooldown_frame = tk.Frame(self.win, bg="#FEF3C7", bd=1, relief=tk.SOLID, padx=12, pady=8)
        self.lbl_cooldown = tk.Label(
            self.cooldown_frame,
            text="",
            font=("Segoe UI", 10, "bold"),
            fg="#92400E",
            bg="#FEF3C7",
        )
        self.lbl_cooldown.pack(side=tk.RIGHT)
        self.btn_cancel_cooldown = tk.Button(
            self.cooldown_frame,
            text="إلغاء الطلب",
            font=("Segoe UI", 9, "bold"),
            bg="#D97706",
            fg="#FFFFFF",
            activebackground="#B45309",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self.app.cancel_pending_cooldown,
        )
        self.btn_cancel_cooldown.pack(side=tk.LEFT)

        # 4. الزر الرئيسي الكبير: تفعيل الحماية الشاملة بضغطة واحدة
        self.btn_one_click = tk.Button(
            self.win,
            text="تفعيل الحماية الشاملة بضغطة واحدة",
            font=("Segoe UI", 13, "bold"),
            bg="#059669",
            fg="#FFFFFF",
            activebackground="#047857",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            pady=12,
            cursor="hand2",
            command=self.app.activate_full_protection_one_click,
        )
        self.btn_one_click.pack(fill=tk.X, padx=18, pady=(2, 12))

        # 5. أهم 4 خيارات بمفاتيح تشغيل/إيقاف كبيرة وواضحة
        toggles_box = tk.Frame(self.win, bg="#F8FAFC")
        toggles_box.pack(fill=tk.BOTH, expand=True, padx=18)

        self.btn_web = self._make_toggle_row(
            toggles_box,
            "حجب المواقع الضارة والبحث الآمن",
            "يمنع المواقع الإباحية والتصفح الخفي تلقائياً",
            self.app.toggle_web_block,
        )
        self.btn_autoclose = self._make_toggle_row(
            toggles_box,
            "إغلاق الصفحة المخالفة تلقائياً",
            "يغلق التبويب فوراً عند ظهور محتوى غير لائق",
            self.app.toggle_auto_close,
        )
        self.btn_night = self._make_toggle_row(
            toggles_box,
            "حماية مضاعفة تلقائياً ليلاً",
            "تشديد الفحص وإخفاء كامل الشاشة من 11 مساءً إلى 6 صباحاً",
            self.app.toggle_night_mode,
        )
        self.btn_cooldown = self._make_toggle_row(
            toggles_box,
            "قفل الإعدادات 30 دقيقة عند الإيقاف",
            "يؤخر إيقاف الحماية 30 دقيقة لحمايتك في لحظات الضعف",
            self.app.toggle_cooldown_lock,
        )

        # 6. أزرار التحكم السفلية
        footer = tk.Frame(self.win, bg="#F8FAFC")
        footer.pack(fill=tk.X, padx=18, pady=(8, 14))

        self.btn_main_power = tk.Button(
            footer,
            text="إيقاف الحماية مؤقتاً",
            font=("Segoe UI", 11, "bold"),
            bg="#EF4444",
            fg="#FFFFFF",
            activebackground="#DC2626",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.app.request_toggle_protection,
        )
        self.btn_main_power.pack(side=tk.RIGHT)

        self.btn_advanced = tk.Button(
            footer,
            text="خيارات متقدمة",
            font=("Segoe UI", 10),
            bg="#E2E8F0",
            fg="#334155",
            activebackground="#CBD5E1",
            relief=tk.FLAT,
            padx=14,
            pady=8,
            cursor="hand2",
            command=self.open_advanced_window,
        )
        self.btn_advanced.pack(side=tk.LEFT)

    def _make_toggle_row(self, parent: tk.Frame, title: str, subtitle: str, command: Callable[[], None]) -> tk.Button:
        row = tk.Frame(parent, bg="#FFFFFF", bd=1, relief=tk.SOLID, padx=12, pady=10)
        row.pack(fill=tk.X, pady=5)

        btn = tk.Button(
            row,
            text="مفعّل",
            width=9,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            pady=6,
            cursor="hand2",
            command=command,
        )
        btn.pack(side=tk.LEFT, padx=(0, 10))

        text_box = tk.Frame(row, bg="#FFFFFF")
        text_box.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        tk.Label(
            text_box, text=title, font=("Segoe UI", 11, "bold"),
            fg="#0F172A", bg="#FFFFFF", anchor="e", justify=tk.RIGHT,
        ).pack(fill=tk.X)
        tk.Label(
            text_box, text=subtitle, font=("Segoe UI", 8),
            fg="#64748B", bg="#FFFFFF", anchor="e", justify=tk.RIGHT,
        ).pack(fill=tk.X)
        return btn

    @staticmethod
    def _style_toggle(btn: tk.Button, is_on: bool) -> None:
        if is_on:
            btn.configure(text="مفعّل (ON)", bg="#10B981", fg="#FFFFFF", activebackground="#059669", activeforeground="#FFFFFF")
        else:
            btn.configure(text="متوقف (OFF)", bg="#E2E8F0", fg="#475569", activebackground="#CBD5E1", activeforeground="#0F172A")

    def refresh(self) -> None:
        cfg = self.app.config
        if cfg.enabled:
            bg = "#10B981"
            self.status_card.configure(bg=bg)
            self.lbl_status_main.configure(text="جهازك محمي الآن", bg=bg)
            sub = self.app.engine_status_text
            if cfg.is_night_active():
                sub = "الحماية الليلية المضاعفة تعمل الآن"
            self.lbl_status_sub.configure(text=sub, bg=bg)
            self.btn_main_power.configure(text="إيقاف الحماية مؤقتاً", bg="#EF4444", activebackground="#DC2626")
        else:
            bg = "#EF4444"
            self.status_card.configure(bg=bg)
            self.lbl_status_main.configure(text="الحماية متوقفة حالياً", bg=bg)
            self.lbl_status_sub.configure(text="اضغط على الزر الأخضر لتفعيل الحماية فوراً", bg=bg)
            self.btn_main_power.configure(text="تفعيل الحماية الآن", bg="#10B981", activebackground="#059669")

        days, hours = cfg.clean_duration_parts()
        self.lbl_counter.configure(
            text=f"أنت ملتزم منذ: {days} يوم و {hours} ساعة  |  تم صد: {cfg.blocked_count} محاولة"
        )

        self._style_toggle(self.btn_web, cfg.web_block_enabled)
        self._style_toggle(self.btn_autoclose, cfg.auto_close_enabled)
        self._style_toggle(self.btn_night, cfg.night_mode_enabled)
        self._style_toggle(self.btn_cooldown, cfg.cooldown_lock_enabled)

        # عرض شريط العد التنازلي للـ 30 دقيقة إن كان نشطاً
        if cfg.pending_action and cfg.pending_execute_at > time.time():
            rem = int(cfg.pending_execute_at - time.time())
            mins, secs = divmod(rem, 60)
            self.lbl_cooldown.configure(text=f"سيتم تنفيذ الإيقاف بعد: {mins:02d}:{secs:02d}")
            if not self.cooldown_frame.winfo_ismapped():
                self.cooldown_frame.pack(fill=tk.X, padx=18, pady=(0, 8), before=self.btn_one_click)
        else:
            if self.cooldown_frame.winfo_ismapped():
                self.cooldown_frame.pack_forget()

        if self._adv_win and self._adv_win.winfo_exists():
            self._refresh_advanced_controls()

    def open_advanced_window(self) -> None:
        if self._adv_win and self._adv_win.winfo_exists():
            self._adv_win.lift()
            return

        adv = tk.Toplevel(self.win)
        adv.title("خيارات متقدمة")
        adv.geometry("460x540")
        adv.resizable(False, False)
        adv.configure(bg="#F8FAFC")
        self._adv_win = adv

        # قفل برقم سري
        self.btn_pin = tk.Button(
            adv,
            text="قفل البرنامج برقم سري",
            font=("Segoe UI", 11, "bold"),
            bg="#1D4ED8",
            fg="#FFFFFF",
            relief=tk.FLAT,
            pady=9,
            cursor="hand2",
            command=self.app.configure_pin,
        )
        self.btn_pin.pack(fill=tk.X, padx=16, pady=(14, 8))

        # خيارات إضافية بسيطة
        self.btn_full_blur = tk.Button(
            adv, font=("Segoe UI", 10, "bold"), relief=tk.FLAT, pady=8, cursor="hand2",
            command=self.app.toggle_full_blur,
        )
        self.btn_full_blur.pack(fill=tk.X, padx=16, pady=4)

        self.btn_strict = tk.Button(
            adv, font=("Segoe UI", 10, "bold"), relief=tk.FLAT, pady=8, cursor="hand2",
            command=self.app.toggle_strict_mode,
        )
        self.btn_strict.pack(fill=tk.X, padx=16, pady=4)

        tk.Button(
            adv,
            text="تفعيل التشغيل التلقائي مع بداية الويندوز",
            font=("Segoe UI", 10),
            bg="#E2E8F0",
            fg="#0F172A",
            relief=tk.FLAT,
            pady=7,
            cursor="hand2",
            command=self.app.install_autostart,
        ).pack(fill=tk.X, padx=16, pady=4)

        # إدارة الكلمات المخصصة المحظورة في عناوين المتصفح
        kw_frame = tk.LabelFrame(
            adv,
            text="كلمات مخصصة لحظرها في عناوين المتصفح",
            font=("Segoe UI", 10, "bold"),
            bg="#FFFFFF",
            fg="#0F172A",
            padx=10,
            pady=10,
        )
        kw_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(10, 8))

        add_row = tk.Frame(kw_frame, bg="#FFFFFF")
        add_row.pack(fill=tk.X, pady=(0, 8))

        self.entry_kw = tk.Entry(add_row, font=("Segoe UI", 10), justify=tk.RIGHT)
        self.entry_kw.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0))

        tk.Button(
            add_row,
            text="إضافة",
            font=("Segoe UI", 9, "bold"),
            bg="#10B981",
            fg="#FFFFFF",
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._add_keyword,
        ).pack(side=tk.LEFT)

        self._kw_listbox = tk.Listbox(kw_frame, font=("Segoe UI", 10), height=6, justify=tk.RIGHT)
        self._kw_listbox.pack(fill=tk.BOTH, expand=True)

        tk.Button(
            kw_frame,
            text="حذف الكلمة المحددة",
            font=("Segoe UI", 9, "bold"),
            bg="#EF4444",
            fg="#FFFFFF",
            relief=tk.FLAT,
            pady=5,
            cursor="hand2",
            command=self._delete_keyword,
        ).pack(fill=tk.X, pady=(8, 0))

        # معلومة اختصار الطوارئ
        tk.Label(
            adv,
            text="زر الطوارئ الفوري من أي مكان: Ctrl + Alt + B (تمويه كامل + كتم الصوت)",
            font=("Segoe UI", 9, "bold"),
            fg="#475569",
            bg="#F8FAFC",
        ).pack(pady=(4, 12))

        self._refresh_advanced_controls()

    def _refresh_advanced_controls(self) -> None:
        cfg = self.app.config
        self.btn_pin.configure(
            text="تغيير أو إزالة الرقم السري (مفعّل حالياً)" if cfg.pin_hash else "قفل البرنامج برقم سري"
        )
        self.btn_full_blur.configure(
            text=f"تمويه الشاشة بالكامل دائماً: {'مفعّل' if cfg.full_screen_blur else 'متوقف'}",
            bg="#10B981" if cfg.full_screen_blur else "#E2E8F0",
            fg="#FFFFFF" if cfg.full_screen_blur else "#0F172A",
        )
        self.btn_strict.configure(
            text=f"تشديد الفحص طوال اليوم: {'مفعّل' if cfg.strict_mode else 'متوقف'}",
            bg="#10B981" if cfg.strict_mode else "#E2E8F0",
            fg="#FFFFFF" if cfg.strict_mode else "#0F172A",
        )
        if self._kw_listbox and self._kw_listbox.winfo_exists():
            self._kw_listbox.delete(0, tk.END)
            for kw in cfg.custom_keywords:
                self._kw_listbox.insert(tk.END, kw)

    def _add_keyword(self) -> None:
        val = self.entry_kw.get().strip().lower()
        if not val:
            return
        if val not in self.app.config.custom_keywords:
            self.app.config.custom_keywords.append(val)
            self.app.config.save()
        self.entry_kw.delete(0, tk.END)
        self._refresh_advanced_controls()

    def _delete_keyword(self) -> None:
        if not self._kw_listbox:
            return
        sel = self._kw_listbox.curselection()
        if not sel:
            return
        if not self.app.verify_pin():
            return
        kw = self._kw_listbox.get(sel[0])
        if kw in self.app.config.custom_keywords:
            self.app.config.custom_keywords.remove(kw)
            self.app.config.save()
        self._refresh_advanced_controls()

    def show(self) -> None:
        self.refresh()
        self.win.deiconify()
        self.win.lift()
        self.win.focus_force()

    def hide(self) -> None:
        self.win.withdraw()


# ==============================================================================
# 12. المنسق الرئيسي للتطبيق
# ==============================================================================
class SafeGuardApp:
    COOLDOWN_SECONDS = 30 * 60  # 30 دقيقة

    def __init__(self):
        self.config = ShieldConfig()
        self.config.load()
        self.hosts_lock = HostsLockManager()
        if self.config.web_block_enabled:
            self.hosts_lock.acquire_lock()

        self.engine_status_text = "جاري تجهيز الحماية..."
        self.panic_active = False
        self.overlay_queue: queue.Queue = queue.Queue(maxsize=2)
        self.ui_queue: queue.Queue = queue.Queue()
        self.exit_event = WatchdogSystem.create_exit_event()
        self._watchdog_proc: Optional[subprocess.Popen] = None

        # نافذة جذر مخفية لاستضافة لوحة التحكم وطبقة التمويه معاً بأمان
        self.root = tk.Tk()
        self.root.withdraw()

        self.overlay = ProtectionOverlay(self.root)
        self.dashboard = SimpleDashboard(self.root, self)

        self.tray = NativeTrayController(
            get_status_label=self._tray_status_line,
            is_enabled=lambda: self.config.enabled,
            on_open_dashboard=lambda: self.ui_queue.put(self.dashboard.show),
            on_toggle_protection=lambda: self.ui_queue.put(self.request_toggle_protection),
            on_exit=lambda: self.ui_queue.put(self.request_exit),
            on_panic_hotkey=lambda: self.ui_queue.put(self.toggle_panic_mode),
        )

        self.worker = ScreenMonitorWorker(
            config=self.config,
            overlay_queue=self.overlay_queue,
            status_cb=self._on_status_change,
            notify_cb=self._notify_user,
            on_block_event=self._on_block_event,
            on_tamper_detected=self._on_tamper_detected,
        )

        self.root.after(45, self._poll_loop)
        self.root.after(1000, self._tick_1s)

    def _tray_status_line(self) -> str:
        days, _ = self.config.clean_duration_parts()
        state = "محمي" if self.config.enabled else "متوقف"
        return f"الحالة: {state} | ملتزم منذ: {days} يوم"

    def _on_status_change(self, text: str) -> None:
        self.engine_status_text = text
        self.ui_queue.put(self._refresh_all)

    def _notify_user(self, title: str, msg: str) -> None:
        self.tray.notify(title, msg, warning=True)

    def _on_block_event(self) -> None:
        self.config.blocked_count += 1
        self.config.save()
        self.ui_queue.put(self._refresh_all)

    def _on_tamper_detected(self, _hwnd: int, _title: str) -> None:
        self.tray.notify("حماية الإعدادات مفعّلة", "تم تصغير نافذة إعدادات النظام لأن الرقم السري مفعّل.", warning=True)
        self.ui_queue.put(self._prompt_tamper_unlock)

    def _prompt_tamper_unlock(self) -> None:
        ans = messagebox.askyesno(
            "حماية الإعدادات",
            "تم منع تعديل إعدادات النظام لحمايتك.\nهل تريد إدخال الرقم السري لفتح الإعدادات مؤقتاً لمدة دقيقتين؟",
            parent=self.dashboard.win if self.dashboard.win.winfo_viewable() else self.root,
        )
        if ans and self.verify_pin():
            self.worker.grant_tamper_grace(120.0)
            messagebox.showinfo("تم السماح مؤقتاً", "يمكنك فتح الإعدادات خلال الدقيقتين القادمتين.", parent=self.root)

    def _refresh_all(self) -> None:
        self.dashboard.refresh()
        self.tray.update_icon(self._tray_status_line())

    def verify_pin(self) -> bool:
        if not self.config.pin_hash:
            return True
        parent = self.dashboard.win if self.dashboard.win.winfo_viewable() else self.root
        entered = simpledialog.askstring("الرقم السري", "أدخل الرقم السري للمتابعة:", show="*", parent=parent)
        if entered is None:
            return False
        if hashlib.sha256(entered.encode("utf-8")).hexdigest() != self.config.pin_hash:
            messagebox.showwarning("رقم غير صحيح", "الرقم السري غير صحيح. ستبقى الحماية مفعّلة.", parent=parent)
            return False
        return True

    def _schedule_or_execute(self, action_key: str, immediate_fn: Callable[[], None]) -> None:
        """تنفيذ فوري، أو تفعيل مهلة 30 دقيقة إذا كان القفل الزمني مفعلاً."""
        if not self.verify_pin():
            return
        if not self.config.cooldown_lock_enabled:
            immediate_fn()
            return

        self.config.pending_action = action_key
        self.config.pending_execute_at = time.time() + self.COOLDOWN_SECONDS
        self.config.save()
        self._refresh_all()
        self.tray.notify(
            "مهلة الحماية (30 دقيقة)",
            "سيتم تنفيذ طلب الإيقاف بعد 30 دقيقة. يمكنك إلغاء الطلب في أي وقت من لوحة التحكم.",
        )

    def cancel_pending_cooldown(self) -> None:
        self.config.pending_action = ""
        self.config.pending_execute_at = 0.0
        self.config.save()
        self._refresh_all()
        self.tray.notify("تم إلغاء الطلب", "ممتاز! تم إلغاء طلب الإيقاف وستستمر الحماية.")

    def _execute_pending_action(self, action_key: str) -> None:
        self.config.pending_action = ""
        self.config.pending_execute_at = 0.0
        self.config.save()

        if action_key == "pause_protection":
            self._do_pause_protection()
        elif action_key == "disable_web_block":
            self._do_disable_web_block()
        elif action_key == "disable_cooldown":
            self.config.cooldown_lock_enabled = False
            self.config.save()
        elif action_key == "remove_pin":
            self.config.pin_hash = None
            self.config.save()
        elif action_key == "exit_app":
            self._do_authorized_exit()
        self._refresh_all()

    # -------------------- أوامر لوحة التحكم --------------------
    def activate_full_protection_one_click(self) -> None:
        """زر الحماية الكاملة بضغطة واحدة."""
        self.config.enabled = True
        self.config.auto_close_enabled = True
        self.config.night_mode_enabled = True
        self.config.pending_action = ""
        self.config.pending_execute_at = 0.0
        self.config.save()
        self.worker.force_rescan()
        self._refresh_all()

        def bg_setup():
            ok_web, msg_web = SystemGuardian.enable_web_protection(self.hosts_lock)
            if ok_web:
                self.config.web_block_enabled = True
                self.config.save()
            SystemGuardian.install_autostart()
            self.ui_queue.put(self._refresh_all)
            self.tray.notify("تم تفعيل الحماية الشاملة", msg_web)

        threading.Thread(target=bg_setup, daemon=True).start()

    def request_toggle_protection(self) -> None:
        if not self.config.enabled:
            self.config.enabled = True
            self.worker.force_rescan()
            self._refresh_all()
        else:
            self._schedule_or_execute("pause_protection", self._do_pause_protection)

    def _do_pause_protection(self) -> None:
        self.config.enabled = False
        self.overlay.render([], False, "")
        self._refresh_all()

    def toggle_web_block(self) -> None:
        if not self.config.web_block_enabled:
            self.tray.notify("جاري التفعيل", "جاري تفعيل حجب المواقع الضارة والبحث الآمن...")

            def job():
                ok, msg = SystemGuardian.enable_web_protection(self.hosts_lock)
                if ok:
                    self.config.web_block_enabled = True
                    self.config.save()
                self.ui_queue.put(self._refresh_all)
                self.tray.notify("حجب المواقع الضارة", msg)

            threading.Thread(target=job, daemon=True).start()
        else:
            self._schedule_or_execute("disable_web_block", self._do_disable_web_block)

    def _do_disable_web_block(self) -> None:
        def job():
            ok, msg = SystemGuardian.disable_web_protection(self.hosts_lock)
            if ok:
                self.config.web_block_enabled = False
                self.config.save()
            self.ui_queue.put(self._refresh_all)
            self.tray.notify("حجب المواقع الضارة", msg)

        threading.Thread(target=job, daemon=True).start()

    def toggle_auto_close(self) -> None:
        if self.config.auto_close_enabled and not self.verify_pin():
            return
        self.config.auto_close_enabled = not self.config.auto_close_enabled
        self.config.save()
        self._refresh_all()

    def toggle_night_mode(self) -> None:
        if self.config.night_mode_enabled and not self.verify_pin():
            return
        self.config.night_mode_enabled = not self.config.night_mode_enabled
        self.config.save()
        self.worker.force_rescan()
        self._refresh_all()

    def toggle_cooldown_lock(self) -> None:
        if not self.config.cooldown_lock_enabled:
            self.config.cooldown_lock_enabled = True
            self.config.save()
            self._refresh_all()
        else:
            self._schedule_or_execute(
                "disable_cooldown",
                lambda: (setattr(self.config, "cooldown_lock_enabled", False), self.config.save(), self._refresh_all()),
            )

    def toggle_full_blur(self) -> None:
        if self.config.full_screen_blur and not self.verify_pin():
            return
        self.config.full_screen_blur = not self.config.full_screen_blur
        self.config.save()
        self.worker.force_rescan()
        self._refresh_all()

    def toggle_strict_mode(self) -> None:
        if self.config.strict_mode and not self.verify_pin():
            return
        self.config.strict_mode = not self.config.strict_mode
        self.config.save()
        self.worker.force_rescan()
        self._refresh_all()

    def configure_pin(self) -> None:
        if not self.verify_pin():
            return
        parent = self.dashboard.win
        new_pin = simpledialog.askstring(
            "الرقم السري",
            "أدخل رقماً سرياً جديداً (أو اتركه فارغاً لإزالة القفل):",
            show="*",
            parent=parent,
        )
        if new_pin is None:
            return
        clean = new_pin.strip()
        if not clean:
            if self.config.pin_hash:
                self._schedule_or_execute(
                    "remove_pin",
                    lambda: (setattr(self.config, "pin_hash", None), self.config.save(), self._refresh_all()),
                )
        else:
            self.config.pin_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()
            self.config.save()
            self._refresh_all()
            messagebox.showinfo("تم الحفظ", "تم قفل البرنامج بالرقم السري بنجاح.", parent=parent)

    def install_autostart(self) -> None:
        def job():
            _, msg = SystemGuardian.install_autostart()
            self.tray.notify("التشغيل التلقائي", msg)

        threading.Thread(target=job, daemon=True).start()

    def toggle_panic_mode(self) -> None:
        self.panic_active = not self.panic_active
        if self.panic_active:
            WindowsHelper.mute_system_audio()
        self.worker.set_panic_mode(self.panic_active)

    def request_exit(self) -> None:
        self._schedule_or_execute("exit_app", self._do_authorized_exit)

    def _do_authorized_exit(self) -> None:
        WatchdogSystem.signal_authorized_exit(self.exit_event)
        self.hosts_lock.release_lock()
        self.worker.stop()
        self.tray.stop()
        self.root.quit()

    # -------------------- حلقات التحديث والحارس --------------------
    def _poll_loop(self) -> None:
        while not self.ui_queue.empty():
            try:
                fn = self.ui_queue.get_nowait()
                fn()
            except queue.Empty:
                break
            except Exception:
                pass

        try:
            patches, active, banner = self.overlay_queue.get_nowait()
            self.overlay.render(patches, active, banner)
        except queue.Empty:
            pass

        self.root.after(45, self._poll_loop)

    def _tick_1s(self) -> None:
        cfg = self.config
        if cfg.pending_action and cfg.pending_execute_at > 0:
            if time.time() >= cfg.pending_execute_at:
                self._execute_pending_action(cfg.pending_action)
            else:
                self.dashboard.refresh()
        elif self.dashboard.win.winfo_viewable():
            self.dashboard.refresh()
        self.root.after(1000, self._tick_1s)

    def _watchdog_keeper_loop(self) -> None:
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
        self.tray.start()
        self.tray._ready.wait(timeout=3.0)
        self.worker.start()
        threading.Thread(target=self._watchdog_keeper_loop, daemon=True).start()
        self.dashboard.show()
        self.root.mainloop()


def main() -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

    if len(sys.argv) >= 3 and sys.argv[1] == "--watchdog":
        WatchdogSystem.run_watchdog_loop(int(sys.argv[2]))
        return

    mutex = kernel32.CreateMutexW(None, False, MAIN_MUTEX_NAME)
    if kernel32.GetLastError() == 183:
        return

    app = SafeGuardApp()
    app.run()


if __name__ == "__main__":
    main()
