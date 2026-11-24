import ctypes
import hashlib
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import cv2
import mss
import numpy as np
from nudenet import NudeDetector
from PyQt6.QtCore import QRect, Qt, QThread, pyqtSignal
from PyQt6.QtGui import (
    QAction,
    QActionGroup,
    QBrush,
    QColor,
    QFont,
    QGuiApplication,
    QIcon,
    QImage,
    QPainter,
    QPen,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QApplication,
    QInputDialog,
    QLineEdit,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
    QWidget,
)

# خاصية ويندوز 10 (2004+) وويندوز 11 لإخفاء نافذة التمويه عن التقاط الشاشة
WDA_EXCLUDEFROMCAPTURE = 0x00000011


# ==============================================================================
# 1. إعدادات النظام ومعايير الذكاء الاصطناعي
# ==============================================================================
@dataclass
class ShieldConfig:
    enabled: bool = True
    full_screen_blur: bool = False        # False = تمويه المنطقة المخالفة فقط | True = الشاشة كاملة
    strict_mode: bool = False             # تشديد الفحص ليشمل المحتوى شبه المكشوف
    scan_fps: float = 3.0                 # عدد الفحوصات في الثانية
    box_padding: int = 40                 # هامش أمان بالبكسل حول المنطقة المخالفة
    hold_seconds: float = 1.2             # بقاء التمويه لحظة إضافية لمنع التقطع أثناء التمرير
    frame_diff_threshold: float = 1.6     # أقل نسبة تغير في الشاشة لإعادة تشغيل الذكاء الاصطناعي
    max_infer_width: int = 960            # تقليص حجم الإطار للفحص فقط لتسريع المعالجة
    pin_hash: Optional[str] = None        # رمز PIN مشفر بـ SHA-256 لمنع الإيقاف العشوائي

    # الفئات الصريحة مع حد الثقة لكل فئة (لتقليل الإنذارات الكاذبة على الوجوه والأيدي)
    base_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "FEMALE_GENITALIA_EXPOSED": 0.40,
            "MALE_GENITALIA_EXPOSED": 0.40,
            "FEMALE_BREAST_EXPOSED": 0.45,
            "BUTTOCKS_EXPOSED": 0.50,
            "ANUS_EXPOSED": 0.40,
        }
    )

    # فئات إضافية عند تفعيل الوضع الصارم
    strict_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "FEMALE_BREAST_COVERED": 0.62,
            "FEMALE_GENITALIA_COVERED": 0.62,
            "BUTTOCKS_COVERED": 0.62,
            "BELLY_EXPOSED": 0.72,
        }
    )

    def active_thresholds(self) -> Dict[str, float]:
        merged = dict(self.base_thresholds)
        if self.strict_mode:
            merged.update(self.strict_thresholds)
        return merged


# ==============================================================================
# 2. محرك المعالجة الصورية والتمويه الثقيل (في الذاكرة فقط)
# ==============================================================================
class BlurProcessor:
    @staticmethod
    def create_heavy_blur_qimage(bgr_region: np.ndarray) -> QImage:
        """تطبيق تمويه ضبابي + بكسلة ثقيلة غير قابلة للاسترجاع بسرعة عالية جداً."""
        h, w = bgr_region.shape[:2]
        if h < 2 or w < 2:
            return QImage()

        # تصغير قوي ثم تكبير مع Gaussian Blur = أسرع بـ 10 مرات وأشد إخفاءً
        small_w = max(6, w // 18)
        small_h = max(6, h // 18)
        downscaled = cv2.resize(bgr_region, (small_w, small_h), interpolation=cv2.INTER_AREA)
        blurred_small = cv2.GaussianBlur(downscaled, (5, 5), 0)
        upscaled = cv2.resize(blurred_small, (w, h), interpolation=cv2.INTER_LINEAR)

        rgb = cv2.cvtColor(upscaled, cv2.COLOR_BGR2RGB)
        rgb = np.ascontiguousarray(rgb)
        bytes_per_line = 3 * w
        return QImage(rgb.data, w, h, bytes_per_line, QImage.Format.Format_RGB888).copy()

    @staticmethod
    def merge_overlapping_boxes(
        boxes: List[Tuple[int, int, int, int]], gap: int = 20
    ) -> List[Tuple[int, int, int, int]]:
        """دمج المربعات المتداخلة أو المتقاربة للحصول على تمويه أنظف وأكثر سلاسة."""
        if not boxes:
            return []

        rects = [list(b) for b in boxes]  # [x1, y1, x2, y2]
        merged = True
        while merged:
            merged = False
            result = []
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
                result.append(curr)
            rects = result
        return [(r[0], r[1], r[2], r[3]) for r in rects]


# ==============================================================================
# 3. خيط المراقبة والذكاء الاصطناعي في الخلفية
# ==============================================================================
class ScreenMonitorWorker(QThread):
    # يرسل قائمة (QRect, QImage) + هل المحتوى المخالف نشط حالياً
    overlay_updated = pyqtSignal(list, bool)
    nsfw_detected_alert = pyqtSignal(int)
    engine_status = pyqtSignal(str)

    def __init__(self, config: ShieldConfig, virtual_geom: QRect):
        super().__init__()
        self.config = config
        self.virtual_geom = virtual_geom
        self._running = True
        self._detector: Optional[NudeDetector] = None
        self._prev_thumb: Optional[np.ndarray] = None
        self._last_nsfw_time: float = 0.0
        self._was_active: bool = False
        self._last_patches: List[Tuple[QRect, QImage]] = []

    def update_geometry(self, geom: QRect) -> None:
        self.virtual_geom = geom

    def force_rescan(self) -> None:
        self._prev_thumb = None

    def stop(self) -> None:
        self._running = False
        self.wait(3000)

    def _run_inference(self, infer_bgr: np.ndarray) -> List[dict]:
        """استدعاء NudeNet في الذاكرة مباشرة بدون كتابة أي ملف على القرص."""
        try:
            return self._detector.detect(infer_bgr)
        except TypeError:
            # توافق مع بعض إصدارات NudeNet الأقدم التي تتوقع bytes
            ok, encoded = cv2.imencode(".jpg", infer_bgr, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
            if not ok:
                return []
            return self._detector.detect(encoded.tobytes())

    def _screen_changed(self, frame_bgr: np.ndarray) -> bool:
        thumb = cv2.resize(frame_bgr, (160, 90), interpolation=cv2.INTER_AREA)
        gray = cv2.cvtColor(thumb, cv2.COLOR_BGR2GRAY)
        if self._prev_thumb is None:
            self._prev_thumb = gray
            return True
        diff = float(np.mean(cv2.absdiff(self._prev_thumb, gray)))
        if diff >= self.config.frame_diff_threshold:
            self._prev_thumb = gray
            return True
        return False

    def run(self) -> None:
        try:
            self.engine_status.emit("جاري تحميل نموذج الذكاء الاصطناعي...")
            self._detector = NudeDetector()
            self.engine_status.emit("الحماية نشطة وتعمل في الخلفية")
        except Exception as exc:
            self.engine_status.emit(f"فشل تحميل النموذج: {exc}")
            return

        with mss.mss() as sct:
            while self._running:
                loop_start = time.perf_counter()

                if not self.config.enabled:
                    if self._was_active:
                        self._was_active = False
                        self._last_patches = []
                        self.overlay_updated.emit([], False)
                    time.sleep(0.3)
                    continue

                try:
                    # monitors[0] يغطي جميع الشاشات المتصلة بويندوز
                    monitor = sct.monitors[0]
                    raw = np.array(sct.grab(monitor))
                    frame_bgr = np.ascontiguousarray(raw[:, :, :3])
                    orig_h, orig_w = frame_bgr.shape[:2]

                    now = time.perf_counter()
                    changed = self._screen_changed(frame_bgr)

                    # إذا لم تتغير الشاشة: نُبقي الحالة الحالية ونوفر طاقة المعالج
                    if not changed:
                        if self._was_active and (now - self._last_nsfw_time) <= self.config.hold_seconds:
                            pass
                        self._sleep_remaining(loop_start)
                        continue

                    # تصغير مؤقت للفحص السريع مع الحفاظ على نسب الأبعاد
                    if orig_w > self.config.max_infer_width:
                        infer_scale = self.config.max_infer_width / orig_w
                        infer_w = self.config.max_infer_width
                        infer_h = max(1, int(orig_h * infer_scale))
                        infer_frame = cv2.resize(frame_bgr, (infer_w, infer_h), interpolation=cv2.INTER_AREA)
                    else:
                        infer_scale = 1.0
                        infer_frame = frame_bgr

                    detections = self._run_inference(infer_frame)
                    thresholds = self.config.active_thresholds()

                    raw_boxes: List[Tuple[int, int, int, int]] = []
                    pad = self.config.box_padding

                    for det in detections:
                        label = det.get("class", "")
                        score = float(det.get("score", 0.0))
                        if label in thresholds and score >= thresholds[label]:
                            bx, by, bw, bh = det["box"]
                            # إعادة الإحداثيات إلى دقة الشاشة الحقيقية
                            x1 = max(0, int(bx / infer_scale) - pad)
                            y1 = max(0, int(by / infer_scale) - pad)
                            x2 = min(orig_w, int((bx + bw) / infer_scale) + pad)
                            y2 = min(orig_h, int((by + bh) / infer_scale) + pad)
                            if x2 > x1 and y2 > y1:
                                raw_boxes.append((x1, y1, x2, y2))

                    if raw_boxes:
                        self._last_nsfw_time = now
                        merged_boxes = BlurProcessor.merge_overlapping_boxes(raw_boxes)

                        # تحويل إحداثيات البكسل الفيزيائي إلى إحداثيات Qt المنطقية (يدعم DPI Scaling)
                        scale_x = self.virtual_geom.width() / orig_w
                        scale_y = self.virtual_geom.height() / orig_h

                        patches: List[Tuple[QRect, QImage]] = []
                        if self.config.full_screen_blur:
                            full_blur = BlurProcessor.create_heavy_blur_qimage(infer_frame)
                            full_rect = QRect(0, 0, self.virtual_geom.width(), self.virtual_geom.height())
                            patches.append((full_rect, full_blur))
                        else:
                            for x1, y1, x2, y2 in merged_boxes:
                                crop = frame_bgr[y1:y2, x1:x2]
                                qimg = BlurProcessor.create_heavy_blur_qimage(crop)
                                qrect = QRect(
                                    int(x1 * scale_x),
                                    int(y1 * scale_y),
                                    max(1, int((x2 - x1) * scale_x)),
                                    max(1, int((y2 - y1) * scale_y)),
                                )
                                patches.append((qrect, qimg))

                        self._last_patches = patches
                        self.overlay_updated.emit(patches, True)
                        if not self._was_active:
                            self.nsfw_detected_alert.emit(len(merged_boxes))
                        self._was_active = True
                    else:
                        # الحفاظ على التمويه لفترة قصيرة جداً لمنع الوميض أثناء التمرير
                        if self._was_active and (now - self._last_nsfw_time) > self.config.hold_seconds:
                            self._was_active = False
                            self._last_patches = []
                            self.overlay_updated.emit([], False)

                except Exception as exc:
                    self.engine_status.emit(f"تنبيه أثناء الفحص: {exc}")

                self._sleep_remaining(loop_start)

    def _sleep_remaining(self, start_time: float) -> None:
        target = 1.0 / max(0.5, self.config.scan_fps)
        elapsed = time.perf_counter() - start_time
        if elapsed < target:
            time.sleep(target - elapsed)


# ==============================================================================
# 4. طبقة التمويه والتنبيه الشفافة فوق ويندوز
# ==============================================================================
class ProtectionOverlay(QWidget):
    def __init__(self):
        super().__init__()
        self._patches: List[Tuple[QRect, QImage]] = []
        self._is_active: bool = False
        self._affinity_applied: bool = False

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
            | Qt.WindowType.WindowTransparentForInput  # يسمح للنقر بالمرور لإغلاق الصفحة فوراً
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.sync_geometry()

    def sync_geometry(self) -> QRect:
        primary = QGuiApplication.primaryScreen()
        geom = primary.virtualGeometry()
        self.setGeometry(geom)
        return geom

    def _apply_capture_exclusion(self) -> None:
        """إخفاء هذه النافذة عن محرك الالتقاط لمنع التداخل والوميض نهائياً."""
        if sys.platform == "win32" and not self._affinity_applied:
            try:
                hwnd = int(self.winId())
                res = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
                if res != 0:
                    self._affinity_applied = True
            except Exception:
                pass

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._apply_capture_exclusion()

    def update_overlay(self, patches: List[Tuple[QRect, QImage]], active: bool) -> None:
        self._patches = patches
        self._is_active = active
        if active and patches:
            if not self.isVisible():
                self.show()
                self._apply_capture_exclusion()
            self.raise_()
            self.update()
        else:
            if self.isVisible():
                self.hide()

    def paintEvent(self, event) -> None:
        if not self._is_active or not self._patches:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)

        # 1. رسم مربعات التمويه فوق المناطق المخالفة
        for rect, qimg in self._patches:
            if not qimg.isNull():
                painter.drawImage(rect, qimg)

            # طبقة تظليل خفيفة وإطار واضح فوق المنطقة المموّهة
            painter.fillRect(rect, QColor(15, 23, 42, 110))
            pen = QPen(QColor(239, 68, 68, 220), 2)
            painter.setPen(pen)
            painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 10, 10)

            # كتابة تنبيه مختصر داخل كل مربع مموّه إذا كان حجمه مناسباً
            if rect.width() >= 180 and rect.height() >= 60:
                box_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
                painter.setFont(box_font)
                painter.setPen(QColor(255, 255, 255, 240))
                painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "تم حجب محتوى غير لائق")

        # 2. رسم شريط التنبيه الرئيسي أعلى الشاشة الأساسية
        primary_geom = QGuiApplication.primaryScreen().geometry()
        offset_x = primary_geom.x() - self.geometry().x()
        offset_y = primary_geom.y() - self.geometry().y()

        banner_w = 500
        banner_h = 62
        banner_x = offset_x + (primary_geom.width() - banner_w) // 2
        banner_y = offset_y + 28
        banner_rect = QRect(banner_x, banner_y, banner_w, banner_h)

        painter.setBrush(QBrush(QColor(185, 28, 28, 238)))
        painter.setPen(QPen(QColor(254, 202, 202, 220), 2))
        painter.drawRoundedRect(banner_rect, 16, 16)

        title_font = QFont("Segoe UI", 15, QFont.Weight.Bold)
        painter.setFont(title_font)
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(
            banner_rect,
            Qt.AlignmentFlag.AlignCenter,
            "⚠ تم إيجاد مواد إباحية — تم التمويه تلقائياً",
        )

        painter.end()


# ==============================================================================
# 5. الواجهة الرئيسية في شريط المهام (System Tray) وإدارة الأمان
# ==============================================================================
class SafeGuardApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)
        self.app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.config = ShieldConfig()
        self.overlay = ProtectionOverlay()
        self._last_toast_time: float = 0.0

        self.worker = ScreenMonitorWorker(self.config, self.overlay.geometry())
        self.worker.overlay_updated.connect(self.overlay.update_overlay)
        self.worker.nsfw_detected_alert.connect(self._show_toast_alert)
        self.worker.engine_status.connect(self._update_status_text)

        self._setup_tray()
        self.worker.start()

    @staticmethod
    def _create_shield_icon(active: bool = True) -> QIcon:
        """رسم أيقونة درع برمجياً بدون الحاجة لملفات صور خارجية."""
        pix = QPixmap(64, 64)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QColor(16, 185, 129) if active else QColor(100, 116, 139)
        p.setBrush(QBrush(bg))
        p.setPen(QPen(QColor(255, 255, 255), 3))
        p.drawRoundedRect(6, 6, 52, 52, 16, 16)
        p.setPen(QColor(255, 255, 255))
        p.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, "✓" if active else "⏸")
        p.end()
        return QIcon(pix)

    def _setup_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._create_shield_icon(True), self.app)
        self.tray.setToolTip("درع العفة — الحماية الذكية من المحتوى الإباحي")

        menu = QMenu()

        self.status_action = QAction("جاري التهيئة...", menu)
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)
        menu.addSeparator()

        self.toggle_action = QAction("إيقاف الحماية مؤقتاً", menu)
        self.toggle_action.triggered.connect(self._toggle_protection)
        menu.addAction(self.toggle_action)

        # اختيار نمط التمويه
        mode_menu = QMenu("نمط التمويه", menu)
        mode_group = QActionGroup(mode_menu)
        mode_group.setExclusive(True)

        self.region_mode_action = QAction("تمويه المنطقة المخالفة فقط (ذكي)", mode_menu, checkable=True)
        self.region_mode_action.setChecked(True)
        self.region_mode_action.triggered.connect(lambda: self._set_blur_mode(False))

        self.full_mode_action = QAction("تمويه الشاشة بالكامل (حجب شامل)", mode_menu, checkable=True)
        self.full_mode_action.triggered.connect(lambda: self._set_blur_mode(True))

        mode_group.addAction(self.region_mode_action)
        mode_group.addAction(self.full_mode_action)
        mode_menu.addAction(self.region_mode_action)
        mode_menu.addAction(self.full_mode_action)
        menu.addMenu(mode_menu)

        # الوضع الصارم
        self.strict_action = QAction("تفعيل الوضع الصارم (حساسية أعلى)", menu, checkable=True)
        self.strict_action.triggered.connect(self._toggle_strict_mode)
        menu.addAction(self.strict_action)

        menu.addSeparator()

        self.pin_action = QAction("تعيين رمز قفل PIN للحماية", menu)
        self.pin_action.triggered.connect(self._configure_pin)
        menu.addAction(self.pin_action)

        exit_action = QAction("إغلاق التطبيق", menu)
        exit_action.triggered.connect(self._exit_app)
        menu.addAction(exit_action)

        self.tray.setContextMenu(menu)
        self.tray.show()

    def _verify_pin(self) -> bool:
        if not self.config.pin_hash:
            return True
        text, ok = QInputDialog.getText(
            None,
            "التحقق من الهوية",
            "أدخل رمز القفل (PIN) للمتابعة:",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return False
        entered_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if entered_hash != self.config.pin_hash:
            QMessageBox.warning(None, "رمز خاطئ", "رمز القفل غير صحيح. تبقى الحماية مفعّلة.")
            return False
        return True

    def _configure_pin(self) -> None:
        if not self._verify_pin():
            return
        text, ok = QInputDialog.getText(
            None,
            "تعيين رمز القفل",
            "أدخل رمز PIN جديد (اتركه فارغاً لإلغاء القفل):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if text.strip():
            self.config.pin_hash = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
            self.pin_action.setText("تغيير / إزالة رمز القفل PIN")
            self.tray.showMessage("درع العفة", "تم تفعيل رمز القفل بنجاح.", QSystemTrayIcon.MessageIcon.Information, 3000)
        else:
            self.config.pin_hash = None
            self.pin_action.setText("تعيين رمز قفل PIN للحماية")

    def _toggle_protection(self) -> None:
        if self.config.enabled and not self._verify_pin():
            return
        self.config.enabled = not self.config.enabled
        self.tray.setIcon(self._create_shield_icon(self.config.enabled))
        if self.config.enabled:
            self.toggle_action.setText("إيقاف الحماية مؤقتاً")
            self.status_action.setText("الحماية نشطة وتعمل في الخلفية")
            self.worker.force_rescan()
        else:
            self.toggle_action.setText("تفعيل الحماية")
            self.status_action.setText("الحماية متوقفة مؤقتاً")
            self.overlay.update_overlay([], False)

    def _set_blur_mode(self, full_screen: bool) -> None:
        self.config.full_screen_blur = full_screen
        self.worker.force_rescan()

    def _toggle_strict_mode(self, checked: bool) -> None:
        if not checked and not self._verify_pin():
            self.strict_action.setChecked(True)
            return
        self.config.strict_mode = checked
        self.worker.force_rescan()

    def _update_status_text(self, text: str) -> None:
        self.status_action.setText(text)

    def _show_toast_alert(self, count: int) -> None:
        now = time.perf_counter()
        # منع تكرار إشعارات ويندوز المزعجة أكثر من مرة كل 8 ثوانٍ
        if now - self._last_toast_time >= 8.0:
            self._last_toast_time = now
            self.tray.showMessage(
                "تم إيجاد مواد إباحية",
                f"تم اكتشاف وحجب ({count}) منطقة غير لائقة على الشاشة تلقائياً.",
                QSystemTrayIcon.MessageIcon.Warning,
                3500,
            )

    def _exit_app(self) -> None:
        if not self._verify_pin():
            return
        self.worker.stop()
        self.overlay.close()
        self.tray.hide()
        self.app.quit()

    def run(self) -> int:
        return self.app.exec()


if __name__ == "__main__":
    # تفعيل الوعي بدقة الشاشة العالية على ويندوز
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

    shield = SafeGuardApp()
    sys.exit(shield.run())
