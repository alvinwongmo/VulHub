from __future__ import annotations

import csv
import html
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from PySide6.QtCore import QDate, QEvent, QItemSelectionModel, QPoint, QRect, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QCalendarWidget,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QProxyStyle,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

import app as core


APP_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
APP_ICON_PATH = APP_DIR / "assets" / "vulhub.ico"
_APP_ICON_CACHE: QIcon | None = None


class NoButtonFocusRectStyle(QProxyStyle):
    """Keep keyboard focus semantics while hiding button focus rectangles."""

    def drawPrimitive(self, element, option, painter, widget=None) -> None:  # type: ignore[no-untyped-def]
        if (
            element == QStyle.PrimitiveElement.PE_FrameFocusRect
            and isinstance(widget, QAbstractButton)
        ):
            return
        super().drawPrimitive(element, option, painter, widget)

CSV_EXPORT_HEADERS_ZH = (
    "發佈日期",
    "CVE編號",
    "風險等級",
    "CVSS 3.1分數",
    "廠商名稱",
    "產品名稱",
    "漏洞名稱",
    "漏洞描述",
    "受影響版本",
    "官方公告",
)

CSV_EXPORT_HEADERS_EN = (
    "Published Date",
    "CVE ID",
    "Severity",
    "CVSS 3.1 Score",
    "Vendor Name",
    "Product Name",
    "Vulnerability Name",
    "Vulnerability Description",
    "Affected Versions",
    "Official Advisories",
)

# Backwards-compatible name used by existing integrations and tests.
CSV_EXPORT_HEADERS = CSV_EXPORT_HEADERS_ZH

CSV_SEVERITY_EN = {
    "嚴重": "Critical",
    "高": "High",
    "中": "Medium",
    "低": "Low",
}


def excel_safe_csv_cell(value: Any) -> Any:
    """Prevent untrusted NVD text from becoming a formula in Excel."""
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    value = value.replace("\x00", "")
    # Excel may ignore leading whitespace before formula control characters.
    # A leading apostrophe forces text interpretation and is hidden by Excel.
    if value.lstrip()[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def unique_natural_strings(values: list[Any] | tuple[Any, ...]) -> list[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if value is not None and str(value).strip()
        },
        key=core.natural_key,
    )


def vulnerability_csv_row(row: dict[str, Any], *, english: bool = False) -> list[Any]:
    visible_vendors = unique_natural_strings(row.get("_visible_vendors") or [])
    visible_products = unique_natural_strings(row.get("_visible_products") or [])
    if english:
        title = row.get("title_en") or row.get("cve_id", "")
        description = row.get("description_en") or ""
        severity = CSV_SEVERITY_EN.get(
            str(row.get("severity", "")), str(row.get("severity", ""))
        )
    else:
        title = row.get("title_zh") or row.get("cve_id", "")
        description = row.get("description_zh") or ""
        severity = row.get("severity", "")
    affected = unique_natural_strings(
        row.get("affected_versions") or row.get("products") or []
    )
    references = list(
        dict.fromkeys(
            str(url).strip()
            for url in (row.get("references") or [])
            if url is not None and str(url).strip()
        )
    )
    return [
        row.get("published", ""),
        row.get("cve_id", ""),
        severity,
        "" if row.get("score") is None else row.get("score"),
        "\n".join(visible_vendors),
        "\n".join(visible_products),
        title,
        description,
        "\n".join(affected),
        "\n".join(references),
    ]


def write_vulnerability_csv(
    target_path: Path,
    rows: list[dict[str, Any]],
    *,
    english: bool = False,
) -> None:
    """Write an Excel-friendly CSV and atomically publish the complete file."""
    target_path = target_path.resolve()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            dir=target_path.parent,
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            writer = csv.writer(output, dialect="excel", lineterminator="\r\n")
            writer.writerow(CSV_EXPORT_HEADERS_EN if english else CSV_EXPORT_HEADERS_ZH)
            for row in rows:
                writer.writerow(
                    [
                        excel_safe_csv_cell(value)
                        for value in vulnerability_csv_row(row, english=english)
                    ]
                )
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(target_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def make_export_triangle_icon() -> QIcon:
    """Create a crisp solid right triangle for the CSV menu action."""
    pixmap = QPixmap(10, 10)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#243548"))
    path = QPainterPath()
    path.moveTo(2.0, 1.5)
    path.lineTo(8.5, 5.0)
    path.lineTo(2.0, 8.5)
    path.closeSubpath()
    painter.drawPath(path)
    painter.end()
    return QIcon(pixmap)


def product_category(name: str) -> str:
    """Convert a full CPE-derived name into its product family for table summaries."""
    value = re.sub(r"\s+", " ", name).strip()
    # A product such as PAN-OS or SD-WAN contains a meaningful hyphen. Only
    # strip a trailing version range when the dash is separated by spaces.
    value = re.sub(r"\s+(?:\*|\S+)\s+[–-]\s+(?:\*|\S+)$", "", value)
    value = re.sub(r"\s+\*\s*[–-]\s*\*$", "", value)
    value = re.sub(
        r"\s+(?:(?:version\s+)?(?:[vr]\d[\w.+-]*|\d+(?:\.\d+)+(?:[a-z0-9._-]*)?|\d{1,4}|\d{2,4}h\d+|\d+[a-z]\d+)(?:\s+[–-]\s+\d[\w.+-]*)?|(?:sp|cu|update|patch|build|release|take|hotfix)\s*\d[\w.+-]*)$",
        "",
        value,
        flags=re.I,
    )
    return value.strip() or name


def product_summary(products: list[str]) -> str:
    full = sorted(set(products), key=core.natural_key)
    categories = sorted({product_category(name) for name in full}, key=core.natural_key)
    shown = "、".join(categories)
    return f"{shown} 等{len(full)}項" if len(full) > 1 else shown


def filter_name_matches(selected: str, candidate: str) -> bool:
    """Match the selected product itself or a trailing-version descendant."""
    selected_key = core.normalize(selected)
    candidate_key = core.normalize(candidate)
    if not selected_key or not candidate_key:
        return False
    return selected_key in {
        candidate_key,
        core.normalize(product_category(candidate)),
    }


def canonical_product_selection(
    options: list[str], selected: set[str]
) -> tuple[list[str], set[str]]:
    """Reconcile saved products without collapsing similarly named products."""
    canonical_by_key = {core.normalize(option): option for option in options}
    canonical_selected: set[str] = set()
    for saved_name in selected:
        saved_key = core.normalize(saved_name)
        exact = canonical_by_key.get(saved_key)
        if exact:
            canonical_selected.add(exact)
            continue
        family_matches = [
            option
            for option in options
            if core.watched_product_matches(option, saved_name)
        ]
        if family_matches:
            canonical_selected.add(sorted(family_matches, key=core.natural_key)[0])
            continue
        # Keep an already watched legacy/deprecated name visible and checked;
        # a catalogue refresh must never silently remove the user's choice.
        canonical_by_key[saved_key] = saved_name
        canonical_selected.add(saved_name)
    merged_options = sorted(canonical_by_key.values(), key=core.natural_key)
    return merged_options, canonical_selected


def title_search_matches(query: str, fields: list[str]) -> bool:
    """Search CVE/title fields without creating short cross-word matches."""
    plain_query = re.sub(r"\s+", " ", query).strip().casefold()
    if not plain_query:
        return True
    compact_query = core.normalize(query)
    for field in fields:
        plain_field = re.sub(r"\s+", " ", str(field)).strip().casefold()
        if plain_query in plain_field:
            return True
        # Compact matching supports inputs such as "redhat" and CVE numbers
        # without separators. Requiring four characters prevents a short term
        # such as "hel" from matching across "the library".
        if len(compact_query) >= 4 and compact_query in core.normalize(str(field)):
            return True
    return False


def product_tooltip(products: list[str]) -> str:
    names = sorted(set(products), key=core.natural_key)
    return "完整產品名稱\n\n" + "\n".join(names) if names else ""


def vendor_summary(watched_vendors: list[str], all_vendors: list[str] | None = None) -> str:
    watched = sorted(set(watched_vendors), key=core.natural_key)
    if not watched:
        return "-"
    return "、".join(watched)


def vendor_tooltip(vendors: list[str]) -> str:
    names = sorted(set(vendors), key=core.natural_key)
    return "完整廠商名稱\n\n" + "\n".join(names) if names else "沒有相符的關注廠商"


def watched_products_for_row(row: dict[str, Any], watched_products: set[str]) -> list[str]:
    """Return only affected product names belonging to a selected watch family."""
    candidates = row.get("affected_versions") or row.get("products") or []
    matched = {
        candidate
        for candidate in candidates
        if any(
            filter_name_matches(watched, candidate)
            or filter_name_matches(watched, product_category(candidate))
            for watched in watched_products
        )
    }
    return sorted(matched, key=core.natural_key)


def watched_product_families_for_row(
    row: dict[str, Any], watched_products: set[str]
) -> list[str]:
    """Use the user's selected product names as the authoritative table categories."""
    candidates = [*(row.get("products") or []), *(row.get("affected_versions") or [])]
    return sorted(
        {
            watched
            for watched in watched_products
            if any(
                filter_name_matches(watched, candidate)
                or filter_name_matches(watched, product_category(candidate))
                for candidate in candidates
            )
        },
        key=core.natural_key,
    )


def watched_product_summary(
    row: dict[str, Any], watched_products: set[str], visible_products: list[str]
) -> str:
    families = watched_product_families_for_row(row, watched_products)
    if not families:
        return "-"
    shown = "、".join(families)
    return f"{shown} 等{len(visible_products)}項" if len(visible_products) > 1 else shown


def watched_vendors_for_row(
    row: dict[str, Any], watched_vendor_products: dict[str, set[str]]
) -> list[str]:
    """Derive vendor display from selected vendor/product groups, not unrelated NVD vendors."""
    candidates = [*(row.get("products") or []), *(row.get("affected_versions") or [])]
    return sorted(
        {
            vendor
            for vendor, watched_products in watched_vendor_products.items()
            if any(
                filter_name_matches(watched, candidate)
                or filter_name_matches(watched, product_category(candidate))
                for watched in watched_products
                for candidate in candidates
            )
        },
        key=core.natural_key,
    )


def prepare_row_watch_display(
    row: dict[str, Any], watched_vendor_products: dict[str, set[str]]
) -> None:
    """Calculate all watchlist matches once and reuse them throughout the UI."""
    products = list(dict.fromkeys(row.get("products") or []))
    affected = list(dict.fromkeys(row.get("affected_versions") or products))
    # Match watch families against NVD product identities first. Affected
    # version strings may end in a build range (for example Server 2025 * –
    # 10.0.x); classifying that string directly can incorrectly strip both the
    # build and the product year.
    identity_candidates = products or affected
    candidate_keys = {
        name: (core.normalize(name), core.normalize(product_category(name)))
        for name in identity_candidates
    }
    watched_keys = {
        vendor: [(name, core.normalize(name)) for name in names]
        for vendor, names in watched_vendor_products.items()
    }

    def matches(watched_key: str, candidate: str) -> bool:
        candidate_key, category_key = candidate_keys[candidate]
        return bool(watched_key) and (
            watched_key == candidate_key or watched_key == category_key
        )

    visible_vendors: set[str] = set()
    visible_families: set[str] = set()
    matching_keys: list[str] = []
    for vendor, names in watched_keys.items():
        vendor_matched = False
        for watched_name, watched_key in names:
            if any(matches(watched_key, candidate) for candidate in identity_candidates):
                vendor_matched = True
                visible_families.add(watched_name)
                matching_keys.append(watched_key)
        if vendor_matched:
            visible_vendors.add(vendor)

    matched_identities = [
        candidate
        for candidate in identity_candidates
        if any(matches(watched_key, candidate) for watched_key in matching_keys)
    ]

    def belongs_to_matched_product(version_name: str) -> bool:
        version_text = re.sub(r"\s+", " ", version_name).strip().casefold()
        return any(
            version_text == product_text
            or version_text.startswith(product_text + " ")
            for product in matched_identities
            for product_text in [re.sub(r"\s+", " ", product).strip().casefold()]
        )

    visible_products = [
        candidate for candidate in affected if belongs_to_matched_product(candidate)
    ]
    row["_visible_vendors"] = sorted(visible_vendors, key=core.natural_key)
    row["_visible_product_families"] = sorted(visible_families, key=core.natural_key)
    row["_visible_products"] = sorted(set(visible_products), key=core.natural_key)
    row["_product_categories"] = [product_category(name) for name in products]
    row["_search_fields"] = [
        row["cve_id"],
        row.get("title_en", ""),
        row.get("title_zh", ""),
    ]


def _render_app_icon(size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(size / 64.0, size / 64.0)
    shield = QPainterPath()
    shield.moveTo(32, 3)
    shield.lineTo(57, 13)
    shield.lineTo(53, 47)
    shield.lineTo(32, 62)
    shield.lineTo(11, 47)
    shield.lineTo(7, 13)
    shield.closeSubpath()
    painter.setPen(QPen(QColor("#35d4cf"), 5))
    painter.setBrush(QColor("#0a1d2c"))
    painter.drawPath(shield)
    # Draw the V as geometry instead of a font glyph.  The icon generator runs
    # with Qt's offscreen platform where the Windows font database is not
    # guaranteed to be available; a font-based V can therefore be baked into
    # the executable as a missing-glyph square on clean machines.
    mark = QPainterPath()
    mark.moveTo(21, 21)
    mark.lineTo(32, 45)
    mark.lineTo(43, 21)
    mark_pen = QPen(QColor("#46e1dc"), 4.5)
    mark_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    mark_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(mark_pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(mark)
    painter.end()
    return pixmap


def make_app_icon() -> QIcon:
    global _APP_ICON_CACHE
    if _APP_ICON_CACHE is not None:
        return _APP_ICON_CACHE
    # Prefer the physical multi-resolution ICO that is also embedded in the
    # executable.  This gives Qt and the Windows taskbar the same native icon
    # source on every machine.  Keep the vector fallback for source checkouts
    # where the asset has accidentally been removed.
    if APP_ICON_PATH.exists():
        file_icon = QIcon(str(APP_ICON_PATH))
        if not file_icon.isNull():
            # QIcon loads file-backed engines lazily.  Decode the native sizes
            # now so the first taskbar button cannot race the initial disk read.
            for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
                file_icon.pixmap(QSize(size, size))
            _APP_ICON_CACHE = file_icon
            return _APP_ICON_CACHE
    icon = QIcon()
    # Windows requests different native icon sizes for the title bar, taskbar,
    # Alt+Tab, Explorer and different DPI settings.  Supplying only 64x64 can
    # leave the taskbar slot blank when Qt replaces the executable resource
    # icon with the live window icon.
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        icon.addPixmap(_render_app_icon(size))
    _APP_ICON_CACHE = icon
    return _APP_ICON_CACHE


class LogoWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(43, 47)

    def paintEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        outer = QPainterPath()
        outer.moveTo(21.5, 2)
        outer.lineTo(39, 9)
        outer.lineTo(36, 34)
        outer.lineTo(21.5, 45)
        outer.lineTo(7, 34)
        outer.lineTo(4, 9)
        outer.closeSubpath()
        painter.setPen(QPen(QColor("#42d8d3"), 3))
        painter.setBrush(QColor("#10283b"))
        painter.drawPath(outer)
        mark = QPainterPath()
        mark.moveTo(14, 15)
        mark.lineTo(21.5, 32)
        mark.lineTo(29, 15)
        mark_pen = QPen(QColor("#43e0da"), 2.5)
        mark_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        mark_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(mark_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(mark)


class SortItem(QTableWidgetItem):
    def __init__(self, text: str, sort_value: Any | None = None) -> None:
        super().__init__(text)
        self.sort_value = text if sort_value is None else sort_value

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, SortItem):
            if isinstance(self.sort_value, (int, float)) and isinstance(other.sort_value, (int, float)):
                return self.sort_value < other.sort_value
            return core.natural_key(str(self.sort_value)) < core.natural_key(str(other.sort_value))
        return super().__lt__(other)


class PreserveSelectionTextDelegate(QStyledItemDelegate):
    """Keep every cell's normal foreground colour when its row is selected."""

    def initStyleOption(self, option, index) -> None:  # type: ignore[no-untyped-def]
        super().initStyleOption(option, index)
        foreground = index.data(Qt.ItemDataRole.ForegroundRole)
        if foreground is not None:
            option.palette.setBrush(QPalette.ColorRole.HighlightedText, foreground)
        else:
            option.palette.setBrush(
                QPalette.ColorRole.HighlightedText,
                option.palette.brush(QPalette.ColorRole.Text),
            )


class ProductDelegate(PreserveSelectionTextDelegate):
    """Adds breathing room to the product summary column."""

    def sizeHint(self, option, index) -> QSize:  # type: ignore[no-untyped-def]
        result = super().sizeHint(option, index)
        result.setHeight(max(52, result.height()))
        return result


class SquareCheckBox(QCheckBox):
    """A checkbox painted as a true 16×16 square on every Windows theme."""

    def paintEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        indicator = QRect(2, max(0, (self.height() - 16) // 2), 16, 16)
        checked = self.isChecked()
        painter.setPen(QPen(QColor("#159b9c" if checked else "#7d8d9d"), 1))
        painter.setBrush(QColor("#159b9c" if checked else "#ffffff"))
        painter.drawRect(indicator.adjusted(0, 0, -1, -1))
        if checked:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.setPen(QPen(QColor("#ffffff"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(indicator.left() + 4, indicator.top() + 8, indicator.left() + 7, indicator.top() + 11)
            painter.drawLine(indicator.left() + 7, indicator.top() + 11, indicator.left() + 13, indicator.top() + 5)
        painter.setPen(self.palette().color(self.foregroundRole()))
        painter.setFont(self.font())
        painter.drawText(
            QRect(27, 0, max(0, self.width() - 27), self.height()),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            self.text(),
        )

    def sizeHint(self) -> QSize:
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 31, 30)


class CalendarDateDelegate(QStyledItemDelegate):
    """Render dates outside the allowed range with an unmistakable dark fill."""

    def __init__(self, calendar: QCalendarWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.calendar = calendar

    def _cell_date(self, index) -> QDate:  # type: ignore[no-untyped-def]
        if index.row() <= 0 or index.column() <= 0:
            return QDate()
        first = QDate(self.calendar.yearShown(), self.calendar.monthShown(), 1)
        first_day = int(self.calendar.firstDayOfWeek().value)
        offset = (int(first.dayOfWeek()) - first_day) % 7
        cell = (index.row() - 1) * 7 + (index.column() - 1)
        return first.addDays(cell - offset)

    def paint(self, painter, option, index) -> None:  # type: ignore[no-untyped-def]
        is_date_cell = index.row() > 0 and index.column() > 0
        cell_date = self._cell_date(index)
        if (
            is_date_cell
            and cell_date.isValid()
            and cell_date.month() != self.calendar.monthShown()
        ):
            painter.save()
            painter.fillRect(option.rect, QColor("#ffffff"))
            painter.setPen(QPen(QColor("#d7dee5"), 1))
            painter.drawRect(option.rect.adjusted(0, 0, -1, -1))
            painter.restore()
            return
        if is_date_cell and option.state & QStyle.StateFlag.State_Selected:
            painter.save()
            painter.fillRect(option.rect, QColor("#075f6b"))
            painter.setPen(QPen(QColor("#064b55"), 1))
            painter.drawRect(option.rect.adjusted(0, 0, -1, -1))
            selected_font = painter.font()
            selected_font.setBold(True)
            painter.setFont(selected_font)
            painter.setPen(QColor("#ffffff"))
            painter.drawText(option.rect, Qt.AlignmentFlag.AlignCenter, str(index.data() or ""))
            painter.restore()
            return
        # Row 0 contains weekday headings and column 0 contains week numbers;
        # only darken actual date cells outside the permitted range.
        if (
            is_date_cell
            and not option.state & QStyle.StateFlag.State_Enabled
        ):
            painter.save()
            painter.fillRect(option.rect, QColor("#ffffff"))
            painter.setPen(QPen(QColor("#d7dee5"), 1))
            painter.drawRect(option.rect.adjusted(0, 0, -1, -1))
            painter.restore()
            return
        super().paint(painter, option, index)


class PersistentCheckMenu(QMenu):
    """Keep a multi-select menu open while its checkable items are toggled."""

    def mouseReleaseEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        action = self.actionAt(event.position().toPoint())
        if action and action.isEnabled() and action.isCheckable():
            action.setChecked(not action.isChecked())
            return
        super().mouseReleaseEvent(event)


class MultiSelectButton(QToolButton):
    changed = Signal()

    def __init__(self, empty_text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.empty_text = empty_text
        self.selected: set[str] = set()
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.setMenu(PersistentCheckMenu(self))
        self.setText(empty_text)

    def set_options(self, values: list[str]) -> None:
        old = set(self.selected)
        menu = self.menu()
        assert menu is not None
        menu.clear()
        # Keep the caller's semantic order (especially 嚴重、高、中、低).
        for value in dict.fromkeys(values):
            action = menu.addAction(value)
            action.setCheckable(True)
            action.setChecked(value in old)
            action.toggled.connect(lambda checked, v=value: self._toggle(v, checked))

    def _toggle(self, value: str, checked: bool) -> None:
        if checked:
            self.selected.add(value)
        else:
            self.selected.discard(value)
        if self.selected:
            prefix = self.empty_text.split("：", 1)[0] if "：" in self.empty_text else ""
            self.setText(
                f"{prefix}：已選 {len(self.selected)} 項"
                if prefix
                else f"已選 {len(self.selected)} 項"
            )
        else:
            self.setText(self.empty_text)
        self.changed.emit()

    def clear_selection(self) -> None:
        self.selected.clear()
        self.setText(self.empty_text)
        menu = self.menu()
        if menu:
            for action in menu.actions():
                action.blockSignals(True)
                action.setChecked(False)
                action.blockSignals(False)


class FilterButton(QPushButton):
    def __init__(self, empty_text: str, parent: QWidget | None = None) -> None:
        super().__init__(empty_text, parent)
        self.empty_text = empty_text
        self.options: list[str] = []
        self.selected: set[str] = set()

    def update_text(self) -> None:
        self.setText(f"已選 {len(self.selected)} 項" if self.selected else self.empty_text)

    def clear_selection(self) -> None:
        self.selected.clear()
        self.update_text()


class FilterSelectionDialog(QDialog):
    def __init__(self, title: str, options: list[str], selected: set[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowIcon(make_app_icon())
        self.selected_values = set(selected)
        self.resize(470, 560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        layout.addWidget(QLabel(f"<b style='font-size:20px'>{html.escape(title)}</b><br><span style='color:#718095'>可搜尋並多選，完成後按套用</span>"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜尋名稱（忽略空格及大小寫）")
        layout.addWidget(self.search)
        self.listing = QListWidget()
        self.listing.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.options = sorted(set(options), key=core.natural_key)
        self.checkboxes: dict[str, QCheckBox] = {}
        self.items_by_value: dict[str, QListWidgetItem] = {}
        self.range_anchor: str | None = None
        self.click_modifiers: dict[str, bool] = {}
        self._populate_items()
        layout.addWidget(self.listing, 1)
        controls = QHBoxLayout()
        self.select_all_button = QPushButton("全選")
        clear = QPushButton("全部取消")
        cancel = QPushButton("取消")
        self.apply_button = QPushButton("套用選擇")
        self.apply_button.setObjectName("primaryButton")
        self.selection_count = QLabel()
        self.update_selection_count()
        controls.addWidget(self.select_all_button)
        controls.addWidget(clear)
        controls.addWidget(self.selection_count)
        controls.addStretch()
        controls.addWidget(cancel)
        controls.addWidget(self.apply_button)
        layout.addLayout(controls)
        self.search.textChanged.connect(self.filter_options)
        self.select_all_button.pressed.connect(self.select_all)
        clear.pressed.connect(self.clear_all)
        cancel.clicked.connect(self.reject)
        self.apply_button.clicked.connect(self.accept)

    def filter_options(self, text: str) -> None:
        query = core.normalize(text)
        for index in range(self.listing.count()):
            item = self.listing.item(index)
            value = str(item.data(Qt.ItemDataRole.UserRole) or "")
            item.setHidden(bool(query and query not in core.normalize(value)))

    def remember_check(self, value: str, checked: bool) -> None:
        if checked:
            self.selected_values.add(value)
        else:
            self.selected_values.discard(value)
        self.update_selection_count()

    def update_selection_count(self) -> None:
        self.selection_count.setText(f"已選 {len(self.selected_values)} / {len(self.options)} 項")

    def _populate_items(self) -> None:
        selected_keys = {core.normalize(value) for value in self.selected_values}
        self.listing.clear()
        self.checkboxes.clear()
        self.items_by_value.clear()
        self.range_anchor = None
        self.click_modifiers.clear()
        for value in self.options:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, value)
            checkbox = QCheckBox(value)
            checkbox.setChecked(core.normalize(value) in selected_keys)
            checkbox.toggled.connect(lambda checked, name=value: self.remember_check(name, checked))
            checkbox.pressed.connect(
                lambda name=value: self.click_modifiers.__setitem__(
                    name,
                    bool(QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier),
                )
            )
            checkbox.clicked.connect(
                lambda checked, name=value: self.apply_range_selection(
                    name,
                    checked,
                    self.click_modifiers.pop(name, False),
                )
            )
            item.setSizeHint(QSize(0, 38))
            self.listing.addItem(item)
            self.listing.setItemWidget(item, checkbox)
            self.checkboxes[value] = checkbox
            self.items_by_value[value] = item

    def apply_range_selection(self, value: str, checked: bool, shift_pressed: bool) -> None:
        """Apply the clicked state from the previous anchor through this visible item."""
        visible_values = self.visible_options()
        if shift_pressed and self.range_anchor in visible_values and value in visible_values:
            start = visible_values.index(self.range_anchor)
            end = visible_values.index(value)
            lower, upper = sorted((start, end))
            for option in visible_values[lower : upper + 1]:
                self.checkboxes[option].setChecked(checked)
        self.range_anchor = value

    def visible_options(self) -> list[str]:
        return [
            option
            for option in self.options
            if option in self.items_by_value and not self.items_by_value[option].isHidden()
        ]

    def select_all(self) -> None:
        visible_values = self.visible_options()
        self.selected_values.update(visible_values)
        for value in visible_values:
            checkbox = self.checkboxes[value]
            checkbox.blockSignals(True)
            checkbox.setChecked(True)
            checkbox.blockSignals(False)
        self.update_selection_count()
        self.listing.viewport().update()

    def clear_all(self) -> None:
        visible_values = self.visible_options()
        self.selected_values.difference_update(visible_values)
        for value in visible_values:
            checkbox = self.checkboxes[value]
            checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(False)
        self.update_selection_count()
        self.listing.viewport().update()

    def set_all_checks(self, state: Qt.CheckState) -> None:
        if state == Qt.CheckState.Checked:
            self.select_all()
        else:
            self.clear_all()

    def selections(self) -> set[str]:
        # selected_values is the authoritative model. Checkbox widgets are
        # rebuilt by select-all/filter operations and must not be used as the
        # return value after the dialog closes.
        return set(self.selected_values)


class VendorProductFilterDialog(QDialog):
    """Filter watched products through their vendor grouping."""

    def __init__(
        self,
        vendor_products: dict[str, set[str]],
        selected: dict[str, set[str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("選擇廠商及產品")
        self.setWindowIcon(make_app_icon())
        self.resize(820, 590)
        self.vendor_products = {
            vendor: set(products) for vendor, products in vendor_products.items()
        }
        self.selected_by_vendor = {
            vendor: set(products) & self.vendor_products.get(vendor, set())
            for vendor, products in selected.items()
            if set(products) & self.vendor_products.get(vendor, set())
        }

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(
            QLabel(
                "<b style='font-size:20px'>篩選廠商及產品</b><br>"
                "<span style='color:#718095'>先選擇左側廠商，再於右側勾選該廠商需要顯示的產品</span>"
            )
        )

        columns = QHBoxLayout()
        columns.setSpacing(14)
        vendor_panel = QFrame()
        vendor_panel.setObjectName("vendorPanel")
        vendor_layout = QVBoxLayout(vendor_panel)
        vendor_layout.setContentsMargins(14, 14, 14, 14)
        vendor_layout.addWidget(QLabel("<b style='font-size:15px'>關注廠商</b>"))
        self.vendor_search = QLineEdit()
        self.vendor_search.setPlaceholderText("搜尋廠商")
        vendor_layout.addWidget(self.vendor_search)
        self.vendor_list = QListWidget()
        self.vendor_list.setObjectName("vendorPanelList")
        vendor_layout.addWidget(self.vendor_list, 1)

        product_panel = QFrame()
        product_panel.setObjectName("productPanel")
        product_layout = QVBoxLayout(product_panel)
        product_layout.setContentsMargins(14, 14, 14, 14)
        self.product_heading = QLabel("<b style='font-size:15px'>關注產品</b>")
        product_layout.addWidget(self.product_heading)
        self.product_search = QLineEdit()
        self.product_search.setPlaceholderText("搜尋目前廠商產品")
        product_layout.addWidget(self.product_search)
        self.product_list = QListWidget()
        self.product_list.setObjectName("filterProductList")
        product_layout.addWidget(self.product_list, 1)
        product_controls = QHBoxLayout()
        select_vendor = QPushButton("全選")
        clear_vendor = QPushButton("取消全選")
        for button in (select_vendor, clear_vendor):
            button.setAutoDefault(False)
        product_controls.addWidget(select_vendor)
        product_controls.addWidget(clear_vendor)
        product_controls.addStretch()
        product_layout.addLayout(product_controls)

        columns.addWidget(vendor_panel, 1)
        columns.addWidget(product_panel, 1)
        layout.addLayout(columns, 1)

        footer = QHBoxLayout()
        self.selection_count = QLabel()
        cancel = QPushButton("取消")
        apply_button = QPushButton("套用篩選")
        apply_button.setObjectName("primaryButton")
        for button in (cancel, apply_button):
            button.setAutoDefault(False)
        footer.addWidget(self.selection_count)
        footer.addStretch()
        footer.addWidget(cancel)
        footer.addWidget(apply_button)
        layout.addLayout(footer)

        for vendor in sorted(self.vendor_products, key=core.natural_key):
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, vendor)
            self.vendor_list.addItem(item)
        self._refresh_vendor_labels()
        if self.vendor_list.count():
            self.vendor_list.setCurrentRow(0)
        self.vendor_list.currentItemChanged.connect(self._show_current_products)
        self.vendor_search.textChanged.connect(self._filter_vendors)
        self.product_search.textChanged.connect(self._filter_products)
        select_vendor.clicked.connect(self._select_current_vendor)
        clear_vendor.clicked.connect(self._clear_current_vendor)
        cancel.clicked.connect(self.reject)
        apply_button.clicked.connect(self.accept)
        self._show_current_products(self.vendor_list.currentItem())
        self._update_count()

    def _current_vendor(self) -> str:
        item = self.vendor_list.currentItem()
        return str(item.data(Qt.ItemDataRole.UserRole) or "") if item else ""

    def _refresh_vendor_labels(self) -> None:
        for index in range(self.vendor_list.count()):
            item = self.vendor_list.item(index)
            vendor = str(item.data(Qt.ItemDataRole.UserRole) or "")
            selected = len(self.selected_by_vendor.get(vendor, set()))
            total = len(self.vendor_products.get(vendor, set()))
            suffix = f"　已選 {selected}/{total}" if selected else f"　{total} 項"
            item.setText(f"{vendor}{suffix}")

    def _show_current_products(self, item: QListWidgetItem | None, _previous=None) -> None:
        self.product_list.clear()
        vendor = str(item.data(Qt.ItemDataRole.UserRole) or "") if item else ""
        self.product_heading.setText(
            f"<b style='font-size:15px'>{html.escape(vendor) if vendor else '關注產品'}</b>"
        )
        selected = self.selected_by_vendor.get(vendor, set())
        for product in sorted(self.vendor_products.get(vendor, set()), key=core.natural_key):
            row = QListWidgetItem()
            row.setData(Qt.ItemDataRole.UserRole, product)
            checkbox = SquareCheckBox(product)
            checkbox.setChecked(product in selected)
            checkbox.toggled.connect(
                lambda checked, v=vendor, p=product: self._toggle_product(v, p, checked)
            )
            # Match the card height and spacing used by「目前關注產品」.
            row.setSizeHint(QSize(0, 46))
            self.product_list.addItem(row)
            self.product_list.setItemWidget(row, checkbox)
        self._filter_products(self.product_search.text())

    def _toggle_product(self, vendor: str, product: str, checked: bool) -> None:
        values = self.selected_by_vendor.setdefault(vendor, set())
        if checked:
            values.add(product)
        else:
            values.discard(product)
            if not values:
                self.selected_by_vendor.pop(vendor, None)
        self._refresh_vendor_labels()
        self._update_count()

    def _filter_vendors(self, text: str) -> None:
        query = core.normalize(text)
        for index in range(self.vendor_list.count()):
            item = self.vendor_list.item(index)
            vendor = str(item.data(Qt.ItemDataRole.UserRole) or "")
            item.setHidden(bool(query and query not in core.normalize(vendor)))

    def _filter_products(self, text: str) -> None:
        query = core.normalize(text)
        for index in range(self.product_list.count()):
            item = self.product_list.item(index)
            product = str(item.data(Qt.ItemDataRole.UserRole) or "")
            item.setHidden(bool(query and query not in core.normalize(product)))

    def _select_current_vendor(self) -> None:
        vendor = self._current_vendor()
        if not vendor:
            return
        self.selected_by_vendor[vendor] = set(self.vendor_products[vendor])
        self._refresh_vendor_labels()
        self._show_current_products(self.vendor_list.currentItem())
        self._update_count()

    def _clear_current_vendor(self) -> None:
        vendor = self._current_vendor()
        self.selected_by_vendor.pop(vendor, None)
        self._refresh_vendor_labels()
        self._show_current_products(self.vendor_list.currentItem())
        self._update_count()

    def _clear_all(self) -> None:
        self.selected_by_vendor.clear()
        self._refresh_vendor_labels()
        self._show_current_products(self.vendor_list.currentItem())
        self._update_count()

    def _update_count(self) -> None:
        vendors = sum(bool(products) for products in self.selected_by_vendor.values())
        products = sum(len(values) for values in self.selected_by_vendor.values())
        self.selection_count.setText(f"已選 {vendors} 間廠商、{products} 項產品")

    def selections(self) -> dict[str, set[str]]:
        return {
            vendor: set(products)
            for vendor, products in self.selected_by_vendor.items()
            if products
        }


class DateRangeDialog(QDialog):
    """Two-calendar date picker constrained to a valid date window."""

    def __init__(
        self,
        minimum: QDate,
        maximum: QDate,
        start: QDate,
        end: QDate,
        show_boundary_months: bool = False,
        max_span_days: int | None = 30,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("自訂日期範圍")
        self.setWindowIcon(make_app_icon())
        self.resize(720, 440)
        self.minimum = minimum
        self.maximum = maximum
        self.max_span_days = max_span_days
        self._syncing_dates = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        layout.addWidget(
            QLabel(
                "<b style='font-size:20px'>選擇日期範圍</b><br>"
                f"<span style='color:#718095'>有效日期為 {minimum.toString('yyyy-MM-dd')} 至 "
                f"{maximum.toString('yyyy-MM-dd')}</span>"
            )
        )
        calendars = QHBoxLayout()
        start_box = QVBoxLayout()
        self.start_heading = QLabel()
        start_box.addWidget(self.start_heading)
        self.start_calendar = QCalendarWidget()
        self.start_calendar.setGridVisible(True)
        start_view = self.start_calendar.findChild(QTableView, "qt_calendar_calendarview")
        if start_view:
            start_view.setItemDelegate(CalendarDateDelegate(self.start_calendar, start_view))
        start_box.addWidget(self.start_calendar)
        end_box = QVBoxLayout()
        self.end_heading = QLabel()
        end_box.addWidget(self.end_heading)
        self.end_calendar = QCalendarWidget()
        self.end_calendar.setGridVisible(True)
        calendar_navigation_style = """
            QCalendarWidget QWidget#qt_calendar_navigationbar {
                background-color: #ffffff;
                border: none;
            }
            QCalendarWidget QToolButton {
                color: #243548;
                background-color: #ffffff;
            }
            QCalendarWidget QToolButton#qt_calendar_monthbutton::menu-indicator {
                image: none;
                width: 0px;
                height: 0px;
            }
        """
        self.start_calendar.setStyleSheet(calendar_navigation_style)
        self.end_calendar.setStyleSheet(calendar_navigation_style)
        self._lock_calendar_period_controls(self.start_calendar)
        self._lock_calendar_period_controls(self.end_calendar)
        end_view = self.end_calendar.findChild(QTableView, "qt_calendar_calendarview")
        if end_view:
            end_view.setItemDelegate(CalendarDateDelegate(self.end_calendar, end_view))
        end_box.addWidget(self.end_calendar)
        calendars.addLayout(start_box, 1)
        calendars.addLayout(end_box, 1)
        layout.addLayout(calendars, 1)
        footer = QHBoxLayout()
        cancel = QPushButton("取消")
        apply_button = QPushButton("套用日期")
        apply_button.setObjectName("primaryButton")
        for button in (cancel, apply_button):
            button.setAutoDefault(False)
        footer.addStretch()
        footer.addWidget(cancel)
        footer.addWidget(apply_button)
        layout.addLayout(footer)

        self.start_calendar.setDateRange(minimum, maximum)
        self.end_calendar.setDateRange(minimum, maximum)
        self.start_calendar.setSelectedDate(max(minimum, min(start, maximum)))
        self.end_calendar.setSelectedDate(max(minimum, min(end, maximum)))
        self.start_calendar.selectionChanged.connect(self._start_changed)
        self.end_calendar.selectionChanged.connect(self._end_changed)
        cancel.clicked.connect(self.reject)
        apply_button.clicked.connect(self.accept)
        self._start_changed()
        if show_boundary_months:
            self.start_calendar.setCurrentPage(minimum.year(), minimum.month())
            self.end_calendar.setCurrentPage(maximum.year(), maximum.month())

    def _start_changed(self) -> None:
        if self._syncing_dates:
            return
        self._syncing_dates = True
        start = self.start_calendar.selectedDate()
        end = self.end_calendar.selectedDate()
        if end < start:
            self.end_calendar.setSelectedDate(start)
        elif self.max_span_days is not None and end > start.addDays(self.max_span_days - 1):
            self.end_calendar.setSelectedDate(
                min(self.maximum, start.addDays(self.max_span_days - 1))
            )
        self._syncing_dates = False
        self._update_label()

    def _end_changed(self) -> None:
        if self._syncing_dates:
            return
        self._syncing_dates = True
        start = self.start_calendar.selectedDate()
        end = self.end_calendar.selectedDate()
        if start > end:
            self.start_calendar.setSelectedDate(end)
        elif self.max_span_days is not None and start < end.addDays(-(self.max_span_days - 1)):
            self.start_calendar.setSelectedDate(
                max(self.minimum, end.addDays(-(self.max_span_days - 1)))
            )
        self._syncing_dates = False
        self._update_label()

    @staticmethod
    def _lock_calendar_period_controls(calendar: QCalendarWidget) -> None:
        """Keep month/year labels visible while navigation is arrow-only."""
        for object_name in ("qt_calendar_monthbutton", "qt_calendar_yearbutton"):
            button = calendar.findChild(QToolButton, object_name)
            if button is None:
                continue
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            button.setCursor(Qt.CursorShape.ArrowCursor)

    def _update_label(self) -> None:
        start_text = self.start_calendar.selectedDate().toString("yyyy-MM-dd")
        end_text = self.end_calendar.selectedDate().toString("yyyy-MM-dd")
        self.start_heading.setText(f"<b>開始日期　{start_text}</b>")
        self.end_heading.setText(f"<b>結束日期　{end_text}</b>")

    def dates(self) -> tuple[QDate, QDate]:
        return self.start_calendar.selectedDate(), self.end_calendar.selectedDate()


class CatalogLookupDialog(QDialog):
    """Require users to choose a canonical vendor/product name from the local NVD index."""

    def __init__(self, kind: str, query: str, matches: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.kind = kind
        self.selected_name: str | None = None
        label = "廠商" if kind == "vendor" else "產品"
        self.setWindowTitle(f"選擇{label}名稱")
        self.setWindowIcon(make_app_icon())
        self.resize(560, 520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        layout.addWidget(
            QLabel(
                f"<b style='font-size:20px'>選擇{label}名稱</b><br>"
                f"<span style='color:#718095'>找到 {len(matches):,} 個包含「{html.escape(query)}」的名稱，雙擊即可添加</span>"
            )
        )
        self.search = QLineEdit()
        self.search.setPlaceholderText("在結果中搜尋（忽略大小寫及空格）")
        layout.addWidget(self.search)
        self.listing = QListWidget()
        self.listing.setObjectName("catalogLookupList")
        self.listing.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.matches = matches
        self.populate(matches)
        layout.addWidget(self.listing, 1)
        footer = QHBoxLayout()
        self.count_label = QLabel(f"{len(matches):,} 項結果")
        cancel = QPushButton("取消")
        footer.addWidget(self.count_label)
        footer.addStretch()
        footer.addWidget(cancel)
        layout.addLayout(footer)
        self.search.textChanged.connect(self.filter_results)
        self.listing.itemDoubleClicked.connect(self.choose_item)
        cancel.clicked.connect(self.reject)

    def populate(self, values: list[str]) -> None:
        self.listing.clear()
        self.listing.addItems(values)
        if values:
            self.listing.setCurrentRow(0)

    def filter_results(self, text: str) -> None:
        query = core.normalize(text)
        filtered = [name for name in self.matches if not query or query in core.normalize(name)]
        self.populate(filtered)
        self.count_label.setText(f"{len(filtered):,} 項結果")

    def choose_item(self, item: QListWidgetItem) -> None:
        self.selected_name = item.text()
        self.accept()


class WatchlistDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("管理關注名單")
        self.resize(820, 550)
        self.setObjectName("watchDialog")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)
        heading = QLabel("<span style='color:#169b9d;font-size:10px;letter-spacing:2px'>WATCHLIST</span><br><b style='font-size:24px'>關注範圍</b><br><span style='color:#718095'>先選擇廠商，雙擊廠商名稱並勾選需要監察的產品，漏洞列表只搜索已勾選產品</span>")
        layout.addWidget(heading)

        columns = QHBoxLayout()
        columns.setSpacing(14)
        vendor_panel, self.vendor_list, self.vendor_name, vendor_add, vendor_remove = self._make_column(
            "廠商名稱", "例如 Red Hat、Microsoft", "＋ 添加廠商", "vendorPanel"
        )
        # QDialog otherwise treats this as an automatic default button: Enter
        # would emit both QLineEdit.returnPressed and QPushButton.clicked.
        vendor_add.setAutoDefault(False)
        vendor_add.setDefault(False)
        vendor_remove.setAutoDefault(False)
        vendor_remove.setDefault(False)
        product_panel, self.product_list, self.product_name, product_add, product_remove = self._make_column(
            "目前關注產品", "", "", "productPanel"
        )
        columns.addWidget(vendor_panel, 1)
        columns.addWidget(product_panel, 1)
        layout.addLayout(columns, 1)
        self.product_name.hide()
        product_add.hide()
        product_remove.hide()
        product_add.setAutoDefault(False)
        product_remove.setAutoDefault(False)
        self.product_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        vendor_add.clicked.connect(self.add_vendor)
        vendor_remove.clicked.connect(self.remove_selected_vendor)
        self.vendor_name.returnPressed.connect(self.add_vendor)
        self.vendor_list.currentItemChanged.connect(self.show_vendor_products)
        self.vendor_list.itemDoubleClicked.connect(self.edit_vendor_products)
        self.vendor_catalog_cache: dict[str, list[str]] = {}
        self.vendor_products: dict[str, set[str]] = {}
        self._load()

        with core.catalog_lock:
            initial_catalog = dict(core.catalog_state)
        initial_status = (
            initial_catalog["message"]
            if initial_catalog["running"]
            else f"目前廠商紀錄：{initial_catalog['unique_vendors']:,}，產品紀錄：{initial_catalog['unique_products']:,}"
        )
        self.catalog_status = QLabel(str(initial_status))
        self.catalog_status.setObjectName("catalogStatus")
        layout.addWidget(self.catalog_status)

        footer = QHBoxLayout()
        self.sync_btn = QPushButton("⟳  更新產品名單")
        cancel_btn = QPushButton("取消")
        save_btn = QPushButton("儲存名單")
        for button in (self.sync_btn, cancel_btn, save_btn):
            button.setAutoDefault(False)
            button.setDefault(False)
        save_btn.setObjectName("primaryButton")
        footer.addWidget(self.sync_btn)
        footer.addStretch()
        footer.addWidget(cancel_btn)
        footer.addWidget(save_btn)
        layout.addLayout(footer)
        self.sync_btn.clicked.connect(self.sync_catalog)
        cancel_btn.clicked.connect(self.reject)
        save_btn.clicked.connect(self.save)
        self.catalog_timer = QTimer(self)
        self.catalog_timer.timeout.connect(self.poll_catalog_sync)
        if initial_catalog["running"]:
            self.sync_btn.setEnabled(False)
            self.sync_btn.setText("同步中…")
            self.catalog_timer.start(900)

    def _make_column(
        self, title: str, placeholder: str, button_text: str, object_name: str
    ) -> tuple[QFrame, QListWidget, QLineEdit, QPushButton, QPushButton]:
        panel = QFrame()
        panel.setObjectName(object_name)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 15, 16, 15)
        panel_layout.setSpacing(10)
        heading_row = QHBoxLayout()
        heading = QLabel(f"<b style='font-size:15px'>{title}</b>")
        count = QLabel("0 項")
        count.setObjectName(f"{object_name}Count")
        heading_row.addWidget(heading)
        heading_row.addStretch()
        heading_row.addWidget(count)
        panel_layout.addLayout(heading_row)
        listing = QListWidget()
        listing.setObjectName(f"{object_name}List")
        listing.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        panel_layout.addWidget(listing, 1)
        name = QLineEdit()
        name.setPlaceholderText(placeholder)
        panel_layout.addWidget(name)
        controls = QHBoxLayout()
        add_button = QPushButton(button_text)
        add_button.setObjectName("addButton")
        remove_button = QPushButton("移除選取")
        controls.addWidget(add_button, 1)
        controls.addWidget(remove_button)
        panel_layout.addLayout(controls)
        return panel, listing, name, add_button, remove_button

    def _load(self) -> None:
        self.vendor_list.clear()
        self.product_list.clear()
        with core.db() as conn:
            vendors = conn.execute(
                "SELECT name FROM watchlist WHERE kind='vendor' AND enabled=1 ORDER BY name COLLATE NOCASE"
            ).fetchall()
            relations = conn.execute(
                "SELECT vendor_name,product_name FROM watch_vendor_products ORDER BY vendor_name,product_name"
            ).fetchall()
        self.vendor_products = {row["name"]: set() for row in vendors}
        for row in relations:
            self.vendor_products.setdefault(row["vendor_name"], set()).add(row["product_name"])
        for vendor in sorted(self.vendor_products, key=core.natural_key):
            self.vendor_list.addItem(vendor)
        self._sort_list(self.vendor_list)
        if self.vendor_list.count():
            self.vendor_list.setCurrentRow(0)
        else:
            self.show_vendor_products()
        self._update_counts()

    @staticmethod
    def _sort_list(listing: QListWidget) -> None:
        names = sorted({listing.item(i).text() for i in range(listing.count())}, key=core.natural_key)
        listing.clear()
        listing.addItems(names)

    def _update_counts(self) -> None:
        vendor_count = self.findChild(QLabel, "vendorPanelCount")
        product_count = self.findChild(QLabel, "productPanelCount")
        if vendor_count:
            vendor_count.setText(f"{self.vendor_list.count()} 項")
        if product_count:
            product_count.setText(f"{self.product_list.count()} 項")

    def add_vendor(self) -> None:
        query = self.vendor_name.text().strip()
        query_key = core.normalize(query)
        if not query_key:
            return
        existing_by_key = {
            core.normalize(self.vendor_list.item(index).text()): index
            for index in range(self.vendor_list.count())
        }
        # An exact spelling variant such as "check point" / "CHECKPOINT"
        # should be reported immediately instead of reopening product editing.
        if query_key in existing_by_key:
            index = existing_by_key[query_key]
            existing_name = self.vendor_list.item(index).text()
            self.vendor_list.setCurrentRow(index)
            self.vendor_name.clear()
            QMessageBox.information(
                self,
                "廠商已存在",
                f"「{existing_name}」已存在於關注名單",
            )
            return
        with core.db() as conn:
            catalog_names = [
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM catalog WHERE kind='vendor' ORDER BY name COLLATE NOCASE"
                ).fetchall()
            ]
        matches = [name for name in catalog_names if query_key in core.normalize(name)]
        matches.sort(
            key=lambda name: (
                0 if core.normalize(name) == query_key else 1,
                core.natural_key(name),
            )
        )
        if not matches:
            QMessageBox.information(self, "找不到廠商", f"找不到包含「{query}」的廠商名稱")
            return
        dialog = CatalogLookupDialog("vendor", query, matches, self)
        if dialog.exec() != QDialog.DialogCode.Accepted or not dialog.selected_name:
            return
        name = dialog.selected_name
        for index in range(self.vendor_list.count()):
            if core.normalize(self.vendor_list.item(index).text()) == core.normalize(name):
                self.vendor_list.setCurrentRow(index)
                self.vendor_name.clear()
                QMessageBox.information(
                    self,
                    "廠商已存在",
                    f"「{self.vendor_list.item(index).text()}」已存在於關注名單",
                )
                return
        self.vendor_name.clear()
        self.edit_vendor_products(name, new_vendor=True)

    def catalog_products_for_vendor(self, vendor: str) -> list[str]:
        if vendor in self.vendor_catalog_cache:
            return self.vendor_catalog_cache[vendor]
        vendor_key = core.normalize(vendor)
        with core.db() as conn:
            names = [
                row["name"]
                for row in conn.execute("SELECT name FROM catalog WHERE kind='product'")
            ]
            raw_vendor_ids = {
                row["vendor_id"]
                for row in conn.execute(
                    "SELECT vendor_id FROM catalog_cpe WHERE kind='vendor' AND name=?",
                    (vendor,),
                )
            }
            if raw_vendor_ids:
                placeholders = ",".join("?" for _ in raw_vendor_ids)
                names.extend(
                    row["name"]
                    for row in conn.execute(
                        f"SELECT name FROM catalog_cpe WHERE kind='product' AND vendor_id IN ({placeholders})",
                        tuple(raw_vendor_ids),
                    )
                )
        vendor_names = {
            name for name in names if core.normalize(name).startswith(vendor_key)
        }
        known_product_keys, protected_parent_keys = core.product_family_context(vendor_names)
        products: dict[str, str] = {}
        for name in vendor_names:
            category = core.validated_product_family(
                name, known_product_keys, protected_parent_keys
            )
            suffix = category
            for _ in range(2):
                prefix_end = next(
                    (
                        position
                        for position in range(1, len(suffix) + 1)
                        if core.normalize(suffix[:position]) == vendor_key
                    ),
                    None,
                )
                if prefix_end is None:
                    break
                suffix = suffix[prefix_end:].strip()
            category = f"{vendor} {suffix}".strip()
            category_key = core.normalize(category)
            if category_key != vendor_key:
                products[category_key] = category
        result = sorted(products.values(), key=core.natural_key)
        self.vendor_catalog_cache[vendor] = result
        return result

    def show_vendor_products(self, item: QListWidgetItem | None = None, _previous=None) -> None:
        self.product_list.clear()
        vendor = item.text() if item else ""
        if vendor:
            self.product_list.addItems(sorted(self.vendor_products.get(vendor, set()), key=core.natural_key))
        self._update_counts()

    def edit_vendor_products(self, vendor_or_item, new_vendor: bool = False) -> None:
        vendor = vendor_or_item.text() if isinstance(vendor_or_item, QListWidgetItem) else str(vendor_or_item)
        options = self.catalog_products_for_vendor(vendor)
        if not options:
            QMessageBox.information(self, "找不到產品", f"找不到「{vendor}」的產品，請先更新產品名單後再試")
            return
        current = self.vendor_products.get(vendor, set())
        options, canonical_current = canonical_product_selection(options, current)
        dialog = FilterSelectionDialog(f"選擇 {vendor} 產品", options, canonical_current, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        selected = dialog.selections()
        if not selected:
            answer = QMessageBox.question(
                self,
                "移除廠商關注",
                f"沒有選擇任何產品，是否移除「{vendor}」及其所有產品的關注？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self.remove_vendor(vendor)
            return
        self.vendor_products[vendor] = selected
        if not any(core.normalize(self.vendor_list.item(i).text()) == core.normalize(vendor) for i in range(self.vendor_list.count())):
            self.vendor_list.addItem(vendor)
            self._sort_list(self.vendor_list)
        for index in range(self.vendor_list.count()):
            if core.normalize(self.vendor_list.item(index).text()) == core.normalize(vendor):
                self.vendor_list.setCurrentRow(index)
                break
        self.show_vendor_products(self.vendor_list.currentItem())

    def remove_vendor(self, vendor: str) -> None:
        self.vendor_products.pop(vendor, None)
        for index in range(self.vendor_list.count()):
            if core.normalize(self.vendor_list.item(index).text()) == core.normalize(vendor):
                self.vendor_list.takeItem(index)
                break
        if self.vendor_list.count():
            self.vendor_list.setCurrentRow(0)
        else:
            self.show_vendor_products()
        self._update_counts()

    def remove_selected_vendor(self) -> None:
        item = self.vendor_list.currentItem()
        if not item:
            return
        vendor = item.text()
        answer = QMessageBox.question(
            self,
            "移除廠商關注",
            f"確定移除「{vendor}」及其所有已選產品？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.remove_vendor(vendor)

    def entries(self) -> list[tuple[str, str, int]]:
        vendors = [("vendor", vendor, 1) for vendor in self.vendor_products]
        products = [("product", product, 1) for values in self.vendor_products.values() for product in values]
        return vendors + products

    def save(self) -> None:
        entries = self.entries()
        with core.db() as conn:
            conn.execute("DELETE FROM watchlist")
            conn.execute("DELETE FROM watch_vendor_products")
            conn.executemany("INSERT OR IGNORE INTO watchlist(kind,name,enabled) VALUES (?, ?, ?)", entries)
            conn.executemany(
                "INSERT INTO watch_vendor_products(vendor_name,product_name) VALUES (?,?)",
                [
                    (vendor, product)
                    for vendor, products in self.vendor_products.items()
                    for product in products
                ],
            )
        self.accept()

    def sync_catalog(self) -> None:
        if core.start_catalog_sync():
            self.sync_btn.setEnabled(False)
            self.sync_btn.setText("同步中…")
            self.catalog_status.setText("正在連接產品名單…")
            self.catalog_timer.start(900)
        else:
            self.catalog_timer.start(900)

    def poll_catalog_sync(self) -> None:
        with core.catalog_lock:
            state = dict(core.catalog_state)
        self.catalog_status.setText(str(state.get("error") or state["message"]))
        if not state["running"]:
            self.catalog_timer.stop()
            self.sync_btn.setEnabled(True)
            if state.get("error"):
                QMessageBox.warning(self, "同步未完成", str(state["error"]))
                self.sync_btn.setText("⟳  重新更新產品名單")
            else:
                self.sync_btn.setText("✓  產品名單已更新")
                self.vendor_catalog_cache.clear()

    def closeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        super().closeEvent(event)


class NvdApiKeyTutorialDialog(QDialog):
    """Compact, readable guide for requesting and activating an NVD API Key."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NVD API Key申請教學")
        self.setWindowIcon(make_app_icon())
        self.setModal(True)
        self.setObjectName("apiKeyTutorialDialog")
        self.resize(580, 570)
        self.setMinimumSize(540, 500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(14)
        heading = QLabel(
            "<b style='font-size:19px;color:#14283a'>NVD API Key申請教學</b><br>"
            "<span style='font-size:12px;color:#758395'>完成以下四個步驟後，把API Key貼回設定視窗</span>"
        )
        layout.addWidget(heading)

        self.step_titles: list[QLabel] = []
        self.step_bodies: list[QLabel] = []
        self.tutorial_links: list[QLabel] = []

        scroll = QScrollArea()
        scroll.setObjectName("apiKeyTutorialScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_content.setObjectName("apiKeyTutorialScrollContent")
        steps_layout = QVBoxLayout(scroll_content)
        steps_layout.setContentsMargins(0, 0, 4, 0)
        steps_layout.setSpacing(10)

        def add_step(
            number: int,
            title: str,
            body: str,
            link: str | None = None,
        ) -> None:
            card = QFrame()
            card.setObjectName("tutorialStepCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(15, 13, 15, 13)
            card_layout.setSpacing(8)

            heading_row = QHBoxLayout()
            heading_row.setSpacing(9)
            badge = QLabel(f"{number:02d}")
            badge.setObjectName("tutorialStepNumber")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setFixedSize(30, 24)
            title_label = QLabel(title)
            title_label.setObjectName("tutorialStepTitle")
            heading_row.addWidget(badge)
            heading_row.addWidget(title_label, 1)
            card_layout.addLayout(heading_row)

            body_label = QLabel(body)
            body_label.setObjectName("tutorialStepBody")
            body_label.setWordWrap(True)
            body_label.setTextFormat(Qt.TextFormat.RichText)
            body_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            card_layout.addWidget(body_label)
            self.step_titles.append(title_label)
            self.step_bodies.append(body_label)

            if link:
                link_label = QLabel(f"<a href='{link}'>{link}</a>")
                link_label.setObjectName("tutorialWebsiteLink")
                link_label.setWordWrap(True)
                link_label.setOpenExternalLinks(True)
                link_label.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextBrowserInteraction
                )
                card_layout.addWidget(link_label)
                self.tutorial_links.append(link_label)
            steps_layout.addWidget(card)

        add_step(
            1,
            "進入NVD API Key申請網站",
            "點擊以下連結，開啟NVD API Key申請頁面",
            "https://nvd.nist.gov/developers/api-key-requested",
        )
        add_step(
            2,
            "填寫申請資料",
            "<b>Organization Name</b>　可任意填寫<br>"
            "<b>Email Address</b>　你的電郵地址<br>"
            "<b>Organization Type</b>　選擇 Personal Use / Not Listed<br><br>"
            "在 <b>Terms of Use</b> 框下拉到最底部，勾選 "
            "<b>I agree to the Terms of Use</b>，最後點選 <b>Submit</b>",
        )
        add_step(
            3,
            "確認電郵地址",
            "你的電郵地址會收到一封標題為 <b>Request for NVD API Key</b> 的郵件<br><br>"
            "開啟以下確認頁面，再次輸入你的電郵地址，以及郵件提供的UUID",
            "https://nvd.nist.gov/developers/confirm-api-key",
        )
        add_step(
            4,
            "保存並使用API Key",
            "網站會顯示你專屬的API Key，請複製並妥善保存<br><br>"
            "回到API Key設定視窗貼上內容，點選 <b>驗證並使用</b>，驗證成功後便會生效",
        )
        steps_layout.addStretch()
        scroll.setWidget(scroll_content)
        self.guide = scroll
        layout.addWidget(scroll, 1)

        footer = QHBoxLayout()
        footer.addStretch()
        close_button = QPushButton("關閉")
        close_button.clicked.connect(self.accept)
        footer.addWidget(close_button)
        layout.addLayout(footer)

        self.setStyleSheet(
            """
            #apiKeyTutorialDialog { background:#f3f6f9; }
            #apiKeyTutorialScroll, #apiKeyTutorialScrollContent { background:transparent; }
            #tutorialStepCard {
                background:#ffffff;
                border:1px solid #d9e3ea;
                border-radius:8px;
            }
            #tutorialStepNumber {
                color:#ffffff;
                background:#148e94;
                border-radius:12px;
                font-size:11px;
                font-weight:700;
            }
            #tutorialStepTitle {
                color:#1b3043;
                font-size:14px;
                font-weight:700;
            }
            #tutorialStepBody {
                color:#4a5d70;
                font-size:12px;
                line-height:1.55;
            }
            #tutorialWebsiteLink {
                color:#0563c1;
                font-size:12px;
            }
            QPushButton {
                min-height:34px;
                padding:0 14px;
                color:#243548;
                background:#ffffff;
                border:1px solid #cbd6df;
                border-radius:6px;
            }
            QPushButton:hover { border-color:#159b9c; color:#0e777b; }
            """
        )


class NvdApiKeyDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("設定API Key")
        self.setWindowIcon(make_app_icon())
        self.setModal(True)
        self.setFixedWidth(490)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)
        title = QLabel("設定API Key")
        title.setStyleSheet("font-size:18px;font-weight:700;color:#14283a")
        layout.addWidget(title)
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.key_input.setClearButtonEnabled(True)
        self.key_input.setPlaceholderText("輸入API Key")
        saved_key = core.current_nvd_api_key()
        if saved_key:
            self.key_input.setText(saved_key)
            self.key_input.setCursorPosition(len(saved_key))
        self.key_input.returnPressed.connect(self.verify_key)
        layout.addWidget(self.key_input)

        buttons = QHBoxLayout()
        self.tutorial_link = QLabel(
            "<a href='tutorial' style='color:#0563c1;text-decoration:underline;font-size:12px'>"
            "查看教學</a>"
        )
        self.tutorial_link.setObjectName("apiKeyTutorialLink")
        self.tutorial_link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        self.tutorial_link.setOpenExternalLinks(False)
        self.tutorial_link.linkActivated.connect(lambda _link: self.open_tutorial())
        buttons.addWidget(self.tutorial_link)
        self.clear_btn = QPushButton("清除API Key")
        self.clear_btn.setVisible(core.has_nvd_api_key())
        self.clear_btn.clicked.connect(self.clear_key)
        buttons.addWidget(self.clear_btn)
        buttons.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)
        self.verify_btn = QPushButton("驗證並使用")
        self.verify_btn.setObjectName("primaryButton")
        self.verify_btn.clicked.connect(self.verify_key)
        buttons.addWidget(self.verify_btn)
        layout.addLayout(buttons)

    def open_tutorial(self) -> None:
        NvdApiKeyTutorialDialog(self).exec()

    def verify_key(self) -> None:
        key = self.key_input.text().strip()
        if not key:
            QMessageBox.information(self, "尚未輸入", "請輸入API Key")
            return
        self.verify_btn.setEnabled(False)
        self.verify_btn.setText("正在驗證…")
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        QApplication.processEvents()
        try:
            try:
                valid, message, reason = core.validate_nvd_api_key(key)
            except Exception:
                valid = False
                reason = "service"
                message = "NVD資料庫回應異常，請稍後再驗證"
        finally:
            QApplication.restoreOverrideCursor()
            self.verify_btn.setEnabled(True)
            self.verify_btn.setText("驗證並使用")
        if valid:
            QMessageBox.information(self, "API Key已設定", message)
            self.accept()
            return
        self.clear_btn.setVisible(core.has_nvd_api_key())
        titles = {
            "key": "API Key無法使用",
            "network": "網絡連線失敗",
            "rate_limit": "請求過於頻繁",
            "service": "NVD服務異常",
        }
        QMessageBox.warning(self, titles.get(reason, "驗證未完成"), message)

    def clear_key(self) -> None:
        answer = QMessageBox.question(
            self,
            "清除API Key",
            "確定清除已保存的API Key，並恢復預設？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            core.clear_nvd_api_key()
            self.accept()


class VulHubWindow(QMainWindow):
    def __init__(self, archive_only: bool = False) -> None:
        super().__init__()
        self.archive_only = archive_only
        self.archive_window: VulHubWindow | None = None
        self.rows: list[dict[str, Any]] = []
        self.filtered_rows: list[dict[str, Any]] = []
        self.selected: dict[str, Any] | None = None
        self.show_english = False
        self.show_title_english = False
        self.watched_product_names: set[str] = set()
        self.watched_vendor_products: dict[str, set[str]] = {}
        self.scope_filter_selection: dict[str, set[str]] = {}
        self.available_date_min = QDate.currentDate()
        self.available_date_max = QDate.currentDate()
        self.filter_start_date = QDate.currentDate().addDays(-29)
        self.filter_end_date = QDate.currentDate()
        self.setWindowTitle("VulHub - 歸檔紀錄" if archive_only else "VulHub - 漏洞警報平台")
        self.setWindowIcon(make_app_icon())
        self.resize(1480, 930)
        self.setMinimumSize(1080, 720)
        self._build_ui()
        self._apply_style()
        application = QApplication.instance()
        if application is not None:
            application.installEventFilter(self)
        core.init_db()
        self.api_status_timer = QTimer(self)
        self.api_status_timer.timeout.connect(self.refresh_api_status)
        if not self.archive_only:
            self.refresh_api_status()
            self.api_status_timer.start(1500)
        self.last_translation_completed = 0
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.poll_update)
        self.translation_timer = QTimer(self)
        self.translation_timer.timeout.connect(self.poll_translations)
        self.translation_timer.start(700)
        self.progress_message.setText("正在載入本地漏洞列表…")
        self.progress.setValue(1)
        self.refresh_btn.setEnabled(False)
        # Some Windows themes assign startup focus to the first push button
        # and draw a prominent dotted rectangle around it.  Move only the
        # initial focus to a non-visual anchor; normal Tab navigation and
        # mouse interaction remain available afterwards.
        QTimer.singleShot(0, self._set_startup_focus)
        # Let Qt paint the main window before processing the local database.
        QTimer.singleShot(50, self.initialize_data)

    def showEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        super().showEvent(event)
        # On a clean Windows profile the taskbar button can be created only
        # after the pre-show icon assignment.  Reapply it once the native HWND
        # exists so the first launch is identical to subsequent launches.
        self.setWindowIcon(make_app_icon())

    def _set_startup_focus(self) -> None:
        self.startup_focus_anchor.setFocus(Qt.FocusReason.OtherFocusReason)

    def initialize_data(self) -> None:
        # Incomplete translations are persisted in vulhub.db.  Resume them in
        # the background after a restart without blocking the first paint.
        core.resume_unfinished_translations()
        self.load_rows()
        self.refresh_btn.setEnabled(True)
        if self.archive_only:
            self.progress_frame.hide()
            return
        core.start_update(30)
        self.update_timer.start(900)

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        central.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.startup_focus_anchor = central
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(72)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(34, 0, 34, 0)
        header_layout.addWidget(LogoWidget())
        brand = QLabel("<b style='font-size:23px;color:white'>VulHub</b><br><span style='font-size:11px;color:#8ea0b3;letter-spacing:3px'>漏洞警報平台</span>")
        header_layout.addWidget(brand)
        header_layout.addStretch()
        self.api_status = QLabel()
        self.api_status.setObjectName("apiStatus")
        if self.archive_only:
            self.api_status.setText("●  NVD API 2.0")
            self.api_status.setTextFormat(Qt.TextFormat.PlainText)
            self.api_status.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            self.api_status.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.api_status.setCursor(Qt.CursorShape.ArrowCursor)
        else:
            self.api_status.setTextFormat(Qt.TextFormat.RichText)
            self.api_status.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)
            self.api_status.setOpenExternalLinks(False)
            self.api_status.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self.api_status.setCursor(Qt.CursorShape.PointingHandCursor)
            self.api_status.linkActivated.connect(lambda _link: self.open_nvd_api_key_dialog())
        header_layout.addWidget(self.api_status)
        watch_btn = QPushButton("☷  關注名單")
        watch_btn.clicked.connect(self.open_watchlist)
        watch_btn.setVisible(not self.archive_only)
        header_layout.addWidget(watch_btn)
        self.refresh_btn = QPushButton("關閉頁面" if self.archive_only else "↻  立即更新")
        self.refresh_btn.setObjectName("refreshButton")
        self.refresh_btn.clicked.connect(self.close if self.archive_only else self.refresh_now)
        header_layout.addWidget(self.refresh_btn)
        root.addWidget(header)

        content = QWidget()
        content.setObjectName("content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(26, 22, 26, 26)
        content_layout.setSpacing(13)

        title_row = QHBoxLayout()
        title = QLabel(
            "<span style='color:#159598;font-size:11px'>01　│</span>　"
            f"<b style='font-size:20px'>{'歸檔紀錄' if self.archive_only else '漏洞搜尋'}</b>　"
            f"<span style='color:#758395'>{'檢視最近 3 個月的漏洞紀錄' if self.archive_only else '搜尋、篩選並檢視最新風險'}</span>"
        )
        title_row.addWidget(title)
        title_row.addStretch()
        self.title_language_btn = QPushButton("EN　英文名稱")
        self.title_language_btn.clicked.connect(self.toggle_search_title_language)
        title_row.addWidget(self.title_language_btn)
        self.count_label = QLabel("0 項漏洞")
        self.count_label.setObjectName("countBadge")
        title_row.addWidget(self.count_label)
        content_layout.addLayout(title_row)

        filter_box = QFrame()
        filter_box.setObjectName("card")
        filters = QGridLayout(filter_box)
        filters.setContentsMargins(14, 12, 14, 12)
        filters.setHorizontalSpacing(8)
        filters.setVerticalSpacing(0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜尋 CVE 編號或漏洞名稱")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_filters)
        filters.addWidget(self.search, 0, 0)
        clear_btn = QPushButton("重設")
        clear_btn.setObjectName("clearFilterButton")
        clear_btn.setFixedWidth(76)
        clear_btn.setToolTip("清除關鍵字及所有篩選條件")
        clear_btn.clicked.connect(self.clear_filters)
        filters.addWidget(clear_btn, 0, 4)

        self.scope_filter = QPushButton("廠商及產品：全部關注項目")
        self.scope_filter.setObjectName("scopeFilterButton")
        self.scope_filter.setToolTip("選擇廠商後，再勾選該廠商的產品")
        self.scope_filter.clicked.connect(self.open_scope_filter)
        filters.addWidget(self.scope_filter, 0, 1)

        self.risk_filter = MultiSelectButton("風險等級：全部")
        self.risk_filter.setObjectName("riskFilter")
        self.risk_filter.set_options(["嚴重", "高", "中", "低"])
        self.risk_filter.changed.connect(self.apply_filters)
        filters.addWidget(self.risk_filter, 0, 2)
        self.date_filter = QToolButton()
        self.date_filter.setObjectName("dateFilter")
        self.date_filter.setText(
            "日期範圍：自訂日期" if self.archive_only else "日期範圍：最近 30 天"
        )
        if self.archive_only:
            self.date_filter.clicked.connect(self.open_custom_date_range)
        else:
            self.date_filter.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            date_menu = QMenu(self.date_filter)
            for label, days in (("最近 1 天", 1), ("最近 7 天", 7), ("最近 14 天", 14), ("最近 30 天", 30)):
                date_menu.addAction(label, lambda checked=False, value=days: self.set_recent_days(value))
            date_menu.addSeparator()
            date_menu.addAction("自訂日期範圍…", self.open_custom_date_range)
            self.date_filter.setMenu(date_menu)
        filters.addWidget(self.date_filter, 0, 3)

        filters.setColumnStretch(0, 5)
        filters.setColumnStretch(1, 4)
        filters.setColumnStretch(2, 2)
        filters.setColumnStretch(3, 3)
        content_layout.addWidget(filter_box)

        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("progressFrame")
        progress_layout = QHBoxLayout(self.progress_frame)
        progress_layout.setContentsMargins(14, 8, 14, 8)
        self.progress_message = QLabel("正在連接 NVD 資料庫…")
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        progress_layout.addWidget(self.progress_message, 2)
        progress_layout.addWidget(self.progress, 1)
        content_layout.addWidget(self.progress_frame)

        self.results_splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["發佈日期", "CVE 編號", "等級", "CVSS 分數", "廠商名稱", "產品名稱", "漏洞名稱"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.setSortingEnabled(True)
        self.table.setMouseTracking(True)
        self.table.setItemDelegate(PreserveSelectionTextDelegate(self.table))
        self.table.setItemDelegateForColumn(5, ProductDelegate(self.table))
        self.table.verticalHeader().setVisible(False)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        for column, width in enumerate([108, 150, 82, 98, 175, 320]):
            self.table.setColumnWidth(column, width)
        # Use the item carried by the signal.  During a mouse click Qt can emit
        # currentItemChanged before the new row's selection flag is committed;
        # re-reading current/selected rows at that moment can therefore show
        # the previously selected CVE in the detail pane.
        self.table.currentItemChanged.connect(self.show_selected_detail)
        self.table.itemClicked.connect(self.show_selected_detail)
        self.table.itemSelectionChanged.connect(self.update_result_count)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.open_result_context_menu)
        self.results_splitter.addWidget(self.table)

        detail_container = QFrame()
        detail_container.setObjectName("detailCard")
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_header = QHBoxLayout()
        detail_header.setContentsMargins(18, 10, 18, 0)
        detail_title = QLabel("<span style='color:#159598;font-size:11px'>02　│</span>　<b style='font-size:18px'>漏洞詳細資料</b>")
        detail_header.addWidget(detail_title)
        detail_header.addStretch()
        self.language_btn = QPushButton("EN　原文顯示")
        self.language_btn.clicked.connect(self.toggle_language)
        detail_header.addWidget(self.language_btn)
        detail_layout.addLayout(detail_header)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        self.detail.setHtml(self.empty_detail_html())
        detail_layout.addWidget(self.detail)
        self.results_splitter.addWidget(detail_container)
        self.results_splitter.setChildrenCollapsible(False)
        self.results_splitter.setStretchFactor(0, 4)
        self.results_splitter.setStretchFactor(1, 6)
        self.results_splitter.setSizes([330, 440])
        content_layout.addWidget(self.results_splitter, 1)
        archive_link_row = QHBoxLayout()
        archive_link_row.setContentsMargins(0, 0, 4, 0)
        archive_link_row.addStretch()
        self.archive_link = QLabel(
            "<a href='archive' style='color:#0563c1;text-decoration:underline;font-size:12px'>"
            "查看歸檔紀錄</a>"
        )
        self.archive_link.setObjectName("archiveLink")
        self.archive_link.setToolTip("檢視最近 3 個月的漏洞紀錄")
        self.archive_link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        self.archive_link.setOpenExternalLinks(False)
        self.archive_link.linkActivated.connect(lambda _link: self.open_archive_window())
        self.archive_link.setVisible(not self.archive_only)
        archive_link_row.addWidget(self.archive_link)
        content_layout.addLayout(archive_link_row)
        root.addWidget(content, 1)

    def _apply_style(self) -> None:
        checkbox_empty = (APP_DIR / "static" / "checkbox-empty.svg").as_posix()
        checkbox_checked = (APP_DIR / "static" / "checkmark.svg").as_posix()
        style = """
            QMainWindow, #central, #content { background: #f3f6f9; }
            QWidget { color: #142235; font-family: 'Microsoft JhengHei UI', 'Noto Sans TC'; font-size: 12px; }
            #header { background: #071421; border-bottom: 1px solid #213348; }
            #header QLabel, #header QWidget { background: transparent; }
            #header QPushButton { color: #e9f2f6; background: #102337; border: 1px solid #33495e; border-radius: 7px; padding: 9px 15px; }
            #header QPushButton:hover { border-color: #35cac7; background: #173148; }
            #header #refreshButton { background: #148e94; border-color: #36c6c4; font-weight: 700; }
            #apiStatus { color: #78d8bd; margin-right: 12px; }
            #card, #detailCard { background: #ffffff; border: 1px solid #d9e2e9; border-radius: 10px; }
            QLineEdit, QComboBox, QDateEdit, QToolButton { min-height: 37px; background: white; border: 1px solid #ccd6df; border-radius: 6px; padding: 0 11px; }
            QLineEdit:focus, QComboBox:focus, QDateEdit:focus, QToolButton:focus { border: 1px solid #1ba5a5; }
            QLineEdit { border-left: 3px solid #169b9e; }
            QLineEdit > QToolButton { min-width:18px; max-width:18px; min-height:18px; max-height:18px; border:none; border-radius:9px; padding:0; margin:0 5px 0 0; background:transparent; }
            QLineEdit > QToolButton:hover { background:#e7edf1; }
            QPushButton { min-height: 34px; background: white; border: 1px solid #cbd5de; border-radius: 6px; padding: 0 13px; }
            QPushButton:hover { border-color: #159b9c; color: #0e777b; }
            QPushButton#primaryButton { color:#ffffff; background:#148e94; border-color:#148e94; font-weight:700; }
            QPushButton#primaryButton:hover { background:#117d82; border-color:#117d82; color:#ffffff; }
            #scopeFilterButton { text-align:left; padding-left:14px; background:#f7fbfb; border-left:3px solid #169b9e; }
            #dateFilter { text-align:left; background:#f9fbfc; }
            #riskFilter::menu-indicator, #dateFilter::menu-indicator { image:none; width:0; }
            #clearFilterButton { color:#617083; background:#f7f9fb; }
            #archiveLink { background:transparent; }
            #primaryButton { color: white; background: #148f94; border: none; font-weight: 700; }
            #countBadge { color: #0d7e83; background: #e4f7f5; border: 1px solid #bfe7e3; border-radius: 12px; padding: 5px 12px; }
            #countBadge[selectionActive="true"] { color: #27638f; background: #edf5ff; border-color: #b7d8f5; }
            #progressFrame { background: #e5f7f5; border: 1px solid #bce7e2; border-radius: 6px; }
            QProgressBar { min-height: 8px; max-height: 8px; border: none; border-radius: 4px; background: #c7eae6; color: transparent; }
            QProgressBar::chunk { background: #17a49c; border-radius: 4px; }
            QTableWidget { background: white; alternate-background-color: white; border: 1px solid #dce3e9; border-radius: 8px; gridline-color: #edf1f4; selection-background-color: #edf5ff; outline: none; }
            QTableWidget::item { padding: 9px 12px; }
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {
                background: #edf5ff;
            }
            QHeaderView::section { background: #f1f4f7; color: #65758a; border: none; border-bottom: 1px solid #d7e0e7; padding: 11px 12px; font-size: 11px; font-weight: 700; }
            QTextBrowser { border: none; background: #ffffff; color: #27394b; padding: 3px 18px 14px; selection-background-color: #bfe8e5; }
            QSplitter::handle { height: 7px; background: transparent; }
            QToolTip { color: #edf4f8; background: #071421; border: 1px solid #334b61; padding: 10px; font-size: 12px; }
            QListWidget { background: white; border: 1px solid #d7e0e7; border-radius: 6px; padding: 4px; outline: none; }
            QListWidget::item { padding: 9px; border-radius: 4px; }
            QListWidget::item:selected { background: #dff3f2; color: #123; }
            QCheckBox { spacing:8px; }
            QCheckBox::indicator { width:16px; height:16px; border:none; image:url(__CHECKBOX_EMPTY__); }
            QCheckBox::indicator:checked { image:url(__CHECKBOX_CHECKED__); }
            #watchDialog { background: #f2f5f8; }
            #vendorPanel, #productPanel { background: #ffffff; border: 1px solid #d8e1e8; border-radius: 10px; }
            #vendorPanelCount, #productPanelCount { color: #0b7f83; background: #e4f6f4; border: 1px solid #bee7e3; border-radius: 10px; padding: 3px 9px; }
            #catalogStatus { color: #3f6470; background: #e8f5f4; border: 1px solid #c5e6e3; border-radius: 6px; padding: 8px 12px; }
            #vendorPanelList, #productPanelList, #filterProductList { background: #f8fafb; border: 1px solid #e1e7ec; }
            #vendorPanelList::item, #productPanelList::item, #filterProductList::item { background: #ffffff; border: 1px solid #e5eaee; border-radius: 5px; margin: 3px; padding: 10px; }
            #filterProductList::item { padding: 0; }
            #vendorPanelList::item:selected, #productPanelList::item:selected, #filterProductList::item:selected { background: #ddf2f0; border-color: #8dd5d0; color: #14343b; }
            #addButton { color: #ffffff; background: #148f94; border: 1px solid #148f94; font-weight: 700; }
            #addButton:hover { background: #0e7c81; color: #ffffff; }
            """
        self.setStyleSheet(
            style.replace("__CHECKBOX_EMPTY__", checkbox_empty).replace(
                "__CHECKBOX_CHECKED__", checkbox_checked
            )
        )

    def load_rows(self) -> None:
        with core.db() as conn:
            rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY published DESC, score DESC").fetchall()
            watched_relations = conn.execute(
                "SELECT vendor_name,product_name FROM watch_vendor_products ORDER BY vendor_name,product_name"
            ).fetchall()
        self.watched_product_names = {row["product_name"] for row in watched_relations}
        self.watched_vendor_products = {}
        for relation in watched_relations:
            self.watched_vendor_products.setdefault(relation["vendor_name"], set()).add(
                relation["product_name"]
            )
        loaded = [core.row_to_dict(row) for row in rows]
        # Applicability is essential in a product watchlist. Keep incomplete NVD
        # records in the database, but do not show them until vendor and product
        # identification are both available.
        self.rows = [row for row in loaded if row["vendors"] and row["products"]]
        for row in self.rows:
            prepare_row_watch_display(row, self.watched_vendor_products)
        self.scope_filter_selection = {
            vendor: set(products) & self.watched_vendor_products.get(vendor, set())
            for vendor, products in self.scope_filter_selection.items()
            if set(products) & self.watched_vendor_products.get(vendor, set())
        }
        self.update_scope_filter_text()
        today = QDate.currentDate()
        if self.archive_only:
            # Archived records are strictly the 31st through 90th day before
            # today. Keep the calendar inside that retention window even when
            # some dates currently contain no vulnerability records.
            self.available_date_min = today.addDays(-90)
            self.available_date_max = today.addDays(-31)
            self.filter_end_date = self.available_date_max
            self.filter_start_date = self.available_date_min
        else:
            # The recent window is clock-driven, never based on the newest CVE
            # currently stored. This keeps "today" available on quiet days.
            self.available_date_min = today.addDays(-30)
            self.available_date_max = today
            self.filter_end_date = self.available_date_max
            self.filter_start_date = self.available_date_min
        self.date_filter.setText(
            "日期範圍：自訂日期" if self.archive_only else "日期範圍：最近 30 天"
        )
        archive_count = sum(bool(row.get("archived")) for row in self.rows)
        self.count_label.setToolTip(f"本機另有 {archive_count} 筆歸檔紀錄（31–90 天）")
        self.apply_filters()

    def apply_filters(self) -> None:
        query = self.search.text()
        start = self.filter_start_date.toString("yyyy-MM-dd")
        end = self.filter_end_date.toString("yyyy-MM-dd")
        selected_risks = set(self.risk_filter.selected)
        result = []
        for row in self.rows:
            if bool(row.get("archived")) != self.archive_only:
                continue
            if not bool(row.get("translation_ready")):
                continue
            categories = row.get("_product_categories", [])
            visible_vendors = row.get("_visible_vendors", [])
            # A saved NVD record can contain several unrelated CPE vendors.  The
            # result list is watchlist-driven, so never expose a row that no
            # longer matches one of the selected vendor/product relationships.
            if not visible_vendors:
                continue
            if query and not title_search_matches(query, row.get("_search_fields", [])):
                continue
            if selected_risks and row["severity"] not in selected_risks:
                continue
            if not (start <= row["published"] <= end):
                continue
            if self.scope_filter_selection:
                scope_match = any(
                    any(filter_name_matches(vendor, visible) for visible in visible_vendors)
                    and any(
                        filter_name_matches(selected_product, candidate)
                        for selected_product in selected_products
                        for candidate in [
                            *row.get("_visible_product_families", []),
                            *categories,
                            *row["products"],
                        ]
                    )
                    for vendor, selected_products in self.scope_filter_selection.items()
                )
                if not scope_match:
                    continue
            result.append(row)
        self.filtered_rows = result
        self.render_table()

    def render_table(self) -> None:
        severity_rank = {"低": 1, "中": 2, "高": 3, "嚴重": 4}
        colors = {"嚴重": QColor("#fde8ed"), "高": QColor("#fbeee7"), "中": QColor("#fff3d8"), "低": QColor("#e7f3f8")}
        risk_colors = {"嚴重": QColor("#e4002b"), "高": QColor("#c85b43"), "中": QColor("#ae700d"), "低": QColor("#247d9e")}
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.filtered_rows))
        for row_index, row in enumerate(self.filtered_rows):
            visible_products = row.get("_visible_products", [])
            visible_vendors = row.get("_visible_vendors", [])
            visible_families = row.get("_visible_product_families", [])
            product_text = "、".join(visible_families) if visible_families else "-"
            if len(visible_products) > 1 and visible_families:
                product_text = f"{product_text} 等{len(visible_products)}項"
            values = [
                SortItem(row["published"]),
                SortItem(row["cve_id"]),
                SortItem(f"●  {row['severity']}", severity_rank.get(row["severity"], 0)),
                SortItem("-" if row["score"] is None else f"{row['score']:.1f}", row["score"] or -1),
                SortItem(vendor_summary(visible_vendors, row.get("vendors", []))),
                SortItem(product_text),
                SortItem(
                    (row.get("title_en") if self.show_title_english else row.get("title_zh"))
                    or row.get("title_en")
                    or row["cve_id"]
                ),
            ]
            for column, item in enumerate(values):
                item.setData(Qt.ItemDataRole.UserRole, row["cve_id"])
                item.setBackground(colors.get(row["severity"], QColor("white")))
                if column == 1:
                    item.setForeground(QColor("#087b88"))
                    item.setFont(QFont(self.font().family(), 10, QFont.Weight.Bold))
                if column == 2:
                    item.setForeground(risk_colors.get(row["severity"], QColor("#333")))
                    item.setFont(QFont(self.font().family(), 10, QFont.Weight.Bold))
                if column == 3:
                    item.setForeground(risk_colors.get(row["severity"], QColor("#333")))
                    item.setFont(QFont(self.font().family(), 11, QFont.Weight.Bold))
                if column == 4:
                    item.setToolTip(vendor_tooltip(row.get("vendors", [])))
                if column == 5:
                    item.setToolTip(product_tooltip(visible_products))
                if column == 6:
                    item.setToolTip(
                        (row.get("title_en") if self.show_title_english else row.get("title_zh"))
                        or row.get("title_en")
                        or row["cve_id"]
                    )
                self.table.setItem(row_index, column, item)
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.SortOrder.DescendingOrder)
        self.update_result_count()

    def update_result_count(self) -> None:
        total = len(self.filtered_rows)
        selected = len(self.table.selectionModel().selectedRows(0))
        selection_active = selected > 0
        self.count_label.setText(
            f"已選 {selected} 項／共 {total} 項"
            if selection_active
            else f"{total} 項漏洞"
        )
        if self.count_label.property("selectionActive") != selection_active:
            self.count_label.setProperty("selectionActive", selection_active)
            self.count_label.style().unpolish(self.count_label)
            self.count_label.style().polish(self.count_label)
            self.count_label.update()

    def show_selected_detail(
        self,
        item: QTableWidgetItem | None = None,
        _previous: QTableWidgetItem | None = None,
    ) -> None:
        if item is None:
            item = self.table.currentItem()
        if item is None:
            selected_rows = self.table.selectionModel().selectedRows(0)
            item = self.table.item(selected_rows[0].row(), 0) if selected_rows else None
        if item is None:
            return
        cve_id = item.data(Qt.ItemDataRole.UserRole)
        self.selected = next((row for row in self.rows if row["cve_id"] == cve_id), None)
        self.show_english = False
        self.language_btn.setText("EN　原文顯示")
        self.render_detail()
        # Give the detail pane enough room immediately after a result is chosen.
        total = max(sum(self.results_splitter.sizes()), 700)
        self.results_splitter.setSizes([max(250, int(total * 0.38)), max(420, int(total * 0.62))])
        QTimer.singleShot(0, self.reset_detail_scroll)

    def selected_cve_ids(self) -> list[str]:
        """Return selected CVEs in their current visual order."""
        selected_rows = sorted(
            self.table.selectionModel().selectedRows(0), key=lambda index: index.row()
        )
        result: list[str] = []
        for index in selected_rows:
            item = self.table.item(index.row(), 0)
            cve_id = str(item.data(Qt.ItemDataRole.UserRole) or "") if item else ""
            if cve_id and cve_id not in result:
                result.append(cve_id)
        return result

    def restore_selected_cve_ids(self, cve_ids: list[str]) -> None:
        wanted = set(cve_ids)
        if not wanted:
            return
        selection = self.table.selectionModel()
        for row_index in range(self.table.rowCount()):
            item = self.table.item(row_index, 0)
            if item and str(item.data(Qt.ItemDataRole.UserRole) or "") in wanted:
                selection.select(
                    self.table.model().index(row_index, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )

    def select_all_visible_rows(self) -> None:
        """Select the visible result set unless the user is editing search text."""
        focused = QApplication.focusWidget()
        if isinstance(focused, QLineEdit):
            focused.selectAll()
            return
        if self.table.rowCount() <= 0:
            return
        self.table.selectAll()
        self.table.setFocus(Qt.FocusReason.ShortcutFocusReason)

    def eventFilter(self, watched, event) -> bool:  # type: ignore[no-untyped-def]
        if QApplication.activeWindow() is self:
            if (
                event.type() == QEvent.Type.KeyPress
                and event.key() == Qt.Key.Key_A
                and event.modifiers() == Qt.KeyboardModifier.ControlModifier
            ):
                focused = QApplication.focusWidget()
                if isinstance(focused, QLineEdit):
                    return False
                self.select_all_visible_rows()
                return True
            if (
                event.type() == QEvent.Type.MouseButtonPress
                and isinstance(watched, QWidget)
                and not getattr(self, "_result_context_menu_open", False)
            ):
                clicked_in_table = watched is self.table or self.table.isAncestorOf(watched)
                if not clicked_in_table and self.table.selectionModel().hasSelection():
                    self.table.clearSelection()
        return super().eventFilter(watched, event)

    def closeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        application = QApplication.instance()
        if application is not None:
            application.removeEventFilter(self)
        super().closeEvent(event)

    def open_result_context_menu(self, position: QPoint) -> None:
        item = self.table.itemAt(position)
        if item is None:
            return
        if not item.isSelected():
            self.table.clearSelection()
            self.table.setCurrentCell(item.row(), item.column())
            self.table.selectRow(item.row())
        selected_for_export = self.selected_cve_ids()
        menu = QMenu(self.table)
        menu.setStyleSheet(
            """
            QMenu {
                background: #ffffff;
                border: 1px solid #ccd6e1;
                border-radius: 6px;
                padding: 2px;
            }
            QMenu::item {
                padding: 6px 0 6px 7px;
                color: #243548;
                border-radius: 5px;
            }
            QMenu::item:selected {
                background: #edf5ff;
                color: #243548;
            }
            QMenu::icon {
                position: relative;
                left: 10px;
            }
            """
        )
        export_action = menu.addAction(make_export_triangle_icon(), "匯出為CSV檔")
        self._result_context_menu_open = True
        try:
            chosen = menu.exec(self.table.viewport().mapToGlobal(position))
        finally:
            self._result_context_menu_open = False
        if chosen == export_action:
            self.export_selected_csv(selected_for_export)

    def export_selected_csv(self, cve_ids: list[str] | None = None) -> None:
        if cve_ids is None:
            cve_ids = self.selected_cve_ids()
        cve_ids = list(dict.fromkeys(str(cve_id) for cve_id in cve_ids if cve_id))
        if not cve_ids:
            QMessageBox.information(
                self, "未選取漏洞", "請先選擇需要匯出的漏洞紀錄"
            )
            return
        rows_by_id = {str(row["cve_id"]): row for row in self.rows}
        missing_ids = [cve_id for cve_id in cve_ids if cve_id not in rows_by_id]
        if missing_ids:
            QMessageBox.warning(
                self,
                "漏洞資料已更新",
                "選取的漏洞資料已經更新，請重新選擇後再匯出",
            )
            return
        export_rows = [rows_by_id[cve_id] for cve_id in cve_ids if cve_id in rows_by_id]
        if not export_rows:
            QMessageBox.warning(self, "匯出失敗", "找不到可匯出的漏洞資料")
            return
        suggested_name = f"VulHub_export_{datetime.now():%Y%m%d_%H%M}.csv"
        filename, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "匯出為CSV",
            suggested_name,
            "CSV 檔案 (*.csv)",
        )
        if not filename:
            return
        if not filename.lower().endswith(".csv"):
            filename += ".csv"
        target_path = Path(filename)
        try:
            write_vulnerability_csv(
                target_path,
                export_rows,
                english=bool(getattr(self, "show_title_english", False)),
            )
        except (OSError, csv.Error, UnicodeError, ValueError) as exc:
            QMessageBox.warning(self, "匯出失敗", f"無法儲存CSV檔案：{exc}")
            return
        QMessageBox.information(
            self, "匯出完成", f"已匯出 {len(export_rows)} 筆漏洞資料"
        )

    def reset_detail_scroll(self) -> None:
        self.detail.verticalScrollBar().setValue(0)

    def render_detail(self) -> None:
        if not self.selected:
            self.detail.setHtml(self.empty_detail_html())
            return
        row = self.selected
        visible_vendors = row.get("_visible_vendors", [])
        title = row.get("title_en") if self.show_english else row.get("title_zh") or row.get("title_en")
        description = row.get("description_en") if self.show_english else row.get("description_zh") or row.get("description_en")
        description_text = (description or "NVD 尚未提供描述").rstrip().rstrip("。.").rstrip()
        affected = row["affected_versions"] or row["products"]
        versions = "".join(
            f"<tr><td>{html.escape(x)}</td></tr>" for x in sorted(affected, key=core.natural_key)
        )
        references = "".join(
            f"<tr><td><a href='{html.escape(url)}'>↗ {html.escape(url)}</a></td></tr>"
            for url in row["references"][:10]
        ) or "<tr><td>尚未提供官方公告</td></tr>"
        risk_color = {"嚴重": "#e4002b", "高": "#c85b43", "中": "#ae700d", "低": "#247d9e"}.get(row["severity"], "#33465a")
        self.detail.setHtml(
            f"""
            <style>
              body {{ font-family:'Microsoft JhengHei UI','Segoe UI'; color:#415367; font-size:13px; font-weight:400; line-height:1.65; background:#ffffff; }}
              .eyebrow {{ font-size:13px; font-weight:600; }}
              .severity, .cve {{ color:#087d88; font-size:13px; font-weight:600; }}
              .separator {{ color:#91a0ad; }}
              .title {{ color:#14283a; font-size:18px; font-weight:600; margin-top:5px; }}
              table {{ width:100%; border-collapse:collapse; margin:0 0 8px; }}
              td {{ border-bottom:1px solid #e1e7ec; padding:11px 14px; font-size:15px; }} td span {{ color:#7a8999; font-size:13px; }}
              .summary {{ background:#ffffff; border-left:4px solid #169b9c; }}
              .summary td {{ padding:7px 14px 7px; border:none; }}
              .summary .title {{ margin:2px 0 3px; }}
              .meta-grid {{ width:400px; margin:6px 0 0; border-bottom:1px solid #e1e7ec; }}
              .meta-grid td {{ border:none; padding:1px 18px 6px 0; white-space:nowrap; color:#192d42; }}
              .meta-grid td span {{ color:#98a5b3; font-size:9px; font-weight:400; }}
              .meta-grid .meta-value {{ color:#192d42; font-size:13px; font-weight:600; }}
              h3 {{ font-size:14px; color:#14283a; padding-left:7px; margin-top:10px; margin-bottom:4px; }}
              .content-table {{ width:100%; margin:8px 0 3px; border:none; }}
              .content-table td {{ border:none; padding:1px 0 1px 14px; color:#33495f; font-family:'Microsoft JhengHei UI'; font-size:13px; font-weight:400; line-height:1.65; }}
              .version-table td {{ color:#33495f; }}
              .repair-table {{ margin-bottom:0; }}
              a {{ color:#07839a; font-size:13px; font-weight:400; text-decoration:none; }}
            </style>
            <table class='summary' cellspacing='0' cellpadding='0'><tr><td>
              <div class='eyebrow'><span class='severity'>{html.escape(row['severity'])}風險</span><span class='separator'>　／　</span><span class='cve'>{html.escape(row['cve_id'])}</span></div>
              <div class='title'>{html.escape(title or row['cve_id'])}</div>
              <table class='meta-grid' cellspacing='0' cellpadding='0'><tr>
                <td><span>發佈日期</span><br><span class='meta-value'>{html.escape(row['published'])}</span></td>
                <td><span>風險等級</span><br><span class='meta-value' style='color:{risk_color}'>{html.escape(row['severity'])}</span></td>
                <td><span>CVSS 3.1 分數</span><br><span class='meta-value' style='color:{risk_color}'>{row['score'] if row['score'] is not None else '-'}</span></td>
                <td><span>廠商名稱</span><br><span class='meta-value'>{html.escape('、'.join(sorted(set(row.get('vendors', [])), key=core.natural_key)) or '-')}</span></td>
              </tr></table>
            </td></tr></table>
            <h3>▌ 漏洞描述</h3><table class='content-table'><tr><td>{html.escape(description_text)}</td></tr></table>
            <h3>▌ 受影響版本</h3><table class='content-table version-table'>{versions}</table>
            <h3>▌ 修復資訊及官方公告</h3><table class='content-table repair-table'><tr><td>請查閱官方公告或供應商修復指引</td></tr>{references}</table>
            """
        )
        QTimer.singleShot(0, self.reset_detail_scroll)

    @staticmethod
    def empty_detail_html() -> str:
        return "<div style='text-align:center;color:#7e8d9d;padding:48px'><h2 style='color:#35475a'>選擇一項漏洞</h2><p>詳細描述、受影響版本與官方公告會顯示在這裡</p></div>"

    def toggle_language(self) -> None:
        if not self.selected:
            return
        self.show_english = not self.show_english
        self.language_btn.setText("中　中文顯示" if self.show_english else "EN　原文顯示")
        self.render_detail()

    def toggle_search_title_language(self) -> None:
        self.show_title_english = not self.show_title_english
        self.title_language_btn.setText("中　中文名稱" if self.show_title_english else "EN　英文名稱")
        self.render_table()

    def open_scope_filter(self) -> None:
        dialog = VendorProductFilterDialog(
            self.watched_vendor_products,
            self.scope_filter_selection,
            self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.scope_filter_selection = dialog.selections()
            self.update_scope_filter_text()
            self.apply_filters()

    def update_scope_filter_text(self) -> None:
        vendors = sum(bool(products) for products in self.scope_filter_selection.values())
        products = sum(len(values) for values in self.scope_filter_selection.values())
        self.scope_filter.setText(
            f"廠商及產品：已選 {vendors} 間廠商 · {products} 項產品"
            if products
            else "廠商及產品：全部關注項目"
        )

    def open_archive_window(self) -> None:
        if self.archive_only:
            return
        if self.archive_window is None:
            self.archive_window = VulHubWindow(archive_only=True)
            self.archive_window.destroyed.connect(
                lambda *_args: setattr(self, "archive_window", None)
            )
        self.archive_window.show()
        self.archive_window.raise_()
        self.archive_window.activateWindow()

    def set_recent_days(self, days: int) -> None:
        self.filter_end_date = self.available_date_max
        self.filter_start_date = max(
            self.available_date_min,
            self.filter_end_date.addDays(-days),
        )
        self.date_filter.setText(f"日期範圍：最近 {days} 天")
        self.apply_filters()

    def open_custom_date_range(self) -> None:
        if not any(bool(row.get("archived")) == self.archive_only for row in self.rows):
            QMessageBox.information(self, "沒有可選日期", "目前沒有漏洞紀錄可供篩選")
            return
        start = max(self.available_date_min, min(self.filter_start_date, self.available_date_max))
        end = max(start, min(self.filter_end_date, self.available_date_max))
        if not self.archive_only:
            end = min(end, start.addDays(30))
        dialog = DateRangeDialog(
            self.available_date_min,
            self.available_date_max,
            start,
            end,
            show_boundary_months=self.archive_only,
            max_span_days=None if self.archive_only else 31,
            parent=self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.filter_start_date, self.filter_end_date = dialog.dates()
            self.date_filter.setText(
                f"日期範圍：{self.filter_start_date.toString('yyyy-MM-dd')} - "
                f"{self.filter_end_date.toString('yyyy-MM-dd')}"
            )
            self.apply_filters()

    def clear_filters(self) -> None:
        self.search.clear()
        self.scope_filter_selection.clear()
        self.update_scope_filter_text()
        self.risk_filter.clear_selection()
        if self.archive_only:
            self.filter_end_date = self.available_date_max
            self.filter_start_date = self.available_date_min
            self.date_filter.setText("日期範圍：自訂日期")
            self.apply_filters()
        else:
            self.set_recent_days(30)

    def refresh_api_status(self) -> None:
        # The archive page intentionally shows a static status label with no
        # API-key function.  This method is also called for every open window
        # after the main-page API dialog closes, so guard the archive window
        # here instead of relying only on its constructor configuration.
        if self.archive_only:
            self.api_status.setTextFormat(Qt.TextFormat.PlainText)
            self.api_status.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
            self.api_status.setText("●  NVD API 2.0")
            self.api_status.setToolTip("")
            return
        if core.has_nvd_api_key():
            label = "●&nbsp;&nbsp;NVD API 2.0&nbsp;&nbsp;｜&nbsp;&nbsp;已啟用"
            tooltip = "API Key已啟用，點擊查看、清除或重新輸入"
        else:
            label = "●&nbsp;&nbsp;NVD API 2.0"
            tooltip = "點擊設定API Key"
        self.api_status.setText(
            f"<a href='nvd-api-key' style='color:#78d8bd;text-decoration:none'>{label}</a>"
        )
        self.api_status.setToolTip(tooltip)

    def open_nvd_api_key_dialog(self) -> None:
        with core.update_lock:
            update_running = bool(core.update_state["running"])
        with core.catalog_lock:
            catalog_running = bool(core.catalog_state["running"])
        if update_running or catalog_running:
            QMessageBox.information(
                self,
                "暫時無法設定 API Key",
                "NVD 資料正在更新，請等待更新完成後再設定 API Key",
            )
            return
        NvdApiKeyDialog(self).exec()
        for window in QApplication.topLevelWidgets():
            if isinstance(window, VulHubWindow):
                window.refresh_api_status()

    def refresh_now(self) -> None:
        with core.catalog_lock:
            catalog_running = bool(core.catalog_state["running"])
        if catalog_running:
            QMessageBox.information(
                self,
                "產品名單正在更新",
                "請等待產品名單更新完成後再更新漏洞列表",
            )
            return
        started = core.start_update(30)
        with core.update_lock:
            already_running = bool(core.update_state["running"])
        if started or already_running:
            self.progress_frame.show()
            self.refresh_btn.setEnabled(False)
            self.update_timer.start(900)

    def hide_progress_if_idle(self) -> None:
        """Do not hide either an active NVD update or translation progress."""
        with core.update_lock:
            running = bool(core.update_state["running"])
        with core.translation_lock:
            translating = bool(core.translation_state["pending"])
        if not running and not translating:
            self.progress_frame.hide()

    def poll_update(self) -> None:
        with core.update_lock:
            state = dict(core.update_state)
        if state["running"]:
            self.progress.setRange(0, 100)
        self.progress.setValue(int(state["progress"]))
        self.progress_message.setText(str(state.get("error") or state["message"]))
        self.refresh_btn.setEnabled(not state["running"])
        if not state["running"]:
            self.load_rows()
            if self.archive_window is not None:
                self.archive_window.load_rows()
            self.update_timer.stop()
            if state.get("error"):
                QMessageBox.warning(self, "漏洞更新未完成", str(state["error"]))
            # Product-list synchronisation is intentionally manual.  The
            # bundled index is ready at startup, so an automatic CPE request
            # here would cause an unrelated "同步未完成" warning on every
            # launch when NVD throttles anonymous access.
            if not state.get("error"):
                QTimer.singleShot(4500, self.hide_progress_if_idle)

    def poll_translations(self) -> None:
        with core.translation_lock:
            state = dict(core.translation_state)
        pending = int(state["pending"])
        with core.update_lock:
            update_running = bool(core.update_state["running"])
        completed_count, total_count = core.translation_progress_counts()
        if total_count and not update_running:
            self.progress.setRange(0, total_count)
            self.progress.setValue(completed_count)
            if pending:
                retry_after = state.get("retry_after")
                if state.get("last_error") and retry_after:
                    message = (
                        f"中文翻譯服務暫時無法連線，{retry_after} 秒後自動重試 "
                        f"{completed_count}/{total_count}"
                    )
                else:
                    message = f"正在翻譯漏洞資料 {completed_count}/{total_count}"
                self.progress_message.setText(message)
                self.progress_frame.show()
        completed = int(state["completed"])
        newly_completed = completed - self.last_translation_completed
        if newly_completed <= 0:
            return
        selected_cve = self.selected.get("cve_id") if self.selected else None
        selected_cve_ids = self.selected_cve_ids()
        self.last_translation_completed = completed
        self.load_rows()
        self.restore_selected_cve_ids(selected_cve_ids)
        if selected_cve:
            refreshed = next((row for row in self.rows if row["cve_id"] == selected_cve), None)
            if refreshed:
                self.selected = refreshed
                self.render_detail()
        if not pending and not update_running and completed_count >= total_count:
            self.progress_message.setText(f"中文翻譯完成 {completed_count}/{total_count}")
            self.progress_frame.show()
            QTimer.singleShot(1800, self.hide_progress_if_idle)

    def open_watchlist(self) -> None:
        with core.update_lock:
            update_running = bool(core.update_state["running"])
        if update_running:
            QMessageBox.information(
                self,
                "暫時無法使用關注名單",
                "漏洞列表正在更新，請等待更新完成後再開啟關注名單功能",
            )
            return
        dialog = WatchlistDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Reset both the recent and archive windows. Filters created for
            # the previous watchlist can otherwise hide every newly added
            # vendor/product result in either view.
            windows = [
                window
                for window in QApplication.topLevelWidgets()
                if isinstance(window, VulHubWindow)
            ]
            for window in windows:
                window.search.blockSignals(True)
                window.search.clear()
                window.search.blockSignals(False)
                window.scope_filter_selection.clear()
                window.risk_filter.clear_selection()
                window.load_rows()
            updater = next((window for window in windows if not window.archive_only), self)
            updater.refresh_now()


def main() -> int:
    application = QApplication(sys.argv)
    # Do not wrap QApplication's currently owned style object directly.
    # QApplication.setStyle() disposes the previous application style; using
    # that same object as the proxy base leaves a dangling native pointer and
    # can crash python.exe/VulHub.exe while Qt is shutting down.
    application.setStyle(NoButtonFocusRectStyle())
    application.setApplicationName("VulHub")
    application.setOrganizationName("VulHub")
    application.setFont(QFont("Microsoft JhengHei UI", 9))
    app_icon = make_app_icon()
    application.setWindowIcon(app_icon)
    window = VulHubWindow()
    window.show()
    window.winId()  # Ensure the native Windows handle exists before reapplying.
    window.setWindowIcon(app_icon)
    QTimer.singleShot(100, lambda: window.setWindowIcon(app_icon))
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
