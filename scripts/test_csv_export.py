"""Regression tests for the selected-vulnerability CSV export workflow."""

from __future__ import annotations

import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import patch


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import desktop  # noqa: E402
from PySide6.QtCore import QItemSelectionModel, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem  # noqa: E402


def sample_row(cve_id: str = "CVE-2099-1234") -> dict:
    return {
        "published": "2099-08-17",
        "cve_id": cve_id,
        "severity": "高",
        "score": 8.8,
        "_visible_vendors": ["Red Hat", "Microsoft", "Microsoft"],
        "_visible_products": ["Windows 11", "Windows 10", "Windows 10"],
        "title_zh": "=WEBSERVICE(\"https://unsafe.test\")",
        "title_en": "English title",
        "description_zh": "第一\x00行，包含逗號\n第二行",
        "description_en": "English description",
        "affected_versions": ["Windows 11 24H2", "Windows 10 22H2"],
        "products": [],
        "references": [
            "https://example.test/advisory",
            "https://example.test/advisory",
            "https://example.test/fix",
        ],
    }


class CsvExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_excel_compatible_content_and_formula_protection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "export.csv"
            desktop.write_vulnerability_csv(target, [sample_row()])
            self.assertTrue(target.read_bytes().startswith(b"\xef\xbb\xbf"))
            with target.open("r", encoding="utf-8-sig", newline="") as source:
                records = list(csv.reader(source))

        self.assertEqual(tuple(records[0]), desktop.CSV_EXPORT_HEADERS)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1][0:4], ["2099-08-17", "CVE-2099-1234", "高", "8.8"])
        self.assertEqual(records[1][4], "Microsoft\nRed Hat")
        self.assertEqual(records[1][5], "Windows 10\nWindows 11")
        self.assertTrue(records[1][6].startswith("'="))
        self.assertEqual(records[1][7], "第一行，包含逗號\n第二行")
        self.assertEqual(records[1][8], "Windows 10 22H2\nWindows 11 24H2")
        self.assertEqual(
            records[1][9],
            "https://example.test/advisory\nhttps://example.test/fix",
        )

    def test_failed_atomic_replace_keeps_existing_file_and_cleans_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.csv"
            target.write_text("original", encoding="utf-8")
            with patch.object(Path, "replace", side_effect=OSError("locked")):
                with self.assertRaises(OSError):
                    desktop.write_vulnerability_csv(target, [sample_row()])
            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(Path(directory).glob(".existing.csv.*.tmp")), [])

    def test_english_display_exports_english_headers_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "english.csv"
            desktop.write_vulnerability_csv(target, [sample_row()], english=True)
            with target.open("r", encoding="utf-8-sig", newline="") as source:
                records = list(csv.reader(source))

        self.assertEqual(tuple(records[0]), desktop.CSV_EXPORT_HEADERS_EN)
        self.assertEqual(records[1][2], "High")
        self.assertEqual(records[1][6], "English title")
        self.assertEqual(records[1][7], "English description")
        self.assertNotIn("第一行", "\n".join(records[1]))

    def test_export_dialog_follows_current_title_language(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "selected-language.csv"
            fake_window = SimpleNamespace(
                rows=[sample_row()],
                show_title_english=True,
            )
            with (
                patch.object(
                    desktop.QFileDialog,
                    "getSaveFileName",
                    return_value=(str(target), "CSV 檔案 (*.csv)"),
                ),
                patch.object(desktop.QMessageBox, "information"),
                patch.object(desktop.QMessageBox, "warning") as warning,
            ):
                desktop.VulHubWindow.export_selected_csv(
                    fake_window,
                    ["CVE-2099-1234"],
                )
            with target.open("r", encoding="utf-8-sig", newline="") as source:
                records = list(csv.reader(source))

        self.assertEqual(tuple(records[0]), desktop.CSV_EXPORT_HEADERS_EN)
        self.assertEqual(records[1][6:8], ["English title", "English description"])
        warning.assert_not_called()

    def test_dialog_filename_extension_deduplication_and_success_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_without_extension = str(Path(directory) / "chosen_name")
            fake_window = SimpleNamespace(rows=[sample_row()])
            with (
                patch.object(
                    desktop.QFileDialog,
                    "getSaveFileName",
                    return_value=(target_without_extension, "CSV 檔案 (*.csv)"),
                ) as save_dialog,
                patch.object(desktop.QMessageBox, "information") as information,
                patch.object(desktop.QMessageBox, "warning") as warning,
            ):
                desktop.VulHubWindow.export_selected_csv(
                    fake_window,
                    ["CVE-2099-1234", "CVE-2099-1234"],
                )

            suggested_name = save_dialog.call_args.args[2]
            self.assertRegex(
                suggested_name,
                r"^VulHub_export_\d{8}_\d{4}\.csv$",
            )
            target = Path(target_without_extension + ".csv")
            self.assertTrue(target.exists())
            with target.open("r", encoding="utf-8-sig", newline="") as source:
                self.assertEqual(len(list(csv.reader(source))), 2)
            information.assert_called_once()
            warning.assert_not_called()

    def test_cancel_and_stale_selection_do_not_create_unexpected_export(self) -> None:
        fake_window = SimpleNamespace(rows=[sample_row()])
        with (
            patch.object(
                desktop.QFileDialog,
                "getSaveFileName",
                return_value=("", ""),
            ),
            patch.object(desktop.QMessageBox, "information") as information,
            patch.object(desktop.QMessageBox, "warning") as warning,
        ):
            desktop.VulHubWindow.export_selected_csv(
                fake_window, ["CVE-2099-1234"]
            )
            information.assert_not_called()
            warning.assert_not_called()

            desktop.VulHubWindow.export_selected_csv(fake_window, ["CVE-2099-MISSING"])
            warning.assert_called_once()

    def test_context_menu_click_exports_the_preserved_multi_selection(self) -> None:
        table = QTableWidget(2, 1)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        for row_index, cve_id in enumerate(("CVE-2099-0001", "CVE-2099-0002")):
            item = QTableWidgetItem(cve_id)
            item.setData(Qt.ItemDataRole.UserRole, cve_id)
            table.setItem(row_index, 0, item)
        table.resize(320, 120)
        table.show()
        self.application.processEvents()
        selection = table.selectionModel()
        for row_index in range(2):
            selection.select(
                table.model().index(row_index, 0),
                QItemSelectionModel.SelectionFlag.Select
                | QItemSelectionModel.SelectionFlag.Rows,
            )

        exported: list[list[str]] = []
        fake_window = SimpleNamespace(table=table)
        fake_window.selected_cve_ids = MethodType(
            desktop.VulHubWindow.selected_cve_ids, fake_window
        )
        fake_window.export_selected_csv = lambda cve_ids: exported.append(cve_ids)

        class FakeAction:
            def __init__(self, text):
                self.text = text

        class FakeMenu:
            def __init__(self, _parent):
                self.action = None

            def setStyleSheet(self, _style):
                return None

            def addAction(self, _icon, text):
                self.action = FakeAction(text)
                return self.action

            def exec(self, _position):
                self.assertion()
                return self.action

            def assertion(self):
                self_outer.assertEqual(self.action.text, "匯出為CSV檔")

        position = table.visualItemRect(table.item(0, 0)).center()
        self_outer = self
        with patch.object(desktop, "QMenu", FakeMenu):
            desktop.VulHubWindow.open_result_context_menu(fake_window, position)

        self.assertEqual(exported, [["CVE-2099-0001", "CVE-2099-0002"]])
        self.assertFalse(fake_window._result_context_menu_open)


if __name__ == "__main__":
    unittest.main(verbosity=2)
