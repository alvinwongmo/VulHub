"""Pre-production regression coverage for VulHub core and desktop helpers.

Every test uses a disposable database and mocked HTTP responses.  The user's
production ``vulhub.db`` and saved API key are never read or modified.
"""

from __future__ import annotations

import gzip
import json
import os
import queue
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402
import desktop  # noqa: E402
from PySide6.QtCore import QDate, QItemSelectionModel, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QToolButton  # noqa: E402


class AppIconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_native_multiresolution_icon_is_available(self) -> None:
        self.assertTrue(desktop.APP_ICON_PATH.is_file())
        icon = desktop.make_app_icon()
        self.assertFalse(icon.isNull())
        sizes = {(size.width(), size.height()) for size in icon.availableSizes()}
        self.assertTrue({(16, 16), (32, 32), (256, 256)}.issubset(sizes))


class DisposableDatabaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = app.DB_PATH
        self.original_snapshot = app.CATALOG_SNAPSHOT_PATH
        self.original_key = app._nvd_api_key
        self.original_key_initialized = app._nvd_api_key_initialized
        app.DB_PATH = Path(self.temp_dir.name) / "test.db"
        app.CATALOG_SNAPSHOT_PATH = Path(self.temp_dir.name) / "missing.json.gz"
        app._nvd_api_key = ""
        app._nvd_api_key_initialized = True
        app.translation_queue = queue.Queue()
        app.translation_queued_keys.clear()
        app.translation_thread = None
        app.init_db()

    def tearDown(self) -> None:
        app.translation_queue.join()
        app.DB_PATH = self.original_db
        app.CATALOG_SNAPSHOT_PATH = self.original_snapshot
        app._nvd_api_key = self.original_key
        app._nvd_api_key_initialized = self.original_key_initialized
        self.temp_dir.cleanup()


class TextAndMatchingTests(unittest.TestCase):
    def test_normalization_ignores_case_spacing_width_and_punctuation(self) -> None:
        expected = app.normalize("Check Point")
        for value in ("checkpoint", "CHECK point", "Ｃｈｅｃｋ－Ｐｏｉｎｔ", "check_point"):
            self.assertEqual(app.normalize(value), expected)

    def test_natural_version_order(self) -> None:
        values = ["8.10", "8.3", "8.2", "9", "10"]
        self.assertEqual(sorted(values, key=app.natural_key), ["8.2", "8.3", "8.10", "9", "10"])

    def test_severity_thresholds(self) -> None:
        self.assertEqual(app.severity_zh(None, 10.0), "嚴重")
        self.assertEqual(app.severity_zh(None, 9.0), "嚴重")
        self.assertEqual(app.severity_zh(None, 8.9), "高")
        self.assertEqual(app.severity_zh(None, 7.0), "高")
        self.assertEqual(app.severity_zh(None, 6.9), "中")
        self.assertEqual(app.severity_zh(None, 4.0), "中")
        self.assertEqual(app.severity_zh(None, 3.9), "低")

    def test_product_family_examples_and_hardware_guard(self) -> None:
        cases = {
            "Microsoft Windows 11 23H2": "Microsoft Windows 11",
            "Red Hat Enterprise Linux 8.6": "Red Hat Enterprise Linux",
            "Palo Alto Networks PAN-OS 11.1.4": "Palo Alto Networks PAN-OS",
            "Check Point Multi-domain Security Management R81.20": "Check Point Multi-domain Security Management",
        }
        for child, parent in cases.items():
            self.assertEqual(app.product_family_name(child), parent)
            self.assertTrue(app.watched_product_matches(parent, child))

        names = {"Palo Alto Networks PA-220", "Palo Alto Networks PA"}
        keys, protected = app.product_family_context(names)
        self.assertEqual(
            app.validated_product_family("Palo Alto Networks PA-220", keys, protected),
            "Palo Alto Networks PA-220",
        )

    def test_similar_product_is_not_a_version_descendant(self) -> None:
        self.assertTrue(app.watched_product_matches("Microsoft Windows 10", "Microsoft Windows 10 22H2"))
        self.assertFalse(app.watched_product_matches("Microsoft Windows 10", "Microsoft Windows 10 Mobile"))
        self.assertFalse(app.watched_product_matches("Microsoft Windows 1", "Microsoft Windows 11"))

    def test_description_fallback_only_when_nvd_has_no_product_identity(self) -> None:
        entries = [("product", "Microsoft Windows 11")]
        self.assertFalse(
            app.record_matches_watchlist(
                ["Acme"], ["Acme Widget"], ["Acme Widget 1.0"],
                "This text mentions Microsoft Windows 11", entries,
            )
        )
        self.assertTrue(
            app.record_matches_watchlist([], [], [], "Issue in Microsoft Windows 11", entries)
        )

    def test_title_search_is_title_only_and_short_terms_do_not_cross_words(self) -> None:
        self.assertTrue(desktop.title_search_matches("redhat", ["Red Hat issue"]))
        self.assertTrue(desktop.title_search_matches("CVE202612345", ["CVE-2026-12345"]))
        self.assertFalse(desktop.title_search_matches("hel", ["The library issue"]))
        self.assertFalse(desktop.title_search_matches("secret body", ["Public title"]))

    def test_watch_display_shows_selected_families_but_preserves_full_versions(self) -> None:
        row = {
            "cve_id": "CVE-2099-0001",
            "title_en": "Issue",
            "title_zh": "問題",
            "products": ["Microsoft Windows 10", "Microsoft Windows 11", "Acme Library"],
            "affected_versions": [
                "Microsoft Windows 10 22H2 * – 10.0.1",
                "Microsoft Windows 11 23H2 * – 10.0.2",
                "Acme Library 1.0",
            ],
        }
        desktop.prepare_row_watch_display(
            row, {"Microsoft": {"Microsoft Windows 10", "Microsoft Windows 11"}}
        )
        self.assertEqual(row["_visible_vendors"], ["Microsoft"])
        self.assertEqual(row["_visible_product_families"], ["Microsoft Windows 10", "Microsoft Windows 11"])
        self.assertEqual(len(row["_visible_products"]), 2)
        self.assertNotIn("Acme Library 1.0", row["_visible_products"])


class DatabaseAndApiTests(DisposableDatabaseTest):
    def _insert_vulnerability(self, cve_id: str, published: str, products: list[str]) -> None:
        with app.db() as conn:
            conn.execute(
                "INSERT INTO vulnerabilities "
                "(cve_id,published,severity,title_en,title_zh,description_en,description_zh,"
                "vendors,products,affected_versions,references_json,translation_ready) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                (
                    cve_id, published, "高", "title", "標題", "description", "描述",
                    json.dumps(["Microsoft"]), json.dumps(products), json.dumps(products), "[]",
                ),
            )

    def test_empty_first_start_has_no_default_watchlist(self) -> None:
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM watch_vendor_products").fetchone()[0], 0)

    def test_bundled_snapshot_import_is_exact_and_idempotent(self) -> None:
        snapshot = {
            "schema_version": 2,
            "source_last_modified": "2099-01-02T03:04:05+00:00",
            "vendors": ["Microsoft", "Red Hat"],
            "products": ["Microsoft Windows 11", "Red Hat Enterprise Linux"],
            "vendor_cpes": [["Microsoft", "microsoft"], ["Red Hat", "redhat"]],
            "product_cpes": [
                ["Microsoft Windows 11", "o", "microsoft", "windows_11"],
                ["Red Hat Enterprise Linux", "o", "redhat", "enterprise_linux"],
            ],
        }
        snapshot_path = Path(self.temp_dir.name) / "snapshot.json.gz"
        with gzip.open(snapshot_path, "wt", encoding="utf-8") as target:
            json.dump(snapshot, target)
        app.CATALOG_SNAPSHOT_PATH = snapshot_path
        with app.db() as conn:
            self.assertTrue(app.import_bundled_catalog(conn))
            self.assertFalse(app.import_bundled_catalog(conn))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='vendor'").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='product'").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM catalog_cpe WHERE kind='product'").fetchone()[0], 2)

    def test_schema_migration_preserves_old_data(self) -> None:
        old_path = Path(self.temp_dir.name) / "old.db"
        app.DB_PATH = old_path
        legacy_conn = sqlite3.connect(old_path)
        try:
            conn = legacy_conn
            conn.executescript(
                "CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY,published TEXT NOT NULL,"
                "modified TEXT,severity TEXT NOT NULL,score REAL,title_en TEXT,title_zh TEXT,"
                "description_en TEXT,description_zh TEXT,vendors TEXT NOT NULL DEFAULT '[]',"
                "products TEXT NOT NULL DEFAULT '[]',affected_versions TEXT NOT NULL DEFAULT '[]',"
                "references_json TEXT NOT NULL DEFAULT '[]',source TEXT NOT NULL DEFAULT 'NVD');"
                "INSERT INTO vulnerabilities(cve_id,published,severity) VALUES ('CVE-2099-OLD','2099-01-01','低');"
            )
            conn.commit()
        finally:
            legacy_conn.close()
        app.init_db()
        with app.db() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(vulnerabilities)")}
            self.assertTrue({"archived", "translation_ready"} <= columns)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM vulnerabilities WHERE cve_id='CVE-2099-OLD'").fetchone())

    def test_retention_boundaries_are_0_30_31_90_and_91_days(self) -> None:
        today = datetime.now().astimezone().date()
        for age in (0, 30, 31, 90, 91):
            self._insert_vulnerability(f"CVE-2099-{age:04d}", (today - timedelta(days=age)).isoformat(), ["Microsoft Windows 11"])
        archived, deleted = app.maintain_vulnerability_retention()
        with app.db() as conn:
            rows = {row["cve_id"]: row["archived"] for row in conn.execute("SELECT cve_id,archived FROM vulnerabilities")}
        self.assertEqual(deleted, 1)
        self.assertEqual(archived, 2)
        self.assertEqual(rows["CVE-2099-0000"], 0)
        self.assertEqual(rows["CVE-2099-0030"], 0)
        self.assertEqual(rows["CVE-2099-0031"], 1)
        self.assertEqual(rows["CVE-2099-0090"], 1)
        self.assertNotIn("CVE-2099-0091", rows)

    def test_purge_removes_only_products_no_longer_watched(self) -> None:
        today = datetime.now().astimezone().date().isoformat()
        self._insert_vulnerability("CVE-2099-KEEP", today, ["Microsoft Windows 11 23H2"])
        self._insert_vulnerability("CVE-2099-DROP", today, ["Acme Widget"])
        self.assertEqual(app.purge_unwatched_vulnerabilities([("product", "Microsoft Windows 11")]), 1)
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT cve_id FROM vulnerabilities").fetchone()[0], "CVE-2099-KEEP")

    def test_api_key_persists_and_clears_only_in_disposable_database(self) -> None:
        app.set_nvd_api_key(" local-test-key ")
        self.assertTrue(app.has_nvd_api_key())
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT value FROM app_meta WHERE key='nvd_api_key'").fetchone()[0], "local-test-key")
        app.clear_nvd_api_key()
        self.assertFalse(app.has_nvd_api_key())

    def test_nvd_unauthorized_key_falls_back_anonymously(self) -> None:
        app.set_nvd_api_key("local-test-key")
        unauthorized = Mock(status_code=403)
        anonymous = Mock(status_code=200)
        with patch.object(app.requests, "get", side_effect=[unauthorized, anonymous]) as request_get:
            result = app.nvd_get(app.NVD_CVE_URL, params={"cveId": "CVE-2021-44228"})
        self.assertIs(result, anonymous)
        self.assertFalse(app.has_nvd_api_key())
        self.assertEqual(request_get.call_args_list[0].kwargs["headers"], {"apiKey": "local-test-key"})
        self.assertEqual(request_get.call_args_list[1].kwargs["headers"], {})

    def test_network_failure_preserves_saved_api_key(self) -> None:
        app.set_nvd_api_key("local-test-key")
        with patch.object(app.requests, "get", side_effect=app.requests.ConnectionError("offline")):
            with self.assertRaises(app.requests.ConnectionError):
                app.nvd_get(app.NVD_CVE_URL, params={})
        self.assertTrue(app.has_nvd_api_key())

    def test_api_key_validation_classifies_failures(self) -> None:
        self.assertEqual(app.validate_nvd_api_key(""), (False, "請輸入API Key", "empty"))
        cases = [
            (app.requests.Timeout(), "network"),
            (app.requests.ConnectionError(), "network"),
        ]
        for exception, expected in cases:
            with patch.object(app.requests, "get", side_effect=exception):
                self.assertEqual(app.validate_nvd_api_key("candidate")[2], expected)
        for status, expected in ((401, "key"), (403, "key"), (429, "rate_limit"), (503, "service")):
            response = Mock(status_code=status)
            response.headers = {}
            response.raise_for_status.side_effect = None
            with patch.object(app.requests, "get", return_value=response):
                self.assertEqual(app.validate_nvd_api_key("candidate")[2], expected)
        invalid_key = Mock(status_code=404)
        invalid_key.headers = {"message": "Invalid apiKey."}
        with patch.object(app.requests, "get", return_value=invalid_key):
            self.assertEqual(
                app.validate_nvd_api_key("candidate"),
                (False, "API Key無效或已失效，請檢查後重新輸入", "key"),
            )

    def test_fetch_pagination_over_2000_is_complete_and_deduplicable(self) -> None:
        class Response:
            def __init__(self, start: int, count: int, total: int):
                self.status_code = 200
                self.start, self.count, self.total = start, count, total
            def raise_for_status(self): return None
            def json(self):
                return {
                    "totalResults": self.total,
                    "vulnerabilities": [
                        {"cve": {"id": f"CVE-2099-{index:05d}"}}
                        for index in range(self.start, self.start + self.count)
                    ],
                }
        offsets: list[int] = []
        def fake_get(_url, *, params, timeout):
            del timeout
            start = int(params["startIndex"])
            offsets.append(start)
            return Response(start, min(2000, 2501 - start), 2501)
        app._nvd_api_key = "test-key"
        with patch.object(app, "nvd_get", fake_get):
            rows = app.fetch_cves({})
        self.assertEqual(offsets, [0, 2000])
        self.assertEqual(len(rows), 2501)
        self.assertEqual(len({row["id"] for row in rows}), 2501)

    def test_product_jobs_include_all_version_children_not_similar_products(self) -> None:
        with app.db() as conn:
            conn.executemany(
                "INSERT INTO catalog_cpe(kind,name,part,vendor_id,product_id) VALUES ('vendor',?,'*',?,'*')",
                [("Microsoft", "microsoft"), ("Palo Alto Networks", "palo_alto_networks")],
            )
            conn.executemany(
                "INSERT INTO catalog_cpe(kind,name,part,vendor_id,product_id) VALUES ('product',?,?,?,?)",
                [
                    ("Microsoft Windows 10", "o", "microsoft", "windows_10"),
                    ("Microsoft Windows 10 22H2", "o", "microsoft", "windows_10_22h2"),
                    ("Microsoft Windows 10 Mobile", "o", "microsoft", "windows_10_mobile"),
                    ("Palo Alto Networks PAN-OS", "o", "palo_alto_networks", "pan-os"),
                    ("Palo Alto Networks PAN-OS 11.1.4", "o", "palo_alto_networks", "pan-os_11.1.4"),
                ],
            )
            conn.executemany(
                "INSERT INTO watch_vendor_products(vendor_name,product_name) VALUES (?,?)",
                [("Microsoft", "Microsoft Windows 10"), ("Palo Alto Networks", "Palo Alto Networks PAN-OS")],
            )
        jobs = app.product_query_jobs(
            [("product", "Microsoft Windows 10"), ("product", "Palo Alto Networks PAN-OS")],
            max_cpe_targets_per_vendor=99,
        )
        product_targets = {(job[1], job[2]) for job in jobs if job[0] == "product"}
        self.assertIn(("microsoft", "windows_10"), product_targets)
        self.assertIn(("microsoft", "windows_10_22h2"), product_targets)
        self.assertNotIn(("microsoft", "windows_10_mobile"), product_targets)
        self.assertIn(("palo_alto_networks", "pan-os"), product_targets)
        self.assertIn(("palo_alto_networks", "pan-os_11.1.4"), product_targets)

    def test_interrupted_full_catalog_sync_resumes_from_saved_page(self) -> None:
        class Response:
            status_code = 200
            def __init__(self, records, total):
                self.records, self.total = records, total
            def raise_for_status(self): return None
            def json(self): return {"products": self.records, "totalResults": self.total}

        def cpe(vendor: str, product: str) -> dict:
            return {"cpe": {"cpeName": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*", "deprecated": False}}

        offsets: list[int] = []
        def interrupted(_url, *, params, timeout):
            del timeout
            offset = int(params["startIndex"])
            offsets.append(offset)
            if offset == 0:
                return Response([cpe("acme", "alpha")], 2)
            raise app.requests.ConnectionError("offline")

        app._nvd_api_key = "test-key"
        with patch.object(app, "nvd_get", interrupted), patch.object(app.time, "sleep"):
            app._catalog_sync_worker(True)
        with app.db() as conn:
            checkpoint = conn.execute("SELECT value FROM app_meta WHERE key='catalog_full_sync_start_index'").fetchone()
            self.assertEqual(checkpoint[0], "1")

        def resumed(_url, *, params, timeout):
            del timeout
            offset = int(params["startIndex"])
            offsets.append(offset)
            self.assertEqual(offset, 1)
            return Response([cpe("acme", "beta")], 2)

        with patch.object(app, "nvd_get", resumed):
            app._catalog_sync_worker(True)
        with app.db() as conn:
            products = [row[0] for row in conn.execute("SELECT name FROM catalog WHERE kind='product' ORDER BY name")]
            checkpoint = conn.execute("SELECT value FROM app_meta WHERE key='catalog_full_sync_start_index'").fetchone()
        self.assertEqual(offsets, [0, 1, 1, 1, 1])
        self.assertEqual(products, ["Acme Alpha", "Acme Beta"])
        self.assertIsNone(checkpoint)

    def test_interrupted_incremental_catalog_sync_resumes_without_repeating_saved_pages(self) -> None:
        class Response:
            status_code = 200
            def __init__(self, records, total):
                self.records, self.total = records, total
            def raise_for_status(self): return None
            def json(self): return {"products": self.records, "totalResults": self.total}

        def cpe(product: str) -> dict:
            return {
                "cpe": {
                    "cpeName": f"cpe:2.3:a:acme:{product}:*:*:*:*:*:*:*:*",
                    "deprecated": False,
                }
            }

        offsets: list[int] = []
        page_sizes: list[int] = []

        def interrupted(_url, *, params, timeout):
            self.assertEqual(timeout, 120)
            offset = int(params["startIndex"])
            offsets.append(offset)
            page_sizes.append(int(params["resultsPerPage"]))
            if offset == 0:
                return Response([cpe("alpha")], 3)
            if offset == 1:
                return Response([cpe("beta")], 3)
            raise app.requests.ConnectionError("offline")

        started = datetime.now().astimezone() - timedelta(hours=1)
        with patch.object(app, "nvd_get", interrupted), patch.object(app.time, "sleep"):
            app._catalog_sync_worker(False, started)
        with app.db() as conn:
            state_row = conn.execute(
                "SELECT value FROM app_meta WHERE key=?",
                (app.CATALOG_INCREMENTAL_STATE_KEY,),
            ).fetchone()
            saved_products = {
                row[0] for row in conn.execute("SELECT name FROM catalog WHERE kind='product'")
            }
        self.assertIsNotNone(state_row)
        self.assertEqual(json.loads(state_row[0])["start_index"], 2)
        self.assertEqual(json.loads(state_row[0])["total"], 3)
        self.assertEqual(saved_products, {"Acme Alpha", "Acme Beta"})
        self.assertIn("已保存進度", app.catalog_state["error"])
        self.assertNotIn("無法連接 NVD 資料庫", app.catalog_state["error"])

        def resumed(_url, *, params, timeout):
            self.assertEqual(timeout, 120)
            self.assertEqual(app.catalog_state["processed"], 2)
            self.assertEqual(app.catalog_state["total"], 3)
            self.assertIn("2/3", app.catalog_state["message"])
            offset = int(params["startIndex"])
            offsets.append(offset)
            page_sizes.append(int(params["resultsPerPage"]))
            self.assertEqual(offset, 2)
            return Response([cpe("gamma")], 3)

        with patch.object(app, "nvd_get", resumed), patch.object(app.time, "sleep"):
            app._catalog_sync_worker(False, started)
        with app.db() as conn:
            products = [
                row[0]
                for row in conn.execute("SELECT name FROM catalog WHERE kind='product' ORDER BY name")
            ]
            state_row = conn.execute(
                "SELECT value FROM app_meta WHERE key=?",
                (app.CATALOG_INCREMENTAL_STATE_KEY,),
            ).fetchone()
        self.assertEqual(offsets, [0, 1, 2, 2, 2, 2])
        self.assertEqual(set(page_sizes), {app.CATALOG_PAGE_SIZE})
        self.assertEqual(products, ["Acme Alpha", "Acme Beta", "Acme Gamma"])
        self.assertIsNone(state_row)

    def test_catalog_sync_recovers_when_saved_nvd_page_offset_becomes_invalid(self) -> None:
        class Response:
            ok = True
            def __init__(self, status, records=None, total=0, message=""):
                self.status_code = status
                self.records = records or []
                self.total = total
                self.headers = {"message": message} if message else {}
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise app.requests.HTTPError(response=self)
            def json(self): return {"products": self.records, "totalResults": self.total}

        now = datetime.now().astimezone()
        state = {
            "version": 1,
            "sync_end": now.isoformat(),
            "windows": [[(now - timedelta(hours=1)).isoformat(), now.isoformat()]],
            "window_index": 0,
            "start_index": 2000,
            "total": 2300,
            "deprecated": [],
        }
        with app.db() as conn:
            conn.execute(
                "INSERT INTO app_meta(key,value) VALUES (?,?)",
                (app.CATALOG_INCREMENTAL_STATE_KEY, json.dumps(state)),
            )
        offsets: list[int] = []

        def changed_page(params):
            offset = int(params["startIndex"])
            offsets.append(offset)
            if offset == 2000:
                return Response(404, message="Invalid startIndex")
            return Response(
                200,
                [{"cpe": {"cpeName": "cpe:2.3:a:acme:current:*:*:*:*:*:*:*:*", "deprecated": False}}],
                1,
            )

        with patch.object(app, "_catalog_page_request", changed_page):
            app._catalog_sync_worker(False, now - timedelta(hours=1))
        self.assertEqual(offsets, [2000, 0], app.catalog_state)
        self.assertIsNone(app.catalog_state["error"])
        with app.db() as conn:
            self.assertIsNotNone(
                conn.execute(
                    "SELECT 1 FROM catalog WHERE kind='product' AND name='Acme Current'"
                ).fetchone()
            )
            self.assertIsNone(
                conn.execute(
                    "SELECT value FROM app_meta WHERE key=?",
                    (app.CATALOG_INCREMENTAL_STATE_KEY,),
                ).fetchone()
            )

    def test_catalog_404_with_saved_key_retries_anonymously(self) -> None:
        keyed = Mock(status_code=404, ok=False, headers={})
        anonymous = Mock(status_code=200, ok=True, headers={})
        app.set_nvd_api_key("local-test-key")
        with (
            patch.object(app, "nvd_get", return_value=keyed),
            patch.object(app.requests, "get", return_value=anonymous) as request_get,
        ):
            response = app._catalog_page_request({"startIndex": 0})
        self.assertIs(response, anonymous)
        self.assertFalse(app.has_nvd_api_key())
        self.assertEqual(request_get.call_args.kwargs["headers"], {})

    def test_completed_incremental_pages_do_not_repeat_deprecated_product_queries(self) -> None:
        now = datetime.now().astimezone()
        state = {
            "version": 1,
            "sync_end": now.isoformat(),
            "windows": [[(now - timedelta(hours=1)).isoformat(), now.isoformat()]],
            "window_index": 1,
            "start_index": 0,
            "total": 23031,
            "deprecated": [["a", "acme", "legacy", "Acme", "Acme Legacy"]],
        }
        with app.db() as conn:
            conn.execute(
                "INSERT INTO app_meta(key,value) VALUES (?,?)",
                (app.CATALOG_INCREMENTAL_STATE_KEY, json.dumps(state)),
            )
        with patch.object(app, "nvd_get") as request:
            app._catalog_sync_worker(False, now - timedelta(hours=1))
        request.assert_not_called()
        self.assertEqual(app.catalog_state["processed"], 23031)
        self.assertEqual(app.catalog_state["total"], 23031)
        self.assertEqual(app.catalog_state["progress"], 100)
        self.assertIsNone(app.catalog_state["error"])
        with app.db() as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT value FROM app_meta WHERE key=?",
                    (app.CATALOG_INCREMENTAL_STATE_KEY,),
                ).fetchone()
            )

    def test_changed_watchlist_discards_only_stale_temporary_plan(self) -> None:
        with app.db() as conn:
            conn.execute("INSERT INTO watch_vendor_products VALUES ('Acme','Acme Current')")
            conn.execute(
                "INSERT INTO vulnerability_update_runs VALUES ('old','obsolete','2026-01-01T00:00:00+00:00','2026-01-31T00:00:00+00:00','2026-01-31T00:00:00+00:00')"
            )
            conn.execute(
                "INSERT INTO vulnerability_update_jobs(run_id,job_order,mode,value,product_id,product_name,range_start,range_end,status) "
                "VALUES ('old',0,'product','acme','old','Old Product','2026-01-01T00:00:00+00:00','2026-01-31T00:00:00+00:00','pending')"
            )
            conn.execute(
                "INSERT INTO vulnerability_update_candidates VALUES ('old','CVE-2099-STALE',?)",
                (gzip.compress(json.dumps({"id": "CVE-2099-STALE"}).encode()),),
            )
        fetched: list[str] = []
        def fetch(_vendor, product_id, _start, _end, _progress, **_kwargs):
            fetched.append(product_id)
            return []
        app._nvd_api_key = "test-key"
        with (
            patch.object(app, "resolve_watch_cpe_mappings", lambda *_args: None),
            patch.object(app, "fully_watched_vendor_entries", lambda: []),
            patch.object(app, "product_query_jobs", lambda _entries: [("product", "acme", "current", "Acme Current")]),
            patch.object(app, "fetch_cpe_target", fetch),
        ):
            app._update_worker(30)
        with app.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM vulnerability_update_runs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM vulnerability_update_candidates").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id='CVE-2099-STALE'").fetchone()[0], 0)
        self.assertEqual(fetched, ["current"])


class DesktopDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication([])

    def test_button_focus_rectangle_is_suppressed_without_disabling_focus(self) -> None:
        style = desktop.NoButtonFocusRectStyle()
        button = QToolButton()
        button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        style.drawPrimitive(
            desktop.QStyle.PrimitiveElement.PE_FrameFocusRect,
            None,
            None,
            button,
        )
        self.assertEqual(button.focusPolicy(), Qt.FocusPolicy.StrongFocus)

    def test_button_focus_style_process_exits_cleanly(self) -> None:
        script = (
            "from PySide6.QtCore import QTimer; "
            "from PySide6.QtWidgets import QApplication; "
            "from desktop import NoButtonFocusRectStyle; "
            "app=QApplication([]); "
            "app.setStyle(NoButtonFocusRectStyle()); "
            "QTimer.singleShot(0, app.quit); "
            "raise SystemExit(app.exec())"
        )
        environment = dict(os.environ)
        environment["QT_QPA_PLATFORM"] = "offscreen"
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_application_icon_contains_windows_taskbar_sizes(self) -> None:
        sizes = {(size.width(), size.height()) for size in desktop.make_app_icon().availableSizes()}
        self.assertTrue({(16, 16), (24, 24), (32, 32), (48, 48), (256, 256)} <= sizes)

    def test_recent_calendar_limits_span_and_locks_month_year_controls(self) -> None:
        minimum, maximum = QDate(2026, 7, 18), QDate(2026, 8, 17)
        dialog = desktop.DateRangeDialog(minimum, maximum, minimum, maximum, max_span_days=30)
        self.assertLessEqual(dialog.dates()[0].daysTo(dialog.dates()[1]) + 1, 30)
        for calendar in (dialog.start_calendar, dialog.end_calendar):
            for object_name in ("qt_calendar_monthbutton", "qt_calendar_yearbutton"):
                button = calendar.findChild(QToolButton, object_name)
                self.assertIsNotNone(button)
                self.assertTrue(button.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents))
        dialog.close()

    def test_archive_calendar_allows_entire_31_to_90_day_window(self) -> None:
        minimum, maximum = QDate(2026, 5, 19), QDate(2026, 7, 17)
        dialog = desktop.DateRangeDialog(
            minimum, maximum, minimum, maximum,
            show_boundary_months=True, max_span_days=None,
        )
        self.assertEqual(dialog.dates(), (minimum, maximum))
        self.assertEqual(dialog.start_calendar.monthShown(), 5)
        self.assertEqual(dialog.end_calendar.monthShown(), 7)
        dialog.close()

    def test_api_key_dialog_has_archive_style_tutorial_link_and_opens_guide(self) -> None:
        with patch.object(app, "current_nvd_api_key", return_value=""), patch.object(app, "has_nvd_api_key", return_value=False):
            dialog = desktop.NvdApiKeyDialog()
        self.assertIn("查看教學", dialog.tutorial_link.text())
        self.assertIn("font-size:12px", dialog.tutorial_link.text())
        self.assertIn("color:#0563c1", dialog.tutorial_link.text())
        tutorial = SimpleNamespace(exec=Mock(return_value=0))
        with patch.object(desktop, "NvdApiKeyTutorialDialog", return_value=tutorial) as tutorial_class:
            dialog.open_tutorial()
        tutorial_class.assert_called_once_with(dialog)
        tutorial.exec.assert_called_once()
        dialog.close()

    def test_api_key_tutorial_contains_all_steps_and_clickable_nvd_links(self) -> None:
        dialog = desktop.NvdApiKeyTutorialDialog()
        self.assertEqual(len(dialog.step_titles), 4)
        self.assertEqual(len(dialog.step_bodies), 4)
        all_text = " ".join(
            [label.text() for label in dialog.step_titles + dialog.step_bodies]
        )
        self.assertIn("Organization Name", all_text)
        self.assertIn("Personal Use / Not Listed", all_text)
        self.assertIn("Request for NVD API Key", all_text)
        self.assertIn("UUID", all_text)
        self.assertEqual(len(dialog.tutorial_links), 2)
        self.assertIn("api-key-requested", dialog.tutorial_links[0].text())
        self.assertIn("confirm-api-key", dialog.tutorial_links[1].text())
        self.assertTrue(all(link.openExternalLinks() for link in dialog.tutorial_links))
        dialog.close()

    def test_product_select_all_and_reopen_state_are_visually_checked(self) -> None:
        options = [f"Product {index}" for index in range(1, 136)]
        dialog = desktop.FilterSelectionDialog("選擇產品", options, set())
        dialog.select_all()
        self.assertEqual(dialog.selections(), set(options))
        self.assertTrue(all(checkbox.isChecked() for checkbox in dialog.checkboxes.values()))
        reopened = desktop.FilterSelectionDialog("選擇產品", options, dialog.selections())
        self.assertTrue(all(checkbox.isChecked() for checkbox in reopened.checkboxes.values()))
        dialog.close()
        reopened.close()

    def test_product_select_all_only_selects_current_search_results(self) -> None:
        matching = {
            "Microsoft Windows 10",
            "Microsoft Windows 11",
            "Microsoft Windows 10 Mobile",
            "Microsoft Windows 11 IoT",
        }
        unrelated = [f"Unrelated Product {index}" for index in range(775)]
        options = unrelated + sorted(matching)
        dialog = desktop.FilterSelectionDialog("選擇產品", options, set())
        dialog.search.setText("Windows 1")
        self.application.processEvents()

        self.assertEqual(set(dialog.visible_options()), matching)
        dialog.select_all()
        self.assertEqual(dialog.selections(), matching)
        self.assertEqual(dialog.selection_count.text(), "已選 4 / 779 項")
        self.assertTrue(all(dialog.checkboxes[value].isChecked() for value in matching))
        self.assertTrue(
            all(not dialog.checkboxes[value].isChecked() for value in unrelated)
        )

        dialog.clear_all()
        self.assertEqual(dialog.selections(), set())
        dialog.close()

    def test_filtered_select_all_preserves_hidden_existing_selections(self) -> None:
        options = ["Existing Product", "Microsoft Windows 10", "Microsoft Windows 11"]
        dialog = desktop.FilterSelectionDialog(
            "選擇產品", options, {"Existing Product"}
        )
        dialog.search.setText("Windows 1")
        self.application.processEvents()
        dialog.select_all()
        self.assertEqual(dialog.selections(), set(options))
        dialog.clear_all()
        self.assertEqual(dialog.selections(), {"Existing Product"})
        dialog.close()

    def test_shift_range_applies_only_to_visible_products(self) -> None:
        options = ["Alpha 1", "Alpha 2", "Alpha 3", "Beta 1"]
        dialog = desktop.FilterSelectionDialog("選擇產品", options, set())
        dialog.filter_options("Alpha")
        dialog.checkboxes["Alpha 1"].setChecked(True)
        dialog.apply_range_selection("Alpha 1", True, False)
        dialog.apply_range_selection("Alpha 3", True, True)
        self.assertEqual(dialog.selections(), {"Alpha 1", "Alpha 2", "Alpha 3"})
        self.assertFalse(dialog.checkboxes["Beta 1"].isChecked())
        dialog.close()

    def test_risk_menu_keeps_critical_high_medium_low_order_and_multiselect(self) -> None:
        button = desktop.MultiSelectButton("風險等級：全部")
        button.set_options(["嚴重", "高", "中", "低"])
        self.assertEqual([action.text() for action in button.menu().actions()], ["嚴重", "高", "中", "低"])
        button.menu().actions()[0].setChecked(True)
        button.menu().actions()[2].setChecked(True)
        self.assertEqual(button.selected, {"嚴重", "中"})
        self.assertEqual(button.text(), "風險等級：已選 2 項")

    def test_archive_api_status_remains_static_plain_text_after_global_refresh(self) -> None:
        fake_status = SimpleNamespace(
            setTextFormat=Mock(),
            setTextInteractionFlags=Mock(),
            setText=Mock(),
            setToolTip=Mock(),
        )
        fake_window = SimpleNamespace(archive_only=True, api_status=fake_status)
        desktop.VulHubWindow.refresh_api_status(fake_window)
        fake_status.setTextFormat.assert_called_once_with(Qt.TextFormat.PlainText)
        fake_status.setTextInteractionFlags.assert_called_once_with(
            Qt.TextInteractionFlag.NoTextInteraction
        )
        fake_status.setText.assert_called_once_with("●  NVD API 2.0")
        self.assertNotIn("<a", fake_status.setText.call_args.args[0])

    def test_offline_startup_does_not_launch_catalog_sync_or_hide_error(self) -> None:
        fake_window = SimpleNamespace(
            progress=SimpleNamespace(setValue=Mock()),
            progress_message=SimpleNamespace(setText=Mock()),
            refresh_btn=SimpleNamespace(setEnabled=Mock()),
            load_rows=Mock(),
            archive_window=None,
            update_timer=SimpleNamespace(stop=Mock()),
            progress_frame=SimpleNamespace(hide=Mock()),
        )
        failed_state = {
            "running": False,
            "progress": 1,
            "message": "更新未完成",
            "error": "無法連接 NVD 資料庫，請檢查網絡或稍後重試",
        }
        with (
            patch.dict(app.update_state, failed_state, clear=True),
            patch.object(desktop.QMessageBox, "warning"),
            patch.object(desktop.QTimer, "singleShot") as single_shot,
            patch.object(app, "start_catalog_sync") as start_catalog_sync,
        ):
            desktop.VulHubWindow.poll_update(fake_window)
        single_shot.assert_not_called()
        start_catalog_sync.assert_not_called()
        fake_window.refresh_btn.setEnabled.assert_called_with(True)
        fake_window.update_timer.stop.assert_called_once()

    def test_manual_retry_restores_hidden_progress_even_if_update_already_running(self) -> None:
        fake_window = SimpleNamespace(
            progress_frame=SimpleNamespace(show=Mock()),
            refresh_btn=SimpleNamespace(setEnabled=Mock()),
            update_timer=SimpleNamespace(start=Mock()),
        )
        with (
            patch.object(app, "start_update", return_value=False),
            patch.dict(app.update_state, {"running": True}, clear=True),
        ):
            desktop.VulHubWindow.refresh_now(fake_window)
        fake_window.progress_frame.show.assert_called_once()
        fake_window.refresh_btn.setEnabled.assert_called_once_with(False)
        fake_window.update_timer.start.assert_called_once_with(900)

    def test_manual_update_is_not_silently_queued_behind_catalog_sync(self) -> None:
        fake_window = SimpleNamespace()
        with (
            patch.dict(app.catalog_state, {"running": True}, clear=True),
            patch.object(app, "start_update") as start_update,
            patch.object(desktop.QMessageBox, "information") as information,
        ):
            desktop.VulHubWindow.refresh_now(fake_window)
        start_update.assert_not_called()
        information.assert_called_once_with(
            fake_window,
            "產品名單正在更新",
            "請等待產品名單更新完成後再更新漏洞列表",
        )

    def test_old_hide_timer_cannot_hide_new_update_progress(self) -> None:
        fake_window = SimpleNamespace(progress_frame=SimpleNamespace(hide=Mock()))
        with (
            patch.dict(app.update_state, {"running": True}, clear=True),
            patch.dict(app.translation_state, {"pending": 0}, clear=True),
        ):
            desktop.VulHubWindow.hide_progress_if_idle(fake_window)
        fake_window.progress_frame.hide.assert_not_called()
        with (
            patch.dict(app.update_state, {"running": False}, clear=True),
            patch.dict(app.translation_state, {"pending": 0}, clear=True),
        ):
            desktop.VulHubWindow.hide_progress_if_idle(fake_window)
        fake_window.progress_frame.hide.assert_called_once()

    def test_main_and_archive_windows_start_from_disposable_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_db = app.DB_PATH
            original_snapshot = app.CATALOG_SNAPSHOT_PATH
            original_initialized = app._nvd_api_key_initialized
            app.DB_PATH = Path(directory) / "ui.db"
            app.CATALOG_SNAPSHOT_PATH = Path(directory) / "missing.json.gz"
            app._nvd_api_key_initialized = True
            try:
                app.init_db()
                today = datetime.now().astimezone().date()
                with app.db() as conn:
                    conn.execute(
                        "INSERT INTO watch_vendor_products(vendor_name,product_name) VALUES ('Microsoft','Microsoft Windows 11')"
                    )
                    for cve_id, published, archived, translation_ready in (
                        ("CVE-2099-RECENT", today.isoformat(), 0, 1),
                        ("CVE-2099-PENDING", today.isoformat(), 0, 0),
                        ("CVE-2099-ARCHIVE", (today - timedelta(days=45)).isoformat(), 1, 1),
                    ):
                        conn.execute(
                            "INSERT INTO vulnerabilities "
                            "(cve_id,published,severity,score,title_en,title_zh,description_en,description_zh,"
                            "vendors,products,affected_versions,references_json,archived,translation_ready) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                cve_id, published, "高", 8.0, "Windows issue", "Windows 問題",
                                "Description", "描述", '["Microsoft"]', '["Microsoft Windows 11"]',
                                '["Microsoft Windows 11 23H2"]', "[]", archived, translation_ready,
                            ),
                        )
                with (
                    patch.object(desktop.QTimer, "singleShot"),
                    patch.object(app, "start_update", return_value=True) as start_update,
                ):
                    main_window = desktop.VulHubWindow(False)
                    main_window.initialize_data()
                    archive_window = desktop.VulHubWindow(True)
                    archive_window.initialize_data()
                main_window.show()
                main_window._set_startup_focus()
                self.application.processEvents()
                self.assertIs(self.application.focusWidget(), main_window.startup_focus_anchor)
                self.assertEqual(main_window.table.rowCount(), 1)
                self.assertEqual(archive_window.table.rowCount(), 1)
                self.assertEqual(main_window.table.item(0, 1).text(), "CVE-2099-RECENT")
                self.assertEqual(archive_window.table.item(0, 1).text(), "CVE-2099-ARCHIVE")
                # Untranslated rows remain hidden; as soon as one row becomes
                # ready, the next polling load publishes that row immediately.
                with app.db() as conn:
                    conn.execute(
                        "UPDATE vulnerabilities SET translation_ready=1,title_zh='已翻譯問題',description_zh='已翻譯描述' "
                        "WHERE cve_id='CVE-2099-PENDING'"
                    )
                main_window.load_rows()
                self.assertEqual(main_window.table.rowCount(), 2)
                # Qt can change the current item before committing the clicked
                # row's selection state.  The detail pane must follow that
                # current item rather than falling back to the old selection.
                rows_by_cve = {
                    str(main_window.table.item(row, 1).data(Qt.ItemDataRole.UserRole)): row
                    for row in range(main_window.table.rowCount())
                }
                old_row = rows_by_cve["CVE-2099-RECENT"]
                new_row = rows_by_cve["CVE-2099-PENDING"]
                main_window.table.selectRow(old_row)
                main_window.show_selected_detail(main_window.table.item(old_row, 1))
                self.assertEqual(main_window.selected["cve_id"], "CVE-2099-RECENT")
                main_window.table.setCurrentItem(
                    main_window.table.item(new_row, 1),
                    QItemSelectionModel.SelectionFlag.NoUpdate,
                )
                self.application.processEvents()
                self.assertEqual(main_window.selected["cve_id"], "CVE-2099-PENDING")
                start_update.assert_called_once_with(30)
                main_window.close()
                archive_window.close()
            finally:
                app.DB_PATH = original_db
                app.CATALOG_SNAPSHOT_PATH = original_snapshot
                app._nvd_api_key_initialized = original_initialized


if __name__ == "__main__":
    unittest.main(verbosity=2)
