"""Regression tests for crash-safe, resumable vulnerability updates.

The tests use temporary SQLite databases and mocked network/translation calls.
They never read or modify the user's vulhub.db.
"""

from __future__ import annotations

import queue
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402


def sample_cve(cve_id: str, product_id: str, description: str) -> dict:
    return {
        "id": cve_id,
        "published": datetime.now().astimezone().isoformat(),
        "lastModified": datetime.now().astimezone().isoformat(),
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": f"cpe:2.3:a:acme:{product_id}:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": f"https://example.test/{cve_id}"}],
    }


class ResumableUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = app.DB_PATH
        self.original_snapshot_path = app.CATALOG_SNAPSHOT_PATH
        self.original_api_key = app._nvd_api_key
        app.DB_PATH = Path(self.temp_dir.name) / "test.db"
        app.CATALOG_SNAPSHOT_PATH = Path(self.temp_dir.name) / "missing.json.gz"
        app._nvd_api_key = "test-key"  # Avoid anonymous rate-limit sleeps in mocked tests.
        app.cancel_translation_retries()
        app.translation_queue = queue.Queue()
        app.translation_queued_keys.clear()
        app.translation_thread = None
        app.translation_state.update(pending=0, completed=0, failed=0, updated_at=None)
        app.update_state.update(running=True, progress=0, message="", error=None)
        app.init_db()
        with app.db() as conn:
            conn.executemany(
                "INSERT INTO watch_vendor_products(vendor_name,product_name) VALUES (?,?)",
                [("Acme", "Acme Alpha"), ("Acme", "Acme Beta")],
            )

    def tearDown(self) -> None:
        app.translation_queue.join()
        app.cancel_translation_retries()
        app.DB_PATH = self.original_db_path
        app.CATALOG_SNAPSHOT_PATH = self.original_snapshot_path
        app._nvd_api_key = self.original_api_key
        self.temp_dir.cleanup()

    @staticmethod
    def jobs(_entries):
        return [
            ("product", "acme", "alpha", "Acme Alpha"),
            ("product", "acme", "beta", "Acme Beta"),
        ]

    @staticmethod
    def translated(text: str) -> str:
        return f"繁中：{text}"

    def test_download_failure_resumes_without_duplicates(self) -> None:
        alpha = sample_cve("CVE-2099-0001", "alpha", "Alpha issue")
        beta = sample_cve("CVE-2099-0002", "beta", "Beta issue")
        calls: list[str] = []

        def fail_on_beta(_vendor, product, _start, _end, _progress, **_kwargs):
            calls.append(product)
            if product == "beta":
                raise app.requests.ConnectionError("network interrupted")
            return [alpha]

        common = [
            patch.object(app, "product_query_jobs", self.jobs),
            patch.object(app, "resolve_watch_cpe_mappings", lambda *_args: None),
            patch.object(app, "fully_watched_vendor_entries", lambda: []),
        ]
        for mocked in common:
            mocked.start()
            self.addCleanup(mocked.stop)

        with patch.object(app, "fetch_cpe_target", fail_on_beta):
            app._update_worker(30)

        with app.db() as conn:
            statuses = [
                row["status"]
                for row in conn.execute(
                    "SELECT status FROM vulnerability_update_jobs ORDER BY job_order"
                )
            ]
            candidates = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_update_candidates"
            ).fetchone()[0]
            last_success = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_last_success_at'"
            ).fetchone()
        self.assertEqual(statuses, ["completed", "pending"])
        self.assertEqual(candidates, 1)
        self.assertIsNone(last_success)

        def resume_beta(_vendor, product, _start, _end, _progress, **_kwargs):
            calls.append(product)
            self.assertEqual(product, "beta")
            # Returning alpha again proves staging/final CVE primary keys deduplicate it.
            return [alpha, beta]

        with (
            patch.object(app, "fetch_cpe_target", resume_beta),
            patch.object(app, "translate_zh", self.translated),
        ):
            app._update_worker(30)

        app.translation_queue.join()
        with app.db() as conn:
            rows = conn.execute(
                "SELECT cve_id,translation_ready FROM vulnerabilities ORDER BY cve_id"
            ).fetchall()
            temporary_rows = sum(
                conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "vulnerability_update_runs",
                    "vulnerability_update_jobs",
                    "vulnerability_update_candidates",
                )
            )
            last_success = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_last_success_at'"
            ).fetchone()
        self.assertEqual(calls, ["alpha", "beta", "beta"])
        self.assertEqual([(row["cve_id"], row["translation_ready"]) for row in rows], [
            ("CVE-2099-0001", 1),
            ("CVE-2099-0002", 1),
        ])
        self.assertEqual(temporary_rows, 0)
        self.assertIsNotNone(last_success)

    def test_interrupted_pagination_resumes_from_checkpointed_page(self) -> None:
        cves = [
            sample_cve(f"CVE-2099-010{index}", "alpha", f"Page issue {index}")
            for index in range(1, 4)
        ]
        requested_offsets: list[int] = []

        class Response:
            def __init__(self, page, total):
                self.page = page
                self.total = total

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "totalResults": self.total,
                    "vulnerabilities": [{"cve": cve} for cve in self.page],
                }

        def interrupted_get(_url, *, params, timeout):
            del timeout
            offset = int(params["startIndex"])
            requested_offsets.append(offset)
            if offset == 0:
                return Response(cves[:2], 3)
            raise app.requests.ConnectionError("page interrupted")

        common = [
            patch.object(
                app,
                "product_query_jobs",
                lambda _entries: [("product", "acme", "alpha", "Acme Alpha")],
            ),
            patch.object(app, "resolve_watch_cpe_mappings", lambda *_args: None),
            patch.object(app, "fully_watched_vendor_entries", lambda: []),
        ]
        for mocked in common:
            mocked.start()
            self.addCleanup(mocked.stop)

        with patch.object(app, "nvd_get", interrupted_get):
            app._update_worker(30)

        with app.db() as conn:
            job = conn.execute(
                "SELECT status,next_start_index,total_results FROM vulnerability_update_jobs"
            ).fetchone()
            candidate_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_update_candidates"
            ).fetchone()[0]
        self.assertEqual((job["status"], job["next_start_index"], job["total_results"]), (
            "pending", 2, 3
        ))
        self.assertEqual(candidate_count, 2)

        def resumed_get(_url, *, params, timeout):
            del timeout
            offset = int(params["startIndex"])
            requested_offsets.append(offset)
            self.assertEqual(offset, 2)
            return Response(cves[2:], 3)

        with (
            patch.object(app, "nvd_get", resumed_get),
            patch.object(app, "translate_zh", self.translated),
        ):
            app._update_worker(30)
        app.translation_queue.join()

        with app.db() as conn:
            rows = conn.execute(
                "SELECT cve_id FROM vulnerabilities ORDER BY cve_id"
            ).fetchall()
        self.assertEqual(requested_offsets, [0, 2, 2])
        self.assertEqual([row["cve_id"] for row in rows], [
            "CVE-2099-0101",
            "CVE-2099-0102",
            "CVE-2099-0103",
        ])

    def test_translation_failure_keeps_checkpoint_and_retries_only_unfinished(self) -> None:
        alpha = sample_cve("CVE-2099-0011", "alpha", "Alpha translation")
        beta = sample_cve("CVE-2099-0012", "beta", "Beta translation")
        fetch_calls: list[str] = []

        def fetch(_vendor, product, _start, _end, _progress, **_kwargs):
            fetch_calls.append(product)
            return [alpha] if product == "alpha" else [beta]

        def partial_translation(text: str) -> str:
            if "Beta" in text:
                raise app.TranslationUnavailableError("translation interrupted")
            return self.translated(text)

        with app.db() as conn:
            conn.execute(
                "INSERT INTO vulnerabilities "
                "(cve_id,published,severity,title_en,title_zh,description_en,description_zh,vendors,products,affected_versions,references_json,translation_ready) "
                "VALUES ('CVE-2099-STALE',date('now'),'低','stale','舊','stale','舊','[]','[]','[]','[]',1)"
            )

        common = [
            patch.object(app, "product_query_jobs", self.jobs),
            patch.object(app, "resolve_watch_cpe_mappings", lambda *_args: None),
            patch.object(app, "fully_watched_vendor_entries", lambda: []),
            patch.object(app, "fetch_cpe_target", fetch),
        ]
        for mocked in common:
            mocked.start()
            self.addCleanup(mocked.stop)

        with patch.object(app, "translate_zh", partial_translation):
            app._update_worker(30)
        app.translation_queue.join()

        with app.db() as conn:
            ready = {
                row["cve_id"]: row["translation_ready"]
                for row in conn.execute(
                    "SELECT cve_id,translation_ready FROM vulnerabilities"
                )
            }
            run_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_update_runs"
            ).fetchone()[0]
            last_success = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_last_success_at'"
            ).fetchone()
        self.assertEqual(ready["CVE-2099-0011"], 1)
        self.assertEqual(ready["CVE-2099-0012"], 0)
        self.assertNotIn("CVE-2099-STALE", ready)
        self.assertEqual(run_count, 0)
        self.assertIsNotNone(last_success)
        self.assertIsNone(app.update_state["error"])

        translated_on_retry: list[str] = []

        def retry_translation(text: str) -> str:
            translated_on_retry.append(text)
            return self.translated(text)

        # A restart/background resume retries only the unfinished row; it
        # never repeats the already completed NVD product downloads.
        app.cancel_translation_retries()
        with patch.object(app, "translate_zh", retry_translation):
            app.resume_unfinished_translations()
            app.translation_queue.join()

        with app.db() as conn:
            rows = conn.execute(
                "SELECT cve_id,translation_ready FROM vulnerabilities ORDER BY cve_id"
            ).fetchall()
            run_count = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_update_runs"
            ).fetchone()[0]
            last_success = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_last_success_at'"
            ).fetchone()
        self.assertEqual(fetch_calls, ["alpha", "beta"])
        self.assertTrue(translated_on_retry)
        self.assertTrue(all("Beta" in text for text in translated_on_retry))
        self.assertEqual([(row["cve_id"], row["translation_ready"]) for row in rows], [
            ("CVE-2099-0011", 1),
            ("CVE-2099-0012", 1),
        ])
        self.assertEqual(run_count, 0)
        self.assertIsNotNone(last_success)


if __name__ == "__main__":
    unittest.main(verbosity=2)
