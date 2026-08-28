from __future__ import annotations

import gzip
import hashlib
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import unquote

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from opencc import OpenCC
except ImportError:  # Existing installations can still start before dependencies update.
    OpenCC = None


RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
# The onedir runtime and bundled resources live under `_internal`, but the
# writable database belongs beside VulHub.exe.  Source/CMD builds keep the
# existing project-root behaviour.
APP_DATA_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
BASE_DIR = RESOURCE_DIR
DB_PATH = APP_DATA_DIR / "vulhub.db"
CATALOG_SNAPSHOT_PATH = RESOURCE_DIR / "data" / "nvd_catalog_snapshot.json.gz"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
PRODUCT_QUERY_STRATEGY_VERSION = "5"
CATALOG_PAGE_SIZE = 2000
CATALOG_INCREMENTAL_STATE_KEY = "catalog_incremental_sync_state"

update_state: dict[str, Any] = {
    "running": False,
    "progress": 0,
    "message": "等待更新",
    "updated_at": None,
    "error": None,
}
update_lock = threading.Lock()
catalog_state: dict[str, Any] = {
    "running": False,
    "progress": 0,
    "message": "尚未同步完整產品名單",
    "total": 0,
    "processed": 0,
    "error": None,
    "complete": False,
    "completed_at": None,
    "unique_vendors": 0,
    "unique_products": 0,
}
catalog_lock = threading.Lock()
nvd_job_lock = threading.Lock()
nvd_api_key_lock = threading.Lock()
_nvd_api_key = os.getenv("NVD_API_KEY", "").strip()
_nvd_api_key_initialized = False
translation_queue: queue.Queue[tuple[str, str, str, str]] = queue.Queue()
# Translation must never decide whether a completed NVD download succeeds.
# Pending rows are retained in SQLite (translation_ready=0), while this state
# only represents the in-process background work.
translation_state: dict[str, Any] = {
    "pending": 0,
    "completed": 0,
    "failed": 0,
    "retrying": 0,
    "last_error": None,
    "retry_after": None,
    "updated_at": None,
}
translation_lock = threading.Lock()
translation_thread: threading.Thread | None = None
translation_queued_keys: set[tuple[str, str]] = set()
translation_retry_attempts: dict[tuple[str, str], int] = {}
translation_retry_timers: set[threading.Timer] = set()
translation_request_lock = threading.Lock()
translation_next_request_at = 0.0
TRANSLATION_MIN_INTERVAL_SECONDS = 1.1
TRANSLATION_REQUEST_TIMEOUT_SECONDS = 20
traditional_converter = OpenCC("s2twp") if OpenCC is not None else None


class TranslationUnavailableError(RuntimeError):
    """Raised when English vulnerability text could not be translated."""


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _parse_catalog_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def import_bundled_catalog(conn: sqlite3.Connection) -> bool:
    """Install the bundled unique-name snapshot once instead of scanning every CPE."""
    if not CATALOG_SNAPSHOT_PATH.exists():
        return False
    with gzip.open(CATALOG_SNAPSHOT_PATH, "rt", encoding="utf-8") as source:
        snapshot = json.load(source)
    schema_version = int(snapshot.get("schema_version", 1))
    version = str(snapshot.get("source_last_modified") or snapshot.get("generated_at") or "")
    if not version:
        return False
    identity = f"{schema_version}:{version}"
    installed = conn.execute(
        "SELECT value FROM app_meta WHERE key='catalog_snapshot_version'"
    ).fetchone()
    if installed and installed["value"] == identity:
        return False

    completed = conn.execute(
        "SELECT value FROM app_meta WHERE key='catalog_full_sync_completed_at'"
    ).fetchone()
    completed_at = _parse_catalog_time(completed["value"] if completed else None)
    snapshot_at = _parse_catalog_time(version)
    installed_schema = int(str(installed["value"]).split(":", 1)[0]) if installed and str(installed["value"]).split(":", 1)[0].isdigit() else 1
    if completed_at and snapshot_at and completed_at >= snapshot_at and installed_schema >= schema_version:
        conn.execute(
            "INSERT INTO app_meta(key, value) VALUES ('catalog_snapshot_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (identity,),
        )
        return False

    vendors = (("vendor", str(name)) for name in snapshot.get("vendors", []) if name)
    products = (("product", str(name)) for name in snapshot.get("products", []) if name)
    conn.execute("DELETE FROM catalog")
    conn.execute("DELETE FROM catalog_cpe")
    conn.executemany("INSERT OR IGNORE INTO catalog(kind, name) VALUES (?, ?)", vendors)
    conn.executemany("INSERT OR IGNORE INTO catalog(kind, name) VALUES (?, ?)", products)
    conn.executemany(
        "INSERT OR IGNORE INTO catalog_cpe(kind, name, part, vendor_id, product_id) VALUES ('vendor', ?, '*', ?, '*')",
        ((str(name), str(vendor_id)) for name, vendor_id in snapshot.get("vendor_cpes", [])),
    )
    conn.executemany(
        "INSERT OR IGNORE INTO catalog_cpe(kind, name, part, vendor_id, product_id) VALUES ('product', ?, ?, ?, ?)",
        (
            (str(name), str(part), str(vendor_id), str(product_id))
            for name, part, vendor_id, product_id in snapshot.get("product_cpes", [])
        ),
    )
    conn.execute(
        "INSERT INTO app_meta(key, value) VALUES ('catalog_snapshot_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (identity,),
    )
    conn.execute(
        "INSERT INTO app_meta(key, value) VALUES ('catalog_full_sync_completed_at', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (version,),
    )
    conn.execute("DELETE FROM app_meta WHERE key='catalog_full_sync_start_index'")
    conn.execute("DELETE FROM app_meta WHERE key=?", (CATALOG_INCREMENTAL_STATE_KEY,))
    return True


def maintain_vulnerability_retention(
    conn: sqlite3.Connection | None = None,
) -> tuple[int, int]:
    """Archive records outside the recent 30-day window and retain 90 calendar days."""
    today = datetime.now().astimezone().date()
    # Exact age bands by published date:
    #   0–30 days old  -> recent
    #   31–90 days old -> archived
    #   over 90 days   -> deleted
    active_start = (today - timedelta(days=30)).isoformat()
    retention_start = (today - timedelta(days=90)).isoformat()

    def apply(database: sqlite3.Connection) -> tuple[int, int]:
        deleted = database.execute(
            "DELETE FROM vulnerabilities WHERE published < ?",
            (retention_start,),
        ).rowcount
        database.execute(
            "UPDATE vulnerabilities SET archived=CASE WHEN published < ? THEN 1 ELSE 0 END",
            (active_start,),
        )
        archived = database.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE archived=1"
        ).fetchone()[0]
        return int(archived), int(deleted)

    if conn is not None:
        return apply(conn)
    with db() as database:
        return apply(database)


def init_db() -> None:
    global _nvd_api_key, _nvd_api_key_initialized
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                published TEXT NOT NULL,
                modified TEXT,
                severity TEXT NOT NULL,
                score REAL,
                title_en TEXT,
                title_zh TEXT,
                description_en TEXT,
                description_zh TEXT,
                vendors TEXT NOT NULL DEFAULT '[]',
                products TEXT NOT NULL DEFAULT '[]',
                affected_versions TEXT NOT NULL DEFAULT '[]',
                references_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'NVD',
                archived INTEGER NOT NULL DEFAULT 0,
                translation_ready INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS watchlist (
                kind TEXT NOT NULL CHECK(kind IN ('vendor', 'product')),
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(kind, name)
            );
            CREATE TABLE IF NOT EXISTS watch_vendor_products (
                vendor_name TEXT NOT NULL,
                product_name TEXT NOT NULL,
                PRIMARY KEY(vendor_name, product_name)
            );
            CREATE TABLE IF NOT EXISTS cpe_resolution_cache (
                kind TEXT NOT NULL,
                name_key TEXT NOT NULL,
                resolved_at TEXT NOT NULL,
                PRIMARY KEY(kind, name_key)
            );
            CREATE TABLE IF NOT EXISTS catalog (
                kind TEXT NOT NULL CHECK(kind IN ('vendor', 'product')),
                name TEXT NOT NULL,
                PRIMARY KEY(kind, name)
            );
            CREATE TABLE IF NOT EXISTS catalog_cpe (
                kind TEXT NOT NULL CHECK(kind IN ('vendor', 'product')),
                name TEXT NOT NULL,
                part TEXT NOT NULL,
                vendor_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                PRIMARY KEY(kind, name, part, vendor_id, product_id)
            );
            CREATE INDEX IF NOT EXISTS idx_catalog_cpe_kind_name ON catalog_cpe(kind, name);
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vulnerability_update_runs (
                run_id TEXT PRIMARY KEY,
                watch_fingerprint TEXT NOT NULL,
                range_start TEXT NOT NULL,
                range_end TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vulnerability_update_jobs (
                run_id TEXT NOT NULL,
                job_order INTEGER NOT NULL,
                mode TEXT NOT NULL,
                value TEXT NOT NULL,
                product_id TEXT NOT NULL,
                product_name TEXT NOT NULL,
                range_start TEXT NOT NULL,
                range_end TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                next_start_index INTEGER NOT NULL DEFAULT 0,
                total_results INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(run_id, job_order)
            );
            CREATE TABLE IF NOT EXISTS vulnerability_update_candidates (
                run_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(run_id, cve_id)
            );
            CREATE INDEX IF NOT EXISTS idx_update_jobs_status
              ON vulnerability_update_jobs(run_id, status, job_order);
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(vulnerabilities)")}
        if "archived" not in columns:
            conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
            )
        if "translation_ready" not in columns:
            conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN translation_ready INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                "UPDATE vulnerabilities SET translation_ready=1 "
                "WHERE trim(coalesce(description_zh,''))<>'' "
                "AND description_zh<>description_en"
            )
        update_job_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(vulnerability_update_jobs)")
        }
        if "next_start_index" not in update_job_columns:
            conn.execute(
                "ALTER TABLE vulnerability_update_jobs "
                "ADD COLUMN next_start_index INTEGER NOT NULL DEFAULT 0"
            )
        if "total_results" not in update_job_columns:
            conn.execute(
                "ALTER TABLE vulnerability_update_jobs "
                "ADD COLUMN total_results INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_archived ON vulnerabilities(archived)"
        )
        normalize_existing_translations(conn)
        maintain_vulnerability_retention(conn)
        snapshot_loaded = import_bundled_catalog(conn)
        if not conn.execute("SELECT 1 FROM watch_vendor_products LIMIT 1").fetchone():
            legacy_products = [
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM watchlist WHERE kind='product' AND enabled=1"
                )
            ]
            known_vendors = [
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM watchlist WHERE kind='vendor' AND enabled=1"
                )
            ]
            vendor_mappings = conn.execute(
                "SELECT name, vendor_id FROM catalog_cpe WHERE kind='vendor'"
            ).fetchall()
            product_mappings = conn.execute(
                "SELECT name, vendor_id FROM catalog_cpe WHERE kind='product'"
            ).fetchall()
            for product in legacy_products:
                raw_vendors = {
                    row["vendor_id"]
                    for row in product_mappings
                    if normalize(product) in normalize(row["name"])
                }
                candidates = [
                    row["name"] for row in vendor_mappings if row["vendor_id"] in raw_vendors
                ]
                candidates.extend(
                    vendor for vendor in known_vendors if normalize(vendor) in normalize(product)
                )
                product_key = normalize(product)
                if "sqlserver" in product_key:
                    candidates.append("Microsoft")
                if product_key.startswith("apache"):
                    candidates.append("Apache Software Foundation")
                if not candidates:
                    continue
                vendor = sorted(set(candidates), key=natural_key)[0]
                conn.execute(
                    "INSERT OR IGNORE INTO watchlist(kind,name,enabled) VALUES ('vendor',?,1)",
                    (vendor,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO watch_vendor_products(vendor_name,product_name) VALUES (?,?)",
                    (vendor, product),
                )
        completed = conn.execute("SELECT value FROM app_meta WHERE key='catalog_full_sync_completed_at'").fetchone()
        vendor_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='vendor'").fetchone()[0]
        product_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='product'").fetchone()[0]
        catalog_state.update(unique_vendors=vendor_count, unique_products=product_count)
        if completed:
            catalog_state.update(complete=True, completed_at=completed["value"], message="產品名單已同步")
            if snapshot_loaded:
                catalog_state.update(message="已載入隨附廠商／產品索引")
        if not _nvd_api_key_initialized:
            environment_key = os.getenv("NVD_API_KEY", "").strip()
            saved_key = conn.execute(
                "SELECT value FROM app_meta WHERE key='nvd_api_key'"
            ).fetchone()
            with nvd_api_key_lock:
                _nvd_api_key = environment_key or (str(saved_key["value"]).strip() if saved_key else "")
            _nvd_api_key_initialized = True
def natural_key(value: str) -> list[Any]:
    return [int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", value)]


def normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


VENDOR_LABELS = {
    "checkpoint": "Check Point",
    "redhat": "Red Hat",
    "microsoft": "Microsoft",
    "apache": "Apache Software Foundation",
    "paloaltonetworks": "Palo Alto Networks",
    "oracle": "Oracle",
    "cisco": "Cisco",
    "google": "Google",
    "apple": "Apple",
}


def pretty_token(value: str) -> str:
    value = unquote(value).replace("\\!", "!").replace("_", " ").strip()
    key = normalize(value)
    if key in VENDOR_LABELS:
        return VENDOR_LABELS[key]
    words = []
    for word in value.split():
        if word.lower() in {"sql", "ios", "macos", "linux", "http", "jdk"}:
            words.append(word.upper() if word.lower() in {"sql", "http", "jdk"} else word.title())
        else:
            words.append(word.capitalize())
    return " ".join(words)


def severity_zh(severity: str | None, score: float | None) -> str:
    value = (severity or "").upper()
    if value == "CRITICAL" or (score is not None and score >= 9):
        return "嚴重"
    if value == "HIGH" or (score is not None and score >= 7):
        return "高"
    if value == "MEDIUM" or (score is not None and score >= 4):
        return "中"
    return "低"


def walk_matches(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for node in nodes or []:
        matches.extend(node.get("cpeMatch", []))
        matches.extend(walk_matches(node.get("nodes", [])))
    return matches


def extract_products(cve: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    for configuration in cve.get("configurations", []):
        for match in walk_matches(configuration.get("nodes", [])):
            if not match.get("vulnerable", True):
                continue
            parts = match.get("criteria", "").split(":")
            if len(parts) < 6:
                continue
            vendor = pretty_token(parts[3])
            product = pretty_token(parts[4])
            version = pretty_token(parts[5]) if parts[5] not in {"*", "-"} else ""
            base_name = f"{vendor} {product}".strip()
            vendors.add(vendor)
            products.add(f"{base_name} {version}".strip() if version else base_name)
            low = match.get("versionStartIncluding") or match.get("versionStartExcluding")
            high = match.get("versionEndIncluding") or match.get("versionEndExcluding")
            if version:
                versions.add(f"{base_name} {version}".strip())
            elif low or high:
                boundary = f"{low or '*'} – {high or '*'}"
                versions.add(f"{base_name} {boundary}".strip())
            else:
                versions.add(base_name)
    return (
        sorted(vendors, key=natural_key),
        sorted(products, key=natural_key),
        sorted(versions, key=natural_key),
    )


def metric(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        values = metrics.get(key, [])
        if values:
            data = values[0].get("cvssData", {})
            score = data.get("baseScore")
            return score, severity_zh(data.get("baseSeverity") or values[0].get("baseSeverity"), score)
    return None, "低"


def english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    return next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")


def make_title(description: str, cve_id: str) -> str:
    if not description:
        return f"{cve_id} 漏洞"
    first = re.split(r"(?<=[.!?])\s+", description.strip())[0]
    return first[:150].rstrip(".") + ("…" if len(first) > 150 else "")


def translate_zh(text: str) -> str:
    global translation_next_request_at
    if not text:
        return ""
    if BeautifulSoup is None:
        raise TranslationUnavailableError("未安裝中文翻譯元件")
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            # Google Translate is an unofficial, shared endpoint in this
            # application.  Serialising requests prevents a large first sync
            # from looking like automated traffic and losing the whole batch.
            with translation_request_lock:
                now = time.monotonic()
                wait_seconds = max(0.0, translation_next_request_at - now)
                translation_next_request_at = max(now, translation_next_request_at) + TRANSLATION_MIN_INTERVAL_SECONDS
            if wait_seconds:
                time.sleep(wait_seconds)
            # Use Google Translate's mobile endpoint with an explicit bounded
            # timeout. A dropped connection must not leave the sole
            # translation worker waiting forever near the end of a batch.
            response = requests.get(
                "https://translate.google.com/m",
                params={"sl": "en", "tl": "zh-TW", "q": text},
                timeout=(5, TRANSLATION_REQUEST_TIMEOUT_SECONDS),
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if response.status_code == 429:
                raise TranslationUnavailableError("中文翻譯服務暫時限流")
            response.raise_for_status()
            document = BeautifulSoup(response.text, "html.parser")
            result = document.find("div", {"class": "t0"}) or document.find(
                "div", {"class": "result-container"}
            )
            translated = result.get_text(strip=True) if result else ""
            if translated:
                return to_traditional_zh(translated)
        except Exception as exc:
            last_error = exc
        if attempt < 2:
            time.sleep(attempt + 1)
    raise TranslationUnavailableError("暫時無法連接中文翻譯服務") from last_error


def to_traditional_zh(text: str) -> str:
    """Normalize mixed Google output to Taiwanese Traditional Chinese."""
    if not text or traditional_converter is None:
        return text
    return traditional_converter.convert(text)


def normalize_existing_translations(conn: sqlite3.Connection) -> int:
    """One-time repair for mixed Simplified Chinese already stored locally."""
    if traditional_converter is None:
        return 0
    version = "s2twp-v1"
    current = conn.execute(
        "SELECT value FROM app_meta WHERE key='traditional_normalization_version'"
    ).fetchone()
    if current and current["value"] == version:
        return 0
    changed = 0
    for row in conn.execute(
        "SELECT cve_id,title_zh,description_zh FROM vulnerabilities"
    ).fetchall():
        title = to_traditional_zh(row["title_zh"] or "")
        description = to_traditional_zh(row["description_zh"] or "")
        if title != (row["title_zh"] or "") or description != (row["description_zh"] or ""):
            conn.execute(
                "UPDATE vulnerabilities SET title_zh=?,description_zh=? WHERE cve_id=?",
                (title, description, row["cve_id"]),
            )
            changed += 1
    conn.execute(
        "INSERT OR REPLACE INTO app_meta(key,value) VALUES ('traditional_normalization_version',?)",
        (version,),
    )
    return changed


def name_matches(selected: str, candidate: str) -> bool:
    selected_key = normalize(selected)
    candidate_key = normalize(candidate)
    if not selected_key or not candidate_key:
        return False
    return selected_key in candidate_key


def product_family_name(name: str) -> str:
    """Remove only a trailing version token, preserving distinct product families."""
    value = re.sub(r"\s+", " ", name).strip()
    # Preserve hyphenated product identities (PAN-OS, SD-WAN, and so on).
    # Version ranges produced by NVD use whitespace around the dash.
    value = re.sub(r"\s+(?:\*|\S+)\s+[–-]\s+(?:\*|\S+)$", "", value)
    value = re.sub(r"\s+\*\s*[–-]\s*\*$", "", value)
    value = re.sub(
        r"\s+(?:(?:version\s+)?(?:[vr]\d[\w.+-]*|\d+(?:\.\d+)+(?:[a-z0-9._-]*)?|\d{1,4}|\d{2,4}h\d+|\d+[a-z]\d+)(?:\s+[–-]\s+\d[\w.+-]*)?|(?:sp|cu|update|patch|build|release|take|hotfix)\s*\d[\w.+-]*)$",
        "",
        value,
        flags=re.I,
    )
    return value.strip() or name


def validated_product_family(
    name: str,
    known_product_keys: set[str],
    protected_parent_keys: set[str] | None = None,
) -> str:
    """Collapse a version suffix only when the resulting parent product exists.

    Numeric and hyphenated suffixes are also commonly part of hardware model
    names. Requiring a real parent CPE prevents those identities from being
    shortened to a vendor or an unrelated product.
    """
    if protected_parent_keys and normalize(name) in protected_parent_keys:
        return name
    candidate = product_family_name(name)
    return candidate if normalize(candidate) in known_product_keys else name


def product_family_context(names: list[str] | set[str]) -> tuple[set[str], set[str]]:
    """Build validated-family context and protect intermediate product parents."""
    known_keys = {normalize(name) for name in names}
    protected_parent_keys = {
        normalize(candidate)
        for name in names
        for candidate in [product_family_name(name)]
        if normalize(candidate) != normalize(name) and normalize(candidate) in known_keys
    }
    return known_keys, protected_parent_keys


def watched_product_matches(selected: str, candidate: str) -> bool:
    selected_key = normalize(selected)
    if not selected_key:
        return False
    return selected_key in {
        normalize(candidate),
        normalize(product_family_name(candidate)),
    }


def is_watched(vendors: list[str], products: list[str], entries: list[tuple[str, str]]) -> bool:
    for kind, name in entries:
        candidates = vendors if kind == "vendor" else products
        matcher = name_matches if kind == "vendor" else watched_product_matches
        if any(matcher(name, candidate) for candidate in candidates):
            return True
    return False


def record_matches_watchlist(
    vendors: list[str],
    products: list[str],
    versions: list[str],
    description: str,
    entries: list[tuple[str, str]],
) -> bool:
    if is_watched(vendors, products + versions, entries):
        return True
    if vendors or products or versions:
        return False
    description_key = normalize(description)
    return any(normalize(name) in description_key for _kind, name in entries if normalize(name))


def fully_watched_vendor_entries() -> list[tuple[str, str]]:
    """Return vendors whose local product catalogue is effectively fully selected.

    A small tolerance allows a catalogue refresh to introduce one or two new
    products after the user clicked Select All without silently disabling the
    vendor fallback for fresh CVEs whose CPE data has not arrived yet.
    """
    with db() as conn:
        selected_rows = conn.execute(
            "SELECT vendor_name,product_name FROM watch_vendor_products"
        ).fetchall()
        vendor_rows = conn.execute(
            "SELECT name,vendor_id FROM catalog_cpe WHERE kind='vendor'"
        ).fetchall()
        product_rows = conn.execute(
            "SELECT name,vendor_id FROM catalog_cpe WHERE kind='product'"
        ).fetchall()
    selected_by_vendor: dict[str, set[str]] = {}
    display_by_key: dict[str, str] = {}
    for row in selected_rows:
        vendor_key = normalize(row["vendor_name"])
        display_by_key[vendor_key] = row["vendor_name"]
        selected_by_vendor.setdefault(vendor_key, set()).add(normalize(row["product_name"]))
    ids_by_vendor: dict[str, set[str]] = {}
    for row in vendor_rows:
        ids_by_vendor.setdefault(normalize(row["name"]), set()).add(row["vendor_id"])
    result: list[tuple[str, str]] = []
    for vendor_key, selected in selected_by_vendor.items():
        vendor_ids = ids_by_vendor.get(vendor_key, set())
        catalog_products = {
            normalize(row["name"])
            for row in product_rows
            if row["vendor_id"] in vendor_ids
        }
        if (
            len(selected) >= 5
            and catalog_products
            and len(selected & catalog_products) / len(catalog_products) >= 0.95
        ):
            result.append(("vendor", display_by_key[vendor_key]))
    return result


def purge_unwatched_vulnerabilities(entries: list[tuple[str, str]]) -> int:
    """Remove saved CVEs that no longer match any enabled watchlist item."""
    with db() as conn:
        rows = conn.execute(
            "SELECT cve_id, vendors, products, affected_versions, description_en FROM vulnerabilities"
        ).fetchall()
        stale: list[tuple[str]] = []
        for row in rows:
            try:
                vendors = json.loads(row["vendors"] or "[]")
                products = json.loads(row["products"] or "[]")
                versions = json.loads(row["affected_versions"] or "[]")
            except (TypeError, json.JSONDecodeError):
                vendors, products, versions = [], [], []
            if not record_matches_watchlist(
                vendors,
                products,
                versions,
                row["description_en"] or "",
                entries,
            ):
                stale.append((row["cve_id"],))
        conn.executemany("DELETE FROM vulnerabilities WHERE cve_id=?", stale)
    return len(stale)


def current_nvd_api_key() -> str:
    with nvd_api_key_lock:
        return _nvd_api_key


def has_nvd_api_key() -> bool:
    return bool(current_nvd_api_key())


def set_nvd_api_key(key: str) -> None:
    """Persist the key locally; vulhub.db is intentionally excluded from Git."""
    global _nvd_api_key
    clean_key = key.strip()
    with db() as conn:
        if clean_key:
            conn.execute(
                "INSERT INTO app_meta(key,value) VALUES ('nvd_api_key',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (clean_key,),
            )
        else:
            conn.execute("DELETE FROM app_meta WHERE key='nvd_api_key'")
    with nvd_api_key_lock:
        _nvd_api_key = clean_key


def clear_nvd_api_key() -> None:
    set_nvd_api_key("")


def nvd_headers(key: str | None = None) -> dict[str, str]:
    actual_key = current_nvd_api_key() if key is None else key.strip()
    return {"apiKey": actual_key} if actual_key else {}


def nvd_get(url: str, *, params: dict[str, Any], timeout: int = 60) -> requests.Response:
    """Call NVD with bounded automatic recovery from server-side rate limits."""
    key = current_nvd_api_key()
    headers = nvd_headers(key)
    for attempt in range(5):
        try:
            response = requests.get(url, params=params, headers=headers, timeout=timeout)
        except requests.RequestException:
            # A timeout, DNS failure or interrupted connection does not prove
            # that the saved key is invalid, so preserve it for the next try.
            raise
        nvd_message = str(response.headers.get("message", ""))
        if key and (
            response.status_code in {401, 403}
            or "invalidapikey" in normalize(nvd_message)
        ):
            clear_nvd_api_key()
            key = ""
            headers = {}
            continue
        if response.status_code not in {429, 500, 502, 503, 504} or attempt == 4:
            return response
        retry_after = response.headers.get("Retry-After", "").strip()
        try:
            delay = float(retry_after)
        except ValueError:
            # NVD anonymous access is much stricter than API Key access.
            base = 6.5 if not key else 1.5
            delay = base * (2 ** attempt)
        time.sleep(min(max(delay, 1.0), 90.0))
    return response


def validate_nvd_api_key(key: str) -> tuple[bool, str, str]:
    """Verify a proposed key and return success, message and failure category."""
    clean_key = key.strip()
    if not clean_key:
        return False, "請輸入API Key", "empty"
    previous_key = current_nvd_api_key()
    try:
        response = requests.get(
            NVD_CVE_URL,
            params={"cveId": "CVE-2021-44228", "resultsPerPage": 1},
            headers=nvd_headers(clean_key),
            timeout=20,
        )
        nvd_message = str(response.headers.get("message", ""))
        # NVD currently returns HTTP 404 with the `message: Invalid apiKey.`
        # header for a rejected key.  Treat the documented message as the
        # authoritative signal instead of misreporting it as a service error.
        key_rejected = response.status_code in {401, 403} or (
            "invalidapikey" in normalize(nvd_message)
        )
        if key_rejected:
            if clean_key == previous_key:
                clear_nvd_api_key()
            return False, "API Key無效或已失效，請檢查後重新輸入", "key"
        if response.status_code == 429:
            return False, "NVD請求過於頻繁，請稍後再驗證", "rate_limit"
        if 500 <= response.status_code:
            return False, "NVD資料庫暫時無法提供服務，請稍後再驗證", "service"
        response.raise_for_status()
        payload = response.json()
        if "vulnerabilities" not in payload:
            raise ValueError("unexpected NVD response")
    except requests.Timeout:
        return False, "連接 NVD 資料庫逾時，請檢查網絡後重試", "network"
    except requests.ConnectionError:
        return False, "無法連接 NVD 資料庫，請檢查網絡連線", "network"
    except requests.RequestException:
        return False, "NVD資料庫回應異常，請稍後再驗證", "service"
    except (ValueError, json.JSONDecodeError):
        return False, "NVD資料庫回應格式異常，請稍後再驗證", "service"
    set_nvd_api_key(clean_key)
    return True, "API Key驗證成功，已啟用", "success"


def fetch_cves(
    params: dict[str, Any],
    item_filter: Callable[[dict[str, Any]], bool] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
    start_index: int = 0,
    page_callback: Callable[[list[dict[str, Any]], int, int], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    current_index = max(0, int(start_index))
    while True:
        request_params = {
            **params,
            "resultsPerPage": 2000,
            "startIndex": current_index,
            "noRejected": "",
        }
        response = nvd_get(NVD_CVE_URL, params=request_params, timeout=60)
        response.raise_for_status()
        payload = response.json()
        page = [item["cve"] for item in payload.get("vulnerabilities", [])]
        accepted_page = [
            cve for cve in page if item_filter is None or item_filter(cve)
        ]
        results.extend(accepted_page)
        current_index += len(page)
        total = int(payload.get("totalResults", current_index))
        if page_callback:
            # The callback persists both this page and its next offset in one
            # SQLite transaction. A process crash can therefore repeat at most
            # the current page, never lose an already checkpointed page.
            page_callback(accepted_page, current_index, total)
        if progress_callback:
            progress_callback(current_index, total)
        if not page or current_index >= total:
            break
        time.sleep(0.6 if has_nvd_api_key() else 6.2)
    return results


def fetch_term(
    term: str,
    start: datetime,
    end: datetime,
    progress_callback: Callable[[int, int], None] | None = None,
    start_index: int = 0,
    page_callback: Callable[[list[dict[str, Any]], int, int], None] | None = None,
) -> list[dict[str, Any]]:
    return fetch_cves(
        {
            "keywordSearch": term,
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
        progress_callback=progress_callback,
        start_index=start_index,
        page_callback=page_callback,
    )


def fetch_modified_cves(
    start: datetime,
    end: datetime,
    progress_callback: Callable[[int, int], None] | None = None,
    start_index: int = 0,
    page_callback: Callable[[list[dict[str, Any]], int, int], None] | None = None,
) -> list[dict[str, Any]]:
    """Fetch the single NVD change stream used by routine incremental updates."""
    return fetch_cves(
        {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
        progress_callback=progress_callback,
        start_index=start_index,
        page_callback=page_callback,
    )


def fetch_cpe_target(
    vendor_id: str,
    product_id: str,
    start: datetime,
    end: datetime,
    progress_callback: Callable[[int, int], None] | None = None,
    start_index: int = 0,
    page_callback: Callable[[list[dict[str, Any]], int, int], None] | None = None,
) -> list[dict[str, Any]]:
    return fetch_cves(
        {
            "virtualMatchString": f"cpe:2.3:*:{vendor_id}:{product_id}:*:*:*:*:*:*:*:*",
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        },
        progress_callback=progress_callback,
        start_index=start_index,
        page_callback=page_callback,
    )


def resolve_watch_cpe_mappings(
    entries: list[tuple[str, str]],
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> None:
    """Resolve watch items locally first and contact NVD only for genuinely unknown names."""
    with db() as conn:
        cached_keys = {
            (row["kind"], row["name_key"])
            for row in conn.execute("SELECT kind,name_key FROM cpe_resolution_cache")
        }
        local_mappings = conn.execute(
            "SELECT kind,name FROM catalog_cpe"
        ).fetchall()
    exact_mapping_keys = {
        (row["kind"], normalize(row["name"])) for row in local_mappings
    }
    # Older versions cached a lookup even when it returned no exact CPE. Such
    # entries must be retried; a cache marker alone is not proof of resolution.
    resolved_keys = cached_keys & exact_mapping_keys

    # Products selected through the bundled/local product catalogue already
    # have CPE mappings.  Mark those as resolved locally instead of querying
    # the NVD CPE endpoint once again for every selected product.
    locally_resolved = {
        (kind, name)
        for kind, name in entries
        if any(
            mapping["kind"] == kind
            and (
                normalize(mapping["name"]) == normalize(name)
            )
            for mapping in local_mappings
        )
    }
    if locally_resolved:
        resolved_at = datetime.now().astimezone().isoformat(timespec="seconds")
        with db() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO cpe_resolution_cache(kind,name_key,resolved_at) VALUES (?,?,?)",
                [
                    (kind, normalize(name), resolved_at)
                    for kind, name in locally_resolved
                ],
            )
        resolved_keys.update((kind, normalize(name)) for kind, name in locally_resolved)

    unresolved = [
        (kind, name)
        for kind, name in entries
        if (kind, normalize(name)) not in resolved_keys
    ]
    if progress_callback:
        progress_callback(0, len(unresolved), "")
    for index, (kind, name) in enumerate(unresolved):
        if progress_callback:
            progress_callback(index, len(unresolved), name)
        response = nvd_get(
            NVD_CPE_URL,
            params={"keywordSearch": name, "resultsPerPage": 10000},
            timeout=60,
        )
        response.raise_for_status()
        mappings: set[tuple[str, str, str, str, str]] = set()
        for record in response.json().get("products", []):
            cpe = record.get("cpe", {})
            if cpe.get("deprecated"):
                continue
            parts = cpe.get("cpeName", "").split(":")
            if len(parts) < 5:
                continue
            vendor = pretty_token(parts[3])
            product = f"{vendor} {pretty_token(parts[4])}".strip()
            matched = normalize(vendor) == normalize(name) if kind == "vendor" else name_matches(name, product)
            if matched:
                mappings.add(("vendor", vendor, "*", parts[3], "*"))
                mappings.add(("product", product, parts[2], parts[3], parts[4]))
        exact_resolved = any(
            mapping_kind == kind and normalize(mapping_name) == normalize(name)
            for mapping_kind, mapping_name, _part, _vendor_id, _product_id in mappings
        )
        with db() as conn:
            if mappings:
                conn.executemany(
                    "INSERT OR IGNORE INTO catalog_cpe(kind, name, part, vendor_id, product_id) VALUES (?, ?, ?, ?, ?)",
                    mappings,
                )
            if exact_resolved:
                conn.execute(
                    "INSERT OR REPLACE INTO cpe_resolution_cache(kind,name_key,resolved_at) VALUES (?,?,?)",
                    (kind, normalize(name), datetime.now().astimezone().isoformat(timespec="seconds")),
                )
            else:
                conn.execute(
                    "DELETE FROM cpe_resolution_cache WHERE kind=? AND name_key=?",
                    (kind, normalize(name)),
                )
        if progress_callback:
            progress_callback(index + 1, len(unresolved), name)
        if not has_nvd_api_key() and index < len(unresolved) - 1:
            time.sleep(6.2)


def watch_cpe_targets(
    entries: list[tuple[str, str]],
) -> tuple[set[tuple[str, str]], list[tuple[str, str]]]:
    with db() as conn:
        mappings = conn.execute(
            "SELECT kind, name, vendor_id, product_id FROM catalog_cpe"
        ).fetchall()
    targets: set[tuple[str, str]] = set()
    resolved: set[tuple[str, str]] = set()
    for kind, selected_name in entries:
        for mapping in mappings:
            if mapping["kind"] != kind:
                continue
            matched = (
                normalize(selected_name) == normalize(mapping["name"])
                if kind == "vendor"
                else name_matches(selected_name, mapping["name"])
            )
            if matched:
                product_id = "*" if kind == "vendor" else mapping["product_id"]
                targets.add((mapping["vendor_id"], product_id))
                resolved.add((kind, selected_name))
    vendor_wildcards = {vendor_id for vendor_id, product_id in targets if product_id == "*"}
    targets = {
        (vendor_id, product_id)
        for vendor_id, product_id in targets
        if product_id == "*" or vendor_id not in vendor_wildcards
    }
    unresolved = [entry for entry in entries if entry not in resolved]
    return targets, unresolved


def product_query_jobs(
    entries: list[tuple[str, str]], max_cpe_targets_per_vendor: int = 4
) -> list[tuple[str, str, str, str]]:
    """Expand every product family and batch large same-vendor sets safely."""
    with db() as conn:
        mappings = conn.execute(
            "SELECT name,vendor_id,product_id FROM catalog_cpe WHERE kind='product'"
        ).fetchall()
        relations = conn.execute(
            "SELECT vendor_name,product_name FROM watch_vendor_products"
        ).fetchall()
        vendor_mappings = conn.execute(
            "SELECT name,vendor_id FROM catalog_cpe WHERE kind='vendor'"
        ).fetchall()
    exact_index: dict[str, set[tuple[str, str]]] = {}
    family_index: dict[str, set[tuple[str, str]]] = {}
    for row in mappings:
        target = (row["vendor_id"], row["product_id"])
        exact_index.setdefault(normalize(row["name"]), set()).add(target)
    mapping_names = [row["name"] for row in mappings]
    known_product_keys, protected_parent_keys = product_family_context(mapping_names)
    for row in mappings:
        target = (row["vendor_id"], row["product_id"])
        family = validated_product_family(
            row["name"], known_product_keys, protected_parent_keys
        )
        family_index.setdefault(normalize(family), set()).add(target)
    relation_index: dict[str, set[str]] = {}
    for row in relations:
        relation_index.setdefault(normalize(row["product_name"]), set()).add(
            normalize(row["vendor_name"])
        )
    vendor_id_index: dict[str, set[str]] = {}
    vendor_display_by_id: dict[str, set[str]] = {}
    for row in vendor_mappings:
        vendor_id_index.setdefault(normalize(row["name"]), set()).add(row["vendor_id"])
        vendor_display_by_id.setdefault(row["vendor_id"], set()).add(row["name"])
    exact_jobs: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    vendor_product_names: dict[str, set[str]] = {}
    watched_vendor_ids: set[str] = set()
    keyword_jobs: dict[tuple[str, str, str], tuple[str, str, str, str]] = {}
    for _kind, selected_name in entries:
        selected_key = normalize(selected_name)
        selected_vendors = relation_index.get(selected_key, set())
        allowed_vendor_ids = {
            vendor_id
            for vendor in selected_vendors
            for vendor_id in vendor_id_index.get(vendor, set())
        }
        watched_vendor_ids.update(allowed_vendor_ids)
        all_exact_targets = exact_index.get(selected_key, set())
        vendor_exact_targets = {
            target for target in all_exact_targets if target[0] in allowed_vendor_ids
        }
        # The exact catalogue product identity is authoritative. Vendor display
        # aliases are only a disambiguation hint when the same display product
        # maps to multiple raw vendors; a missing alias must never discard an
        # otherwise unique exact product CPE.
        exact_targets = (
            vendor_exact_targets
            if vendor_exact_targets
            else all_exact_targets
        )
        version_targets = {
            target
            for target in family_index.get(selected_key, set())
            if not allowed_vendor_ids or target[0] in allowed_vendor_ids
        }
        family_targets: set[tuple[str, str]] = set()
        if not exact_targets:
            family_targets = {
                (row["vendor_id"], row["product_id"])
                for row in mappings
                if name_matches(selected_name, row["name"])
                and (not allowed_vendor_ids or row["vendor_id"] in allowed_vendor_ids)
            }
        # Some vendors model releases in the CPE version component, while
        # others create separate product ids (for example windows_11_23h2 and
        # Check Point ... R81.20). Include only descendants whose display name
        # differs by a trailing version token; similarly named products such as
        # Windows 10 Mobile remain separate families.
        targets = (exact_targets | version_targets) if exact_targets else family_targets
        if not targets:
            job = ("keyword", selected_name, "", selected_name)
            keyword_jobs[job[:3]] = job
        else:
            for vendor_id, product_id in targets:
                job = ("product", vendor_id, product_id, selected_name)
                exact_jobs[(vendor_id, product_id)] = job
                vendor_product_names.setdefault(vendor_id, set()).add(selected_name)
    jobs = dict(keyword_jobs)
    targets_by_vendor: dict[str, list[tuple[str, str, str, str]]] = {}
    for (vendor_id, _product_id), job in exact_jobs.items():
        targets_by_vendor.setdefault(vendor_id, []).append(job)
    for vendor_id, vendor_jobs in targets_by_vendor.items():
        if len(vendor_jobs) > max_cpe_targets_per_vendor:
            selected_names = sorted(vendor_product_names[vendor_id], key=natural_key)
            label = "、".join(selected_names)
            job = ("vendor", vendor_id, "*", label)
            jobs[job[:3]] = job
        else:
            for job in vendor_jobs:
                jobs[job[:3]] = job
    # Fresh CNA records commonly reach NVD before configurations and CPE
    # matches are populated. Every watched vendor therefore gets one compact
    # keyword fallback, whether one product or the complete line is selected.
    # save_cve still enforces the selected product/full-line scope.
    for vendor_id in watched_vendor_ids:
        displays = sorted(vendor_display_by_id.get(vendor_id, set()), key=natural_key)
        if displays:
            display = displays[0]
            keyword_job = ("keyword", display, "", f"{display} 關注產品")
            jobs[keyword_job[:3]] = keyword_job
    return sorted(jobs.values(), key=lambda job: natural_key(":".join(job)))


def _translation_worker(work_queue: queue.Queue[tuple[str, str, str, str]]) -> None:
    while True:
        cve_id, title_en, description_en, expected_description = work_queue.get()
        key = (cve_id, expected_description)
        translated = False
        try:
            description_zh = translate_zh(description_en)
            # Titles are derived from the first sentence of the description
            # when the CVE is stored, so translating the description once is
            # both consistent and half as many Google requests.
            title_zh = make_title(description_zh, cve_id)
            with db() as conn:
                conn.execute(
                    "UPDATE vulnerabilities SET title_zh=?, description_zh=?, translation_ready=1 "
                    "WHERE cve_id=? AND description_en=?",
                    (title_zh, description_zh, cve_id, expected_description),
                )
            translated = True
        except Exception:
            # Keep the database row unfinished and retry it later.  The retry
            # is deliberately independent from the NVD update result.
            with translation_lock:
                attempt = translation_retry_attempts.get(key, 0) + 1
                translation_retry_attempts[key] = attempt
            delay = min(300, 5 * (2 ** min(attempt - 1, 6)))
            with translation_lock:
                translation_state["failed"] = int(translation_state["failed"]) + 1
                translation_state["retrying"] = int(translation_state["retrying"]) + 1
                translation_state["last_error"] = "中文翻譯服務暫時無法連線，將自動重試"
                translation_state["retry_after"] = delay
                translation_state["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")

            def retry() -> None:
                with translation_lock:
                    translation_retry_timers.discard(timer)
                    translation_state["retrying"] = max(
                        0, int(translation_state["retrying"]) - 1
                    )
                    if not translation_state["retrying"]:
                        translation_state["last_error"] = None
                        translation_state["retry_after"] = None
                    # The row may have been translated by a later update.
                    if key not in translation_queued_keys:
                        return
                work_queue.put((cve_id, title_en, description_en, expected_description))

            timer = threading.Timer(delay, retry)
            timer.daemon = True
            with translation_lock:
                translation_retry_timers.add(timer)
            timer.start()
        finally:
            with translation_lock:
                # A failed job keeps its key and pending count while its timer
                # waits.  A successful job becomes visible to the Chinese UI.
                if translated:
                    translation_queued_keys.discard(key)
                    translation_retry_attempts.pop(key, None)
                    translation_state["pending"] = max(0, int(translation_state["pending"]) - 1)
                    translation_state["completed"] = int(translation_state["completed"]) + 1
                    if not translation_state["retrying"]:
                        translation_state["last_error"] = None
                        translation_state["retry_after"] = None
                    translation_state["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            work_queue.task_done()


def queue_translations(jobs: list[tuple[str, str, str, str]]) -> int:
    global translation_thread
    if not jobs or BeautifulSoup is None:
        return 0
    work_queue = translation_queue
    with translation_lock:
        new_jobs: list[tuple[str, str, str, str]] = []
        for job in jobs:
            key = (job[0], job[3])
            if key in translation_queued_keys:
                continue
            translation_queued_keys.add(key)
            new_jobs.append(job)
        translation_state["pending"] = int(translation_state["pending"]) + len(new_jobs)
        if translation_thread is None or not translation_thread.is_alive():
            translation_thread = threading.Thread(target=_translation_worker, args=(work_queue,), daemon=True)
            translation_thread.start()
    for job in new_jobs:
        work_queue.put(job)
    return len(new_jobs)


def resume_unfinished_translations() -> int:
    """Resume persisted untranslated rows after application startup."""
    return queue_translations(untranslated_jobs())


def translation_progress_counts() -> tuple[int, int]:
    """Return (completed, total) persisted Chinese-translation progress."""
    with db() as conn:
        row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN translation_ready=1 THEN 1 ELSE 0 END) AS completed,
                COUNT(*) AS total
            FROM vulnerabilities
            WHERE trim(coalesce(description_en,'')) <> ''
            """
        ).fetchone()
    return int(row["completed"] or 0), int(row["total"] or 0)


def cancel_translation_retries() -> None:
    """Test/shutdown helper that prevents delayed retries from touching a closed DB."""
    with translation_lock:
        timers = list(translation_retry_timers)
        translation_retry_timers.clear()
        translation_retry_attempts.clear()
        translation_queued_keys.clear()
        translation_state["pending"] = 0
        translation_state["retrying"] = 0
        translation_state["last_error"] = None
        translation_state["retry_after"] = None
    for timer in timers:
        timer.cancel()


def untranslated_jobs() -> list[tuple[str, str, str, str]]:
    """Return stored CVEs whose Chinese fields still contain the English fallback."""
    with db() as conn:
        rows = conn.execute(
            """
            SELECT cve_id,title_en,description_en
            FROM vulnerabilities
            WHERE trim(coalesce(description_en,'')) <> ''
              AND translation_ready=0
            ORDER BY published DESC,cve_id
            """
        ).fetchall()
    return [
        (row["cve_id"], row["title_en"], row["description_en"], row["description_en"])
        for row in rows
    ]


def save_cve(
    cve: dict[str, Any],
    watched_entries: list[tuple[str, str]],
    translation_jobs: list[tuple[str, str, str, str]] | None = None,
) -> bool:
    import json

    cve_id = cve.get("id", "")
    vendors, products, versions = extract_products(cve)
    description = english_description(cve)
    # Some fresh CVEs have incomplete CPE data; the NVD description is still useful for watch matching.
    if not record_matches_watchlist(vendors, products, versions, description, watched_entries):
        return False
    if not vendors and not products and not versions:
        description_key = normalize(description)
        vendors = sorted(
            {
                name
                for kind, name in watched_entries
                if kind == "vendor" and normalize(name) in description_key
            },
            key=natural_key,
        )
        products = sorted(
            {
                name
                for kind, name in watched_entries
                if kind == "product" and normalize(name) in description_key
            },
            key=natural_key,
        )
    score, severity = metric(cve)
    title_en = make_title(description, cve_id)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    with db() as conn:
        existing = conn.execute(
            "SELECT description_en, title_zh, description_zh, translation_ready "
            "FROM vulnerabilities WHERE cve_id=?", (cve_id,)
        ).fetchone()
        needs_translation = (
            not existing
            or existing["description_en"] != description
            or not (existing["description_zh"] or "").strip()
            or existing["description_zh"] == description
        )
        title_zh = title_en if needs_translation else existing["title_zh"]
        description_zh = description if needs_translation else existing["description_zh"]
        translation_ready = 0 if needs_translation else int(existing["translation_ready"])
        if needs_translation and translation_jobs is not None:
            translation_jobs.append((cve_id, title_en, description, description))
        conn.execute(
            """
            INSERT INTO vulnerabilities (
              cve_id, published, modified, severity, score, title_en, title_zh,
              description_en, description_zh, vendors, products, affected_versions,
              references_json, source, translation_ready
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
              published=excluded.published, modified=excluded.modified, severity=excluded.severity,
              score=excluded.score, title_en=excluded.title_en, title_zh=excluded.title_zh,
              description_en=excluded.description_en, description_zh=excluded.description_zh,
              vendors=excluded.vendors, products=excluded.products,
              affected_versions=excluded.affected_versions, references_json=excluded.references_json,
              translation_ready=excluded.translation_ready
            """,
            (
                cve_id,
                cve.get("published", "")[:10],
                cve.get("lastModified", "")[:10],
                severity,
                score,
                title_en,
                title_zh,
                description,
                description_zh,
                json.dumps(vendors, ensure_ascii=False),
                json.dumps(products, ensure_ascii=False),
                json.dumps(versions, ensure_ascii=False),
                json.dumps(refs, ensure_ascii=False),
                "NVD",
                translation_ready,
            ),
        )
    return True


def _update_worker(days: int = 30) -> None:
    global update_state
    try:
        with db() as conn:
            watch_rows = conn.execute(
                "SELECT vendor_name,product_name FROM watch_vendor_products "
                "ORDER BY vendor_name,product_name"
            ).fetchall()
            watched_entries = [
                ("product", product_name)
                for product_name in sorted(
                    {str(row["product_name"]) for row in watch_rows}, key=natural_key
                )
            ]
            watch_relations = sorted(
                {
                    (normalize(str(row["vendor_name"])), normalize(str(row["product_name"])))
                    for row in watch_rows
                }
            )
            last_success_row = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_last_success_at'"
            ).fetchone()
            last_products_row = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_watch_products'"
            ).fetchone()
            strategy_row = conn.execute(
                "SELECT value FROM app_meta WHERE key='vulnerability_query_strategy_version'"
            ).fetchone()
        match_entries = watched_entries + fully_watched_vendor_entries()
        fingerprint_payload = sorted(
            {(kind, normalize(name)) for kind, name in match_entries}
        )
        watch_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "strategy": PRODUCT_QUERY_STRATEGY_VERSION,
                    "watch": fingerprint_payload,
                    "relations": watch_relations,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with update_lock:
            update_state.update(
                progress=2,
                message=f"正在準備 {len(watched_entries)} 個關注產品…",
            )

        last_success = _parse_catalog_time(last_success_row["value"] if last_success_row else None)
        try:
            previous_products = json.loads(last_products_row["value"]) if last_products_row else []
            if not isinstance(previous_products, list):
                previous_products = []
        except (TypeError, json.JSONDecodeError):
            previous_products = []
        current_by_key = {normalize(name): name for _kind, name in watched_entries}
        previous_keys = {normalize(str(name)) for name in previous_products}
        has_baseline = bool(
            last_success
            and last_products_row
            and strategy_row
            and strategy_row["value"] == PRODUCT_QUERY_STRATEGY_VERSION
        )
        new_entries = (
            [entry for entry in watched_entries if normalize(entry[1]) not in previous_keys]
            if has_baseline
            else list(watched_entries)
        )

        def report_product_resolution(processed: int, total: int, name: str) -> None:
            with update_lock:
                if total:
                    update_state.update(
                        progress=2 + round(processed / total * 6),
                        message=f"正在識別新加入的產品 {processed}/{total}"
                        + (f"：{name}" if name else ""),
                    )
                else:
                    update_state.update(
                        progress=8,
                        message="產品資料已準備完成，正在建立搜尋工作…",
                    )

        with db() as conn:
            active_run = conn.execute(
                "SELECT * FROM vulnerability_update_runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if active_run and active_run["watch_fingerprint"] != watch_fingerprint:
                # A changed watch list makes the old download plan invalid.
                # Only temporary data is discarded; the live vulnerability
                # table remains untouched until a new update succeeds.
                conn.execute("DELETE FROM vulnerability_update_candidates")
                conn.execute("DELETE FROM vulnerability_update_jobs")
                conn.execute("DELETE FROM vulnerability_update_runs")
                active_run = None

        resumed = active_run is not None
        if active_run is None:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=max(1, min(days, 120)))
            if new_entries:
                resolve_watch_cpe_mappings(new_entries, report_product_resolution)
            with update_lock:
                update_state.update(
                    progress=8,
                    message=(
                        f"正在建立 {len(new_entries)} 個新產品的搜尋工作…"
                        if has_baseline
                        else "正在建立漏洞搜尋工作…"
                    ),
                )
            planned_jobs: list[tuple[str, str, str, str, datetime, datetime]] = []
            for mode, value, product_id, product_name in product_query_jobs(new_entries):
                planned_jobs.append((mode, value, product_id, product_name, start, end))
            if has_baseline and last_success and watched_entries:
                incremental_start = max(
                    end - timedelta(days=120),
                    min(last_success, end) - timedelta(minutes=2),
                )
                planned_jobs.append(
                    ("modified", "", "", "最新漏洞變更", incremental_start, end)
                )
            run_id = uuid.uuid4().hex
            created_at = datetime.now().astimezone().isoformat(timespec="seconds")
            with db() as conn:
                # There can be only one resumable vulnerability update. Clear
                # abandoned temporary rows left by much older application builds.
                conn.execute("DELETE FROM vulnerability_update_candidates")
                conn.execute("DELETE FROM vulnerability_update_jobs")
                conn.execute("DELETE FROM vulnerability_update_runs")
                conn.execute(
                    "INSERT INTO vulnerability_update_runs "
                    "(run_id,watch_fingerprint,range_start,range_end,created_at) VALUES (?,?,?,?,?)",
                    (
                        run_id,
                        watch_fingerprint,
                        start.isoformat(timespec="seconds"),
                        end.isoformat(timespec="seconds"),
                        created_at,
                    ),
                )
                conn.executemany(
                    "INSERT INTO vulnerability_update_jobs "
                    "(run_id,job_order,mode,value,product_id,product_name,range_start,range_end,status) "
                    "VALUES (?,?,?,?,?,?,?,?, 'pending')",
                    [
                        (
                            run_id,
                            order,
                            mode,
                            value,
                            product_id,
                            product_name,
                            job_start.isoformat(timespec="seconds"),
                            job_end.isoformat(timespec="seconds"),
                        )
                        for order, (mode, value, product_id, product_name, job_start, job_end)
                        in enumerate(planned_jobs)
                    ],
                )
        else:
            run_id = str(active_run["run_id"])
            with update_lock:
                update_state.update(
                    progress=5,
                    message="正在繼續上次未完成的漏洞更新…",
                )

        # Completed product searches are never repeated. Each job and all of
        # its downloaded CVEs are committed in one SQLite transaction.
        while True:
            with db() as conn:
                job_rows = conn.execute(
                    "SELECT * FROM vulnerability_update_jobs WHERE run_id=? ORDER BY job_order",
                    (run_id,),
                ).fetchall()
            total_steps = max(len(job_rows), 1)
            for row in job_rows:
                if row["status"] == "completed":
                    continue
                job_order = int(row["job_order"])
                mode = str(row["mode"])
                product_name = str(row["product_name"])
                resume_index = int(row["next_start_index"] or 0)
                job_start = datetime.fromisoformat(str(row["range_start"])).astimezone(timezone.utc)
                job_end = datetime.fromisoformat(str(row["range_end"])).astimezone(timezone.utc)
                with update_lock:
                    update_state.update(
                        progress=10 + round(job_order / total_steps * 65),
                        message=(
                            "正在檢查最新漏洞變更…"
                            if mode == "modified"
                            else f"正在搜尋 {product_name}"
                        ),
                    )

                def report_download(processed: int, total: int, index: int = job_order) -> None:
                    base = 10 + round(index / total_steps * 65)
                    share = round(processed / max(total, 1) * (65 / total_steps))
                    with update_lock:
                        update_state.update(
                            progress=min(75, base + share),
                            message=(
                                f"正在下載漏洞資訊 {processed:,}/{total:,}"
                                if total > 0
                                else "正在確認漏洞資訊…"
                            ),
                        )

                def persist_download_page(
                    page: list[dict[str, Any]],
                    next_start_index: int,
                    total_results: int,
                    current_run_id: str = run_id,
                    current_job_order: int = job_order,
                ) -> None:
                    compressed_rows = [
                        (
                            current_run_id,
                            str(cve.get("id", "")),
                            gzip.compress(
                                json.dumps(
                                    cve,
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ).encode("utf-8"),
                                compresslevel=5,
                            ),
                        )
                        for cve in page
                        if cve.get("id")
                    ]
                    with db() as conn:
                        conn.executemany(
                            "INSERT OR REPLACE INTO vulnerability_update_candidates "
                            "(run_id,cve_id,payload_json) VALUES (?,?,?)",
                            compressed_rows,
                        )
                        conn.execute(
                            "UPDATE vulnerability_update_jobs "
                            "SET next_start_index=?,total_results=? "
                            "WHERE run_id=? AND job_order=?",
                            (
                                next_start_index,
                                total_results,
                                current_run_id,
                                current_job_order,
                            ),
                        )

                if mode == "keyword":
                    fetched = fetch_term(
                        str(row["value"]),
                        job_start,
                        job_end,
                        report_download,
                        start_index=resume_index,
                        page_callback=persist_download_page,
                    )
                elif mode == "modified":
                    fetched = fetch_modified_cves(
                        job_start,
                        job_end,
                        report_download,
                        start_index=resume_index,
                        page_callback=persist_download_page,
                    )
                else:
                    fetched = fetch_cpe_target(
                        str(row["value"]),
                        str(row["product_id"]),
                        job_start,
                        job_end,
                        report_download,
                        start_index=resume_index,
                        page_callback=persist_download_page,
                    )
                candidate_rows = [
                    (
                        run_id,
                        str(cve.get("id", "")),
                        gzip.compress(
                            json.dumps(cve, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                            compresslevel=5,
                        ),
                    )
                    for cve in fetched
                    if cve.get("id")
                ]
                with db() as conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO vulnerability_update_candidates "
                        "(run_id,cve_id,payload_json) VALUES (?,?,?)",
                        candidate_rows,
                    )
                    conn.execute(
                        "UPDATE vulnerability_update_jobs SET status='completed' "
                        "WHERE run_id=? AND job_order=?",
                        (run_id, job_order),
                    )
                if not has_nvd_api_key():
                    time.sleep(6.2)

            # If an interrupted run is resumed later, append one compact
            # modification query so completion also catches everything that
            # changed while the application was closed.
            with db() as conn:
                run_row = conn.execute(
                    "SELECT * FROM vulnerability_update_runs WHERE run_id=?", (run_id,)
                ).fetchone()
                pending = conn.execute(
                    "SELECT 1 FROM vulnerability_update_jobs WHERE run_id=? AND status<>'completed' LIMIT 1",
                    (run_id,),
                ).fetchone()
            if pending:
                continue
            run_end = datetime.fromisoformat(str(run_row["range_end"])).astimezone(timezone.utc)
            catchup_end = datetime.now(timezone.utc)
            if resumed and watched_entries and catchup_end - run_end > timedelta(minutes=2):
                catchup_start = max(
                    catchup_end - timedelta(days=120), run_end - timedelta(minutes=2)
                )
                with db() as conn:
                    next_order = int(
                        conn.execute(
                            "SELECT COALESCE(MAX(job_order),-1)+1 FROM vulnerability_update_jobs WHERE run_id=?",
                            (run_id,),
                        ).fetchone()[0]
                    )
                    conn.execute(
                        "INSERT INTO vulnerability_update_jobs "
                        "(run_id,job_order,mode,value,product_id,product_name,range_start,range_end,status) "
                        "VALUES (?,?,?,?,?,?,?,?, 'pending')",
                        (
                            run_id,
                            next_order,
                            "modified",
                            "",
                            "",
                            "重新開啟後的最新漏洞變更",
                            catchup_start.isoformat(timespec="seconds"),
                            catchup_end.isoformat(timespec="seconds"),
                        ),
                    )
                    conn.execute(
                        "UPDATE vulnerability_update_runs SET range_end=? WHERE run_id=?",
                        (catchup_end.isoformat(timespec="seconds"), run_id),
                    )
                resumed = False
                continue
            break

        with db() as conn:
            candidate_rows = conn.execute(
                "SELECT payload_json FROM vulnerability_update_candidates WHERE run_id=? ORDER BY cve_id",
                (run_id,),
            ).fetchall()
            run_row = conn.execute(
                "SELECT * FROM vulnerability_update_runs WHERE run_id=?", (run_id,)
            ).fetchone()
        seen = [
            json.loads(gzip.decompress(row["payload_json"]).decode("utf-8"))
            for row in candidate_rows
        ]
        saved = 0
        translation_jobs: list[tuple[str, str, str, str]] = []
        for index, cve in enumerate(seen, start=1):
            if save_cve(cve, match_entries, translation_jobs):
                saved += 1
            with update_lock:
                update_state.update(
                    progress=76 + round(index / max(len(seen), 1) * 20),
                    message=f"正在整理漏洞資料 {index}/{len(seen)}",
                )
        pending_by_cve = {job[0]: job for job in untranslated_jobs()}
        pending_by_cve.update({job[0]: job for job in translation_jobs})
        pending_translation_jobs = list(pending_by_cve.values())
        queued_translations = queue_translations(pending_translation_jobs)

        # Translation is a best-effort background task.  NVD data, purge and
        # retention are already committed safely, so a temporary Google
        # translation failure must not turn a successful vulnerability update
        # into an error or make the user repeat the download.
        purged = purge_unwatched_vulnerabilities(match_entries)
        archived, expired = maintain_vulnerability_retention()
        completed_end = datetime.fromisoformat(str(run_row["range_end"])).astimezone(timezone.utc)
        with db() as conn:
            recent_total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE archived=0"
                ).fetchone()[0]
            )
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key,value) VALUES ('vulnerability_last_success_at',?)",
                (completed_end.isoformat(timespec="seconds"),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key,value) VALUES ('vulnerability_watch_products',?)",
                (json.dumps(sorted(current_by_key.values(), key=natural_key), ensure_ascii=False),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key,value) VALUES ('vulnerability_query_strategy_version',?)",
                (PRODUCT_QUERY_STRATEGY_VERSION,),
            )
            conn.execute("DELETE FROM app_meta WHERE key='vulnerability_watch_scope'")
            conn.execute("DELETE FROM vulnerability_update_candidates WHERE run_id=?", (run_id,))
            conn.execute("DELETE FROM vulnerability_update_jobs WHERE run_id=?", (run_id,))
            conn.execute("DELETE FROM vulnerability_update_runs WHERE run_id=?", (run_id,))
        with update_lock:
            result_parts = [f"更新完成，近 30 天內共有 {recent_total} 筆符合條件的漏洞"]
            if purged:
                result_parts.append(
                    f"移除 {purged} 筆不在關注名單的紀錄"
                )
            result_parts.append(f"目前共有 {archived} 筆舊有紀錄歸檔")
            if expired:
                result_parts.append(
                    f"刪除 {expired} 筆超過 90 天的紀錄"
                )
            if queued_translations:
                result_parts.append(f"中文翻譯正在背景處理 {queued_translations} 筆")
            update_state.update(
                running=False,
                progress=100,
                message="；".join(result_parts),
                updated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                error=None,
            )
    except Exception as exc:
        if isinstance(exc, TranslationUnavailableError):
            friendly = "漏洞列表已下載，但中文翻譯服務暫時無法連線；下次更新會自動重試"
        elif isinstance(exc, requests.RequestException):
            friendly = "無法連接 NVD 資料庫，請檢查網絡或稍後重試"
        else:
            friendly = "更新資料時發生問題，請稍後重試"
        with update_lock:
            update_state.update(running=False, message="更新未完成", error=friendly)


def update_worker(days: int = 30) -> None:
    if not nvd_job_lock.acquire(blocking=False):
        with update_lock:
            update_state.update(
                progress=1,
                message="正在等待其他資料更新完成…",
            )
        nvd_job_lock.acquire()
    try:
        _update_worker(days)
    finally:
        nvd_job_lock.release()


def start_update(days: int = 30) -> bool:
    with update_lock:
        if update_state["running"]:
            return False
        update_state.update(running=True, progress=1, message="正在準備漏洞列表更新…", error=None)
    threading.Thread(target=update_worker, args=(days,), daemon=True).start()
    return True


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    import json

    item = dict(row)
    for key in ("vendors", "products", "affected_versions", "references_json"):
        item[key] = json.loads(item[key] or "[]")
    item["references"] = item.pop("references_json")
    return item


def _catalog_page_request(params: dict[str, Any]) -> requests.Response:
    """Fetch one bounded CPE page, retrying transient connection failures."""
    for attempt in range(3):
        try:
            response = nvd_get(NVD_CPE_URL, params=params, timeout=120)
            # Some NVD deployments reject an API key with a bare HTTP 404 and
            # no `message: Invalid apiKey` header. Verify the same request once
            # anonymously before treating the CPE query itself as invalid.
            if response.status_code == 404 and has_nvd_api_key():
                anonymous = requests.get(
                    NVD_CPE_URL,
                    params=params,
                    headers={},
                    timeout=120,
                )
                if anonymous.ok:
                    clear_nvd_api_key()
                    return anonymous
            if response.status_code in {400, 404} and attempt < 2:
                time.sleep(2.0 * (2 ** attempt))
                continue
            return response
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise
            time.sleep(2.0 * (2 ** attempt))
    raise RuntimeError("unreachable catalogue request state")


def _catalog_failure_message(exc: Exception) -> str:
    """Describe the real catalogue failure without masking every case as offline."""
    suffix = "，已保存進度，重新更新時會自動繼續"
    if isinstance(exc, requests.Timeout):
        return "產品名單下載逾時" + suffix
    if isinstance(exc, requests.ConnectionError):
        return "網絡連線中斷，請檢查網絡後重試" + suffix
    if isinstance(exc, requests.HTTPError):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        nvd_message = str(getattr(response, "headers", {}).get("message", "")).strip()
        detail = f"，HTTP {status}" if status is not None else ""
        if nvd_message:
            detail += f"：{nvd_message}"
        if status == 429:
            return "NVD請求過於頻繁，請稍後重試" + suffix
        if status is not None and 500 <= int(status):
            return "NVD產品名單服務暫時異常，請稍後重試" + suffix
        return "NVD產品名單回應異常" + detail + suffix
    if isinstance(exc, requests.RequestException):
        return "NVD產品名單請求失敗，請稍後重試" + suffix
    if isinstance(exc, (ValueError, json.JSONDecodeError)):
        return "NVD產品名單資料格式異常，請稍後重試" + suffix
    return "同步產品名單時發生問題" + suffix


def _catalog_sync_worker(full_sync: bool, incremental_start: datetime | None = None) -> None:
    try:
        sync_end = datetime.now(timezone.utc)
        resume_window = 0
        resume_index = 0
        incremental_state: dict[str, Any] | None = None
        if full_sync:
            with db() as conn:
                checkpoint = conn.execute("SELECT value FROM app_meta WHERE key='catalog_full_sync_start_index'").fetchone()
            windows: list[tuple[datetime | None, datetime | None]] = [(None, None)]
            resume_index = int(checkpoint["value"]) if checkpoint else 0
        else:
            with db() as conn:
                resume_row = conn.execute(
                    "SELECT value FROM app_meta WHERE key=?",
                    (CATALOG_INCREMENTAL_STATE_KEY,),
                ).fetchone()
            if resume_row:
                try:
                    incremental_state = json.loads(str(resume_row["value"]))
                    raw_windows = incremental_state["windows"]
                    windows = [
                        (_parse_catalog_time(str(start)), _parse_catalog_time(str(end)))
                        for start, end in raw_windows
                    ]
                    if not windows or any(start is None or end is None for start, end in windows):
                        raise ValueError("invalid catalogue resume windows")
                    sync_end = _parse_catalog_time(str(incremental_state["sync_end"])) or sync_end
                    resume_window = max(0, int(incremental_state.get("window_index", 0)))
                    resume_index = max(0, int(incremental_state.get("start_index", 0)))
                    resume_total = max(0, int(incremental_state.get("total", 0)))
                    resume_processed = resume_total if resume_window >= len(windows) else resume_index
                    with catalog_lock:
                        catalog_state.update(
                            processed=resume_processed,
                            total=resume_total,
                            progress=round(resume_processed / max(resume_total, 1) * 100) if resume_total else 0,
                            message=(
                                f"正在繼續上次未完成的產品名單更新：NVD名單紀錄 "
                                f"{resume_processed:,}/{resume_total:,}"
                                if resume_total
                                else (
                                    f"正在繼續上次未完成的產品名單更新：已處理 {resume_processed:,} 筆"
                                    if resume_processed
                                    else "正在重新連接 NVD 產品名單…"
                                )
                            ),
                        )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    with db() as conn:
                        conn.execute(
                            "DELETE FROM app_meta WHERE key=?",
                            (CATALOG_INCREMENTAL_STATE_KEY,),
                        )
                    incremental_state = None
            if incremental_state is None:
                start = incremental_start or sync_end - timedelta(days=7)
                windows = []
                while start < sync_end:
                    window_end = min(start + timedelta(days=119), sync_end)
                    windows.append((start, window_end))
                    start = window_end
                incremental_state = {
                    "version": 1,
                    "sync_end": sync_end.isoformat(),
                    "windows": [
                        [start.isoformat(), end.isoformat()]
                        for start, end in windows
                        if start is not None and end is not None
                    ],
                    "window_index": 0,
                    "start_index": 0,
                    "total": 0,
                }
                with db() as conn:
                    conn.execute(
                        "INSERT INTO app_meta(key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (CATALOG_INCREMENTAL_STATE_KEY, json.dumps(incremental_state, separators=(",", ":"))),
                    )

        with db() as conn:
            vendor_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='vendor'").fetchone()[0]
            product_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='product'").fetchone()[0]
        restarted_windows: set[int] = set()
        for window_index in range(resume_window, len(windows)):
            modified_start, modified_end = windows[window_index]
            start_index = resume_index if window_index == resume_window else 0
            while True:
                params: dict[str, Any] = {"resultsPerPage": CATALOG_PAGE_SIZE, "startIndex": start_index}
                if modified_start and modified_end:
                    params.update(
                        lastModStartDate=modified_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        lastModEndDate=modified_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    )
                response = _catalog_page_request(params)
                if response.status_code == 404 and start_index > 0 and window_index not in restarted_windows:
                    # CPEs can be modified again while a fixed modified-date
                    # window is being paged, which may shrink the result set
                    # and invalidate a saved startIndex. Restart this window;
                    # INSERT OR IGNORE keeps the already stored rows unique.
                    restarted_windows.add(window_index)
                    start_index = 0
                    if incremental_state is not None:
                        incremental_state.update(
                            window_index=window_index,
                            start_index=0,
                            total=0,
                        )
                        with db() as conn:
                            conn.execute(
                                "INSERT INTO app_meta(key, value) VALUES (?, ?) "
                                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                (
                                    CATALOG_INCREMENTAL_STATE_KEY,
                                    json.dumps(incremental_state, separators=(",", ":")),
                                ),
                            )
                    with catalog_lock:
                        catalog_state.update(
                            processed=0,
                            total=0,
                            progress=0,
                            message="NVD產品名單頁碼已變更，正在自動重新定位…",
                        )
                    continue
                response.raise_for_status()
                payload = response.json()
                records = payload.get("products", [])
                total = int(payload.get("totalResults", 0))
                inserts: set[tuple[str, str]] = set()
                cpe_inserts: set[tuple[str, str, str, str, str]] = set()
                for record in records:
                    cpe = record.get("cpe", {})
                    parts = cpe.get("cpeName", "").split(":")
                    if len(parts) >= 5:
                        vendor = pretty_token(parts[3])
                        product = f"{vendor} {pretty_token(parts[4])}".strip()
                        if not cpe.get("deprecated"):
                            inserts.update({("vendor", vendor), ("product", product)})
                            cpe_inserts.update(
                                {
                                    ("vendor", vendor, "*", parts[3], "*"),
                                    ("product", product, parts[2], parts[3], parts[4]),
                                }
                            )
                next_index = start_index + len(records)
                window_complete = not records or next_index >= total
                with db() as conn:
                    conn.executemany("INSERT OR IGNORE INTO catalog VALUES (?, ?)", inserts)
                    conn.executemany(
                        "INSERT OR IGNORE INTO catalog_cpe(kind, name, part, vendor_id, product_id) VALUES (?, ?, ?, ?, ?)",
                        cpe_inserts,
                    )
                    if full_sync:
                        conn.execute(
                            "INSERT INTO app_meta(key, value) VALUES ('catalog_full_sync_start_index', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (str(next_index),),
                        )
                    elif incremental_state is not None:
                        incremental_state.update(
                            window_index=window_index + 1 if window_complete else window_index,
                            start_index=0 if window_complete else next_index,
                            total=total,
                        )
                        conn.execute(
                            "INSERT INTO app_meta(key, value) VALUES (?, ?) "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (
                                CATALOG_INCREMENTAL_STATE_KEY,
                                json.dumps(incremental_state, separators=(",", ":")),
                            ),
                        )
                    vendor_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='vendor'").fetchone()[0]
                    product_count = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='product'").fetchone()[0]
                mode_label = "首次建立本機索引" if full_sync else "增量更新"
                with catalog_lock:
                    catalog_state.update(
                        total=total,
                        processed=next_index,
                        progress=round(next_index / max(total, 1) * 100),
                        unique_vendors=vendor_count,
                        unique_products=product_count,
                        message=f"{mode_label}：NVD名單紀錄 {next_index:,}/{total:,}；目前廠商紀錄：{vendor_count:,}，產品紀錄：{product_count:,}",
                    )
                if window_complete:
                    break
                start_index = next_index
                time.sleep(0.6 if has_nvd_api_key() else 6.2)
        # Do not verify deprecated CPEs one product at a time. A deprecated
        # version does not mean its whole product family is obsolete, and the
        # extra requests quickly trigger NVD's anonymous rate limit. The
        # bundled catalogue snapshot is periodically rebuilt to remove truly
        # obsolete names; incremental updates are deliberately additions-only.
        completed_at = sync_end.astimezone().isoformat(timespec="seconds")
        with db() as conn:
            conn.execute(
                "INSERT INTO app_meta(key, value) VALUES ('catalog_full_sync_completed_at', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (completed_at,),
            )
            conn.execute("DELETE FROM app_meta WHERE key='catalog_full_sync_start_index'")
            conn.execute("DELETE FROM app_meta WHERE key=?", (CATALOG_INCREMENTAL_STATE_KEY,))
        with catalog_lock:
            catalog_state.update(
                running=False,
                progress=100,
                message=f"同步完成，目前廠商紀錄：{vendor_count:,}，產品紀錄：{product_count:,}",
                error=None,
                complete=True,
                completed_at=completed_at,
                unique_vendors=vendor_count,
                unique_products=product_count,
            )
    except Exception as exc:
        friendly = _catalog_failure_message(exc)
        with catalog_lock:
            catalog_state.update(running=False, message="產品名單同步已暫停", error=friendly)


def catalog_sync_worker(full_sync: bool, incremental_start: datetime | None = None) -> None:
    with nvd_job_lock:
        _catalog_sync_worker(full_sync, incremental_start)


def start_catalog_sync(force_full: bool = False) -> bool:
    with catalog_lock:
        if catalog_state["running"]:
            return False
        if not catalog_state["complete"] and not force_full:
            catalog_state.update(
                message="缺少隨附的廠商／產品索引，已停止以避免掃描完整 CPE 資料庫",
                error="請重新安裝或放回 data/nvd_catalog_snapshot.json.gz",
            )
            return False
        full_sync = force_full
        completed_at = catalog_state.get("completed_at")
        catalog_state.update(
            running=True,
            progress=0,
            processed=0,
            total=0,
            message="正在準備首次本機索引…" if full_sync else "正在查詢 NVD 增量變更…",
            error=None,
            mode="full" if full_sync else "incremental",
        )
    incremental_start = None
    if not full_sync and completed_at:
        try:
            incremental_start = datetime.fromisoformat(str(completed_at)).astimezone(timezone.utc) - timedelta(minutes=2)
        except ValueError:
            incremental_start = None
    threading.Thread(target=catalog_sync_worker, args=(full_sync, incremental_start), daemon=True).start()
    return True
