"""Measure first/subsequent initialization using a disposable full catalogue DB."""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402


def main() -> None:
    original_db = app.DB_PATH
    original_initialized = app._nvd_api_key_initialized
    try:
        with tempfile.TemporaryDirectory() as directory:
            app.DB_PATH = Path(directory) / "fresh.db"
            app._nvd_api_key_initialized = True
            started = time.perf_counter()
            app.init_db()
            first_seconds = time.perf_counter() - started
            with app.db() as conn:
                vendors = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='vendor'").fetchone()[0]
                products = conn.execute("SELECT COUNT(*) FROM catalog WHERE kind='product'").fetchone()[0]
                mappings = conn.execute("SELECT COUNT(*) FROM catalog_cpe WHERE kind='product'").fetchone()[0]
                watch_count = conn.execute("SELECT COUNT(*) FROM watch_vendor_products").fetchone()[0]
            started = time.perf_counter()
            app.init_db()
            repeat_seconds = time.perf_counter() - started
            if (vendors, products, mappings) != (24022, 148598, 149489):
                raise AssertionError(f"unexpected full catalogue counts: {(vendors, products, mappings)}")
            if watch_count != 0:
                raise AssertionError("fresh start unexpectedly created default watch products")
            print(
                "PASS disposable startup: "
                f"first={first_seconds:.2f}s, repeat={repeat_seconds:.2f}s, "
                f"vendors={vendors:,}, products={products:,}, mappings={mappings:,}"
            )
    finally:
        app.DB_PATH = original_db
        app._nvd_api_key_initialized = original_initialized


if __name__ == "__main__":
    main()
