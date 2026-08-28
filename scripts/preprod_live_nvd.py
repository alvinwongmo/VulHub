"""Temporary live integration checks against official NVD API 2.0 endpoints.

The API key is read without echo and kept only in process memory.  This script
never opens or writes the user's production vulhub.db.
"""

from __future__ import annotations

import getpass
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    supplied_key = getpass.getpass("NVD API Key: ").strip()
    require(bool(supplied_key), "API key was not supplied")

    # Do not call set_nvd_api_key: validation would persist into DB.  A mocked
    # setter keeps the verified key in memory only for this temporary process.
    original_setter = app.set_nvd_api_key
    original_clearer = app.clear_nvd_api_key
    original_key = app._nvd_api_key
    app.set_nvd_api_key = lambda key: setattr(app, "_nvd_api_key", key.strip())
    app.clear_nvd_api_key = lambda: setattr(app, "_nvd_api_key", "")
    try:
        valid, message, category = app.validate_nvd_api_key(supplied_key)
        require(valid and category == "success", f"key validation failed: {category}: {message}")
        print("PASS API key validation")

        payload = app.nvd_get(
            app.NVD_CVE_URL,
            params={"cveId": "CVE-2021-44228", "resultsPerPage": 1, "noRejected": ""},
            timeout=30,
        ).json()
        require(
            any(item.get("cve", {}).get("id") == "CVE-2021-44228" for item in payload.get("vulnerabilities", [])),
            "known CVE lookup did not return CVE-2021-44228",
        )
        print("PASS known CVE lookup")

        cpe_terms = [
            "Microsoft Windows 11",
            "Red Hat Enterprise Linux",
            "Palo Alto Networks PAN-OS",
            "Check Point Security Gateway",
            "VMware vCenter Server",
        ]
        for term in cpe_terms:
            response = app.nvd_get(
                app.NVD_CPE_URL,
                params={"keywordSearch": term, "resultsPerPage": 20},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            require(int(data.get("totalResults", 0)) > 0, f"no CPE result for {term}")
            print(f"PASS CPE lookup: {term} ({int(data['totalResults']):,} results)")

        now = datetime.now(timezone.utc)
        response = app.nvd_get(
            app.NVD_CVE_URL,
            params={
                "lastModStartDate": (now - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "resultsPerPage": 1,
                "noRejected": "",
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        require("vulnerabilities" in data and "totalResults" in data, "modified-CVE response schema mismatch")
        print(f"PASS recent modification query ({int(data['totalResults']):,} results)")

        recent_start = now - timedelta(days=30)
        recent_targets = [
            ("paloaltonetworks", "pan-os", "Palo Alto Networks PAN-OS"),
            ("paloaltonetworks", "firewall", "Palo Alto Networks Firewall"),
            ("vmware", "vcenter_server", "VMware vCenter Server"),
            ("vmware", "esxi", "VMware ESXi"),
            ("checkpoint", "security_gateway", "Check Point Security Gateway"),
        ]
        for vendor_id, product_id, label in recent_targets:
            rows = app.fetch_cpe_target(vendor_id, product_id, recent_start, now)
            require(all(row.get("id") for row in rows), f"invalid recent CVE data for {label}")
            print(f"PASS 30-day product query: {label} ({len(rows):,} CVEs)")

        for label in ("Palo Alto Networks", "VMware", "Check Point"):
            rows = app.fetch_term(label, recent_start, now)
            matched = 0
            for cve in rows:
                vendors, products, versions = app.extract_products(cve)
                if app.record_matches_watchlist(
                    vendors,
                    products,
                    versions,
                    app.english_description(cve),
                    [("vendor", label)],
                ):
                    matched += 1
            print(
                f"PASS 30-day vendor fallback: {label} "
                f"({len(rows):,} candidates, {matched:,} applicable)"
            )

        app._nvd_api_key = ""
        response = app.nvd_get(
            app.NVD_CVE_URL,
            params={"cveId": "CVE-2021-44228", "resultsPerPage": 1},
            timeout=30,
        )
        response.raise_for_status()
        require(int(response.json().get("totalResults", 0)) >= 1, "anonymous fallback lookup failed")
        print("PASS anonymous NVD mode")
    finally:
        app._nvd_api_key = original_key
        app.set_nvd_api_key = original_setter
        app.clear_nvd_api_key = original_clearer
        supplied_key = ""


if __name__ == "__main__":
    # Explicitly remove environment inheritance so only the interactive value
    # is used and nothing is written to a shell history or command line.
    os.environ.pop("NVD_API_KEY", None)
    main()
