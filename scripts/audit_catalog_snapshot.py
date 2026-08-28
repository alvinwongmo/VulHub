"""Read-only integrity audit for the bundled NVD product catalogue snapshot."""

from __future__ import annotations

import gzip
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with gzip.open(app.CATALOG_SNAPSHOT_PATH, "rt", encoding="utf-8") as source:
        snapshot = json.load(source)

    vendors = [str(value) for value in snapshot.get("vendors", [])]
    products = [str(value) for value in snapshot.get("products", [])]
    vendor_cpes = [tuple(map(str, row)) for row in snapshot.get("vendor_cpes", [])]
    product_cpes = [tuple(map(str, row)) for row in snapshot.get("product_cpes", [])]

    require(len(vendors) == len(set(vendors)), "duplicate vendor display names")
    require(len(products) == len(set(products)), "duplicate product display names")
    require(len(vendor_cpes) == len(set(vendor_cpes)), "duplicate vendor CPE mappings")
    require(len(product_cpes) == len(set(product_cpes)), "duplicate product CPE mappings")
    require(all(len(row) == 2 and all(row) for row in vendor_cpes), "invalid vendor mapping")
    require(all(len(row) == 4 and all(row) for row in product_cpes), "invalid product mapping")

    vendor_names = set(vendors)
    product_names = set(products)
    require(all(row[0] in vendor_names for row in vendor_cpes), "orphan vendor mapping")
    require(all(row[0] in product_names for row in product_cpes), "orphan product mapping")
    mapped_products = {row[0] for row in product_cpes}
    require(not (product_names - mapped_products), "products without CPE mapping")

    # NVD contains legitimate aliases that differ only by punctuation or
    # spacing.  Record the amount for review, but do not treat those aliases as
    # corruption because the UI intentionally resolves them equivalently.
    normalized_product_counts = Counter(app.normalize(name) for name in products)
    alias_groups = sum(count > 1 for count in normalized_product_counts.values())

    expected_fragments = {
        "Microsoft Windows 10": "microsoftwindows10",
        "Microsoft Windows 11": "microsoftwindows11",
        "Red Hat Enterprise Linux": "redhatenterpriselinux",
        "Palo Alto Networks PAN-OS": "paloaltonetworkspanos",
        "Check Point Security Gateway": "checkpointsecuritygateway",
        "Vmware Vcenter Server": "vmwarevcenterserver",
    }
    normalized_products = {app.normalize(name): name for name in products}
    for label, key in expected_fragments.items():
        require(key in normalized_products, f"representative product missing: {label}")

    known_keys, protected_keys = app.product_family_context(products)
    collapsed = 0
    for name in products:
        family = app.validated_product_family(name, known_keys, protected_keys)
        if app.normalize(family) != app.normalize(name):
            collapsed += 1
            require(app.normalize(family) in known_keys, f"invalid family collapse: {name} -> {family}")

    print(
        "Catalogue audit passed: "
        f"{len(vendors):,} vendors, {len(products):,} products, "
        f"{len(product_cpes):,} product mappings, {collapsed:,} validated version descendants, "
        f"{alias_groups:,} normalized alias groups"
    )


if __name__ == "__main__":
    main()
