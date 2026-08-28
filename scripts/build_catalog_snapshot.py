from __future__ import annotations

import argparse
import gzip
import json
import re
import tarfile
import unicodedata
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests


FEED_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip"
META_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta"

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


def normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def pretty_token(value: str) -> str:
    value = unquote(value).replace("\\!", "!").replace("_", " ").strip()
    key = normalize(value)
    if key in VENDOR_LABELS:
        return VENDOR_LABELS[key]
    return " ".join(word.upper() if word.lower() in {"sql", "http", "jdk"} else word.capitalize() for word in value.split())


def download(url: str, target: Path) -> None:
    partial = target.with_suffix(target.suffix + ".part")
    expected = int(requests.head(url, timeout=30).headers.get("content-length", 0))
    while not expected or not partial.exists() or partial.stat().st_size < expected:
        received = partial.stat().st_size if partial.exists() else 0
        headers = {"Range": f"bytes={received}-"} if received else {}
        with requests.get(url, headers=headers, stream=True, timeout=90) as response:
            response.raise_for_status()
            append = received > 0 and response.status_code == 206
            if not append:
                received = 0
            with partial.open("ab" if append else "wb") as output:
                for chunk in response.iter_content(1024 * 1024):
                    if not chunk:
                        continue
                    output.write(chunk)
                    received += len(chunk)
                    if expected:
                        print(f"Downloading CPE feed: {received / 1024 / 1024:.1f}/{expected / 1024 / 1024:.1f} MB", end="\r")
        if not expected:
            break
        if partial.stat().st_size > expected:
            raise RuntimeError("Downloaded CPE feed is larger than the official Content-Length")
    partial.replace(target)
    print()


def valid_feed(path: Path) -> bool:
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                return any(name.lower().endswith(".json") for name in archive.namelist())
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            return any(member.isfile() and member.name.lower().endswith(".json") for member in members)
    except (OSError, EOFError, tarfile.TarError):
        return False


def feed_modified_at() -> str:
    try:
        response = requests.get(META_URL, timeout=30)
        response.raise_for_status()
        for line in response.text.splitlines():
            if line.lower().startswith("lastmodifieddate:"):
                return line.split(":", 1)[1].strip()
    except requests.RequestException:
        pass
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build(feed_path: Path, output_path: Path) -> None:
    vendor_counts: Counter[str] = Counter()
    product_counts: Counter[str] = Counter()
    vendor_cpes: set[tuple[str, str]] = set()
    product_cpes: set[tuple[str, str, str, str]] = set()
    records = 0
    if zipfile.is_zipfile(feed_path):
        archive = zipfile.ZipFile(feed_path)
        members = [name for name in archive.namelist() if name.lower().endswith(".json")]
        streams = ((number, archive.open(name)) for number, name in enumerate(members, start=1))
    else:
        archive = tarfile.open(feed_path, "r:gz")
        members = [member for member in archive if member.isfile() and member.name.lower().endswith(".json")]
        streams = ((number, archive.extractfile(member)) for number, member in enumerate(members, start=1))
    with archive:
        for number, extracted in streams:
            if extracted is None:
                continue
            with extracted:
                payload = json.load(extracted)
            for record in payload.get("products", []):
                cpe = record.get("cpe", {})
                if cpe.get("deprecated"):
                    continue
                parts = cpe.get("cpeName", "").split(":")
                if len(parts) < 5:
                    continue
                vendor = pretty_token(parts[3])
                product = f"{vendor} {pretty_token(parts[4])}".strip()
                vendor_counts[vendor] += 1
                product_counts[product] += 1
                vendor_cpes.add((vendor, parts[3]))
                product_cpes.add((product, parts[2], parts[3], parts[4]))
                records += 1
            print(f"Processing feed chunks: {number}/{len(members)}", end="\r")
    print()
    snapshot = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": FEED_URL,
        "source_last_modified": feed_modified_at(),
        "active_cpe_records": records,
        "vendors": sorted(vendor_counts),
        "products": sorted(product_counts),
        "vendor_cpes": sorted(vendor_cpes),
        "product_cpes": sorted(product_cpes),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output_path, "wt", encoding="utf-8", compresslevel=9) as output:
        json.dump(snapshot, output, ensure_ascii=False, separators=(",", ":"))
    print(f"Snapshot written: {output_path}")
    print(f"Unique vendors: {len(vendor_counts):,}; unique products: {len(product_counts):,}")
    print(f"CPE mappings: {len(vendor_cpes):,} vendors; {len(product_cpes):,} products")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the bundled VulHub NVD vendor/product snapshot")
    parser.add_argument("--feed", type=Path, help="Use an existing NVD CPE .zip or .tar.gz feed")
    parser.add_argument("--output", type=Path, default=Path("data/nvd_catalog_snapshot.json.gz"))
    args = parser.parse_args()
    feed = args.feed or Path("data/nvdcpe-2.0.zip")
    if not feed.exists() or not valid_feed(feed):
        feed.parent.mkdir(parents=True, exist_ok=True)
        partial = feed.with_suffix(feed.suffix + ".part")
        if feed.exists() and not partial.exists():
            feed.replace(partial)
        download(FEED_URL, feed)
    build(feed, args.output)


if __name__ == "__main__":
    main()
