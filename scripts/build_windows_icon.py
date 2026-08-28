"""Build a multi-resolution Windows ICO from VulHub's Qt vector drawing."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import desktop  # noqa: E402


SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def png_bytes(size: int) -> bytes:
    payload = QByteArray()
    buffer = QBuffer(payload)
    if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
        raise RuntimeError("Unable to open icon image buffer")
    if not desktop._render_app_icon(size).save(buffer, "PNG"):
        raise RuntimeError(f"Unable to render {size}x{size} icon")
    buffer.close()
    return bytes(payload)


def build_ico(target: Path) -> None:
    images = [(size, png_bytes(size)) for size in SIZES]
    header_size = 6 + 16 * len(images)
    offset = header_size
    entries: list[bytes] = []
    for size, payload in images:
        dimension = 0 if size == 256 else size
        entries.append(
            struct.pack(
                "<BBBBHHII",
                dimension,
                dimension,
                0,
                0,
                1,
                32,
                len(payload),
                offset,
            )
        )
        offset += len(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(
        struct.pack("<HHH", 0, 1, len(images))
        + b"".join(entries)
        + b"".join(payload for _, payload in images)
    )


def main() -> int:
    application = QApplication.instance() or QApplication([])
    target = PROJECT_ROOT / "assets" / "vulhub.ico"
    build_ico(target)
    print(f"Created {target} with {len(SIZES)} sizes")
    application.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
