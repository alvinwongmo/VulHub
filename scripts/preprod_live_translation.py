"""Non-destructive live check for the English-to-Traditional-Chinese pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app  # noqa: E402


def main() -> None:
    samples = [
        "A vulnerability allows an attacker to execute code remotely",
        "The affected product must be updated to the latest version",
    ]
    outputs = [app.translate_zh(text) for text in samples]
    if not all(output and output != source for source, output in zip(samples, outputs)):
        raise AssertionError("translation service returned an empty or untranslated result")
    # OpenCC's Taiwanese conversion should eliminate these common Simplified
    # forms if Google happens to return mixed Chinese output.
    forbidden = {"漏洞允许", "攻击者", "软件", "网络"}
    if any(term in output for output in outputs for term in forbidden):
        raise AssertionError("translation result still contains common Simplified Chinese forms")
    print(f"PASS live Traditional-Chinese translation ({len(outputs)} samples)")


if __name__ == "__main__":
    main()
