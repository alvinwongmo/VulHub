"""Regression checks for user-facing terminology and punctuation."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = (PROJECT_ROOT / "app.py", PROJECT_ROOT / "desktop.py")


class UiWordingTests(unittest.TestCase):
    def test_visible_strings_use_current_terminology_and_no_chinese_full_stop(self) -> None:
        problems: list[str] = []
        for path in SOURCE_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                if "API KEY" in value:
                    problems.append(f"{path.name}:{node.lineno}: API KEY")
                if "漏洞紀錄歸檔" in value:
                    problems.append(f"{path.name}:{node.lineno}: 漏洞紀錄歸檔")
                if "產品名單中找不到" in value:
                    problems.append(f"{path.name}:{node.lineno}: 產品名單中找不到")
                # This exact internal character set is used to strip sentence
                # endings from NVD descriptions and is never displayed.
                if "。" in value and value != "。.":
                    problems.append(f"{path.name}:{node.lineno}: 中文句號")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
