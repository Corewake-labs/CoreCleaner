"""never-touch.txt follows the grammar in its own header (the contract safety.py parses)."""

import re
import unittest
from pathlib import Path

LIST = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "references" / "never-touch.txt"
SECTIONS = ("all", "macos", "linux", "windows")
MODES = ("tree", "node", "name")


def parse():
    section, rules = None, []
    for no, line in enumerate(LIST.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        header = re.fullmatch(r"\[(\w+)\]", line)
        if header:
            section = header.group(1)
            rules.append((no, section, "header", ""))
            continue
        mode, _, pattern = line.partition(" ")
        rules.append((no, section, mode, pattern))
    return rules


class NeverTouchFormat(unittest.TestCase):
    def test_every_line_is_header_or_valid_rule(self):
        seen_sections = []
        for no, section, mode, pattern in parse():
            where = "never-touch.txt:%d" % no
            if mode == "header":
                self.assertIn(section, SECTIONS, where)
                seen_sections.append(section)
                continue
            self.assertIsNotNone(section, where + " rule before any [section]")
            self.assertIn(mode, MODES, where)
            self.assertEqual(pattern, pattern.strip(), where + " stray whitespace")
            self.assertTrue(pattern, where + " empty pattern")
            self.assertNotIn("\\", pattern, where + " use '/' only")
            if mode == "name":
                self.assertNotIn("/", pattern, where)
            else:
                self.assertRegex(pattern, r"^(~|<root>|\$\{?\w+\}?|%[^%]+%|/|[A-Za-z]:/)", where)
                if pattern == "<root>":
                    self.assertEqual(mode, "node", where)
        self.assertEqual(seen_sections, list(SECTIONS))

    def test_required_rules_present(self):
        have = {(s, m, p) for _, s, m, p in parse() if m != "header"}
        for rule in [
            ("all", "node", "~"),
            ("all", "node", "<root>"),
            ("all", "tree", "~/.ssh"),
            ("all", "tree", "~/.gnupg"),
            ("all", "tree", "~/.aws"),
            ("all", "tree", "~/.claude/.credentials.json"),
            ("all", "tree", "~/.codex/auth.json"),
            ("all", "name", ".git"),
            ("macos", "tree", "/System"),
            ("macos", "tree", "~/Library/Keychains"),
            ("macos", "tree", "~/Library/Mobile Documents"),
            ("macos", "tree", "~/Library/CloudStorage"),
            ("linux", "tree", "/etc"),
            ("linux", "tree", "/mnt"),
            ("windows", "tree", "%SystemRoot%"),
            ("windows", "tree", "%ProgramFiles%"),
            ("windows", "tree", "%APPDATA%/Microsoft/Protect"),
        ]:
            self.assertIn(rule, have)

    def test_agent_history_is_not_denied(self):
        # History/caches are the job; denying them would make the tool useless.
        for _, _, mode, pattern in parse():
            if mode == "header":
                continue
            for job in ("/projects", "/sessions", "/file-history", "/worktrees", "/debug", "/plans"):
                self.assertFalse(pattern.endswith(job), pattern)


if __name__ == "__main__":
    unittest.main()
