"""Tool-cache commands: the strings the plan emits are the documented ones, and Homebrew is a decision.

`brew cleanup --prune=all` also removes old versions of installed formulae (so cache.homebrew is not a
self-refilling cache), and `npx` resolves ./node_modules/.bin first and downloads what it cannot find (so its
commands carry --no-install). Everything lives under tempfile.mkdtemp().
"""

import os
import shlex
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from corecleaner_lib import ask as ask_mod
from corecleaner_lib import inventory as inventory_mod
from corecleaner_lib import plan as plan_mod

SKILL_DIR = Path(__file__).resolve().parents[1] / "skills" / "corecleaner"
CATEGORIAS = SKILL_DIR / "references" / "categorias.md"
SKILL_MD = SKILL_DIR / "SKILL.md"

BREW = "brew cleanup --prune=all"
PLAYWRIGHT = "npx --no-install playwright uninstall --all"


def puppeteer(path):
    return "npx --no-install @puppeteer/browsers clear --path " + shlex.quote(path)


class DocumentedCommandStrings(unittest.TestCase):
    def test_every_clean_command_is_in_the_categorias_table_row_of_its_kind(self):
        rows = [r for r in CATEGORIAS.read_text(encoding="utf-8").splitlines() if r.startswith("| cache.")]
        checked = 0
        for spec in inventory_mod._CACHE_SPECS:
            template = spec.get("clean")
            if not template:
                continue
            row = next((r for r in rows if spec["kind"] in r.split("|")[1]), None)
            self.assertIsNotNone(row, spec["kind"] + " has no row in categorias.md")
            documented = template.replace("{bin}", spec["bins"][0]).replace("{path}", "<dir>")
            self.assertIn(documented, row, spec["kind"])
            checked += 1
        self.assertGreaterEqual(checked, 12)

    def test_the_plan_accepts_exactly_the_documented_brew_and_npx_commands(self):
        path = "/tmp/with space/cache"
        accepted = inventory_mod.clean_commands_for(path)
        for cmd in (BREW, PLAYWRIGHT, puppeteer(path)):
            self.assertIn(cmd, accepted)
        for unflagged in ("npx playwright uninstall --all", "npx @puppeteer/browsers clear --path " + shlex.quote(path)):
            self.assertNotIn(unflagged, accepted)
        npx = [c for c in accepted if c.startswith("npx ")]
        self.assertEqual(len(npx), 2, npx)
        self.assertTrue(all(c.startswith("npx --no-install ") for c in npx), npx)

    def test_skill_step_11_names_the_flag_and_the_brew_warning(self):
        text = SKILL_MD.read_text(encoding="utf-8")
        step = next(line for line in text.splitlines() if line.startswith("11. `tool_command` items"))
        for needle in ("cd ~", "--no-install", "./node_modules/.bin", "old versions of installed formulae"):
            self.assertIn(needle, step)


class HomebrewIsADecision(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-toolcmd-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.old = time.time() - 60 * 86400

    def cache(self, name):
        path = os.path.join(self.root, name)
        os.makedirs(path)
        Path(path, "f.bin").write_bytes(b"x" * 100)
        os.utime(os.path.join(path, "f.bin"), (self.old, self.old))
        os.utime(path, (self.old, self.old))
        return path

    def item(self, kind, command, **ev):
        path = self.cache(kind.replace(".", "_"))
        cmd = command(path) if callable(command) else command
        cand = {"category": "F", "kind": kind, "path": path, "bytes": 100, "mtime": self.old, "owner": "tool",
                "evidence": dict(tool_command=cmd, **ev)}
        return plan_mod._build_item(cand, time.time())

    def test_homebrew_is_not_a_self_refilling_cache(self):
        self.assertNotIn("cache.homebrew", plan_mod.SELF_REFILLING)
        for kind in ("cache.npm", "cache.pip", "cache.uv", "cache.bun", "cache.pnpm_store", "cache.go_mod"):
            self.assertIn(kind, plan_mod.SELF_REFILLING)

    def test_homebrew_command_goes_to_group_2_and_the_sure_junk_caches_stay_in_group_1(self):
        brew = self.item("cache.homebrew", BREW)
        self.assertEqual((brew["group"], brew["action"], brew["tool_command"]), (2, "tool_command", BREW))
        npm = self.item("cache.npm", "npm cache clean --force")
        self.assertEqual((npm["group"], npm["action"]), (1, "tool_command"))

    def test_browser_downloads_keep_group_2_with_the_flagged_commands(self):
        pw = self.item("cache.playwright", PLAYWRIGHT)
        self.assertEqual((pw["group"], pw["action"], pw["tool_command"]), (2, "tool_command", PLAYWRIGHT))
        pp = self.item("cache.puppeteer", puppeteer)
        self.assertEqual((pp["group"], pp["action"]), (2, "tool_command"))
        self.assertTrue(pp["tool_command"].startswith("npx --no-install @puppeteer/browsers clear --path "))

    def test_an_unflagged_npx_command_is_refused_not_planned(self):
        item = self.item("cache.playwright", "npx playwright uninstall --all")
        self.assertEqual((item["group"], item["action"], item["tool_command"]), (3, "list_only", None))

    def test_a_cited_homebrew_cache_is_a_live_dependency_not_a_setting(self):
        item = self.item("cache.homebrew", BREW, referenced_by=["/tmp/x/.zshrc"], referenced_by_total=1)
        self.assertEqual(item["group"], 2)
        self.assertEqual(item["reason"], "live dependency: cited by 1 file(s)")

    def test_the_question_warns_about_brew_and_about_npx(self):
        for lang, brew_words, npx_words in (
            ("en", "old versions of installed formulae", "downloads nothing"),
            ("pt", "versões antigas de fórmulas instaladas", "não baixa nada"),
        ):
            for command, words in ((BREW, brew_words), (PLAYWRIGHT, npx_words)):
                it = {"id": "c000001", "group": 2, "category": "F", "path": "/tmp/x/cache", "display": "cache",
                      "bytes": 5000000, "inode": 1, "mtime": 1.0, "owner": "tool", "evidence": {"age_days": 60},
                      "action": "tool_command", "tool_command": command, "deny": None}
                plan = {"version": 1, "created": "2026-10-22T00:00:00Z", "free_before": 1, "items": [it],
                        "summary": {}, "sha256": "a" * 64}
                out = ask_mod.render(plan, "claude", lang=lang)
                yes = next(o for q in out["batch_questions"][0] for o in q["options"] if command in o["description"])
                self.assertIn(words, yes["description"], (lang, command))

    def test_other_tool_commands_get_no_extra_warning(self):
        it = {"id": "c000001", "group": 1, "category": "F", "path": "/tmp/x/cache", "display": "cache", "bytes": 5000000,
              "inode": 1, "mtime": 1.0, "owner": "tool", "evidence": {"age_days": 60}, "action": "tool_command",
              "tool_command": "npm cache clean --force", "deny": None}
        plan = {"version": 1, "created": "2026-10-22T00:00:00Z", "free_before": 1, "items": [it], "summary": {},
                "sha256": "a" * 64}
        out = ask_mod.render(plan, "claude")
        text = " ".join(o["description"] for q in out["batch_questions"][0] for o in q["options"])
        self.assertNotIn("Homebrew", text)
        self.assertNotIn("--no-install", text)


if __name__ == "__main__":
    unittest.main()
