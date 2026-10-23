"""inventory.py cost: a candidate younger than its minimum age must not be walked, a live node_modules project
must not be fully scanned, and the code_sign_clone ceiling is explicit. Every fixture lives in mkdtemp().

Origin: a real run took 6m57 (279 s of system time) because every FRESH scratch unit was measured entry by
entry before its age was checked, although it was then dropped.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_inventory import DAY, InvCase  # noqa: E402

from corecleaner_lib import inventory  # noqa: E402


class CountingScan:
    """Wraps inventory._scan_dir and counts the directories it reads."""

    def __init__(self):
        self.real = inventory._scan_dir
        self.dirs = []

    def __call__(self, d, *args, **kw):
        self.dirs.append(d)
        return self.real(d, *args, **kw)


class MeasureEarlyExit(InvCase):
    def wide_tree(self, base, old_days=30, subdirs=50, files=10):
        for i in range(subdirs):
            for j in range(files):
                self.touch(base / ("d%03d" % i) / ("f%02d.bin" % j), old_days, b"z" * 100)
        self.age_tree(base, old_days)
        return base

    def test_a_fresh_entry_ends_the_walk_before_any_subdirectory_is_read(self):
        base = self.wide_tree(self.root / "unit")
        self.touch(base / "just-now.txt", 0)  # direct child of the root, newer than the 7 day limit
        spy = CountingScan()
        with mock.patch.object(inventory, "_scan_dir", spy):
            got = inventory.measure(str(base), fresh_after=self.now - 7 * DAY)
        self.assertTrue(got.fresh)
        self.assertLessEqual(len(spy.dirs), 1, "only the root is read; the 50 subdirectories are never queued")
        self.assertLess(got.entries, 60)

    def test_a_fresh_entry_deep_inside_is_found_and_stops_the_other_walkers(self):
        base = self.wide_tree(self.root / "unit")
        self.touch(base / "d007" / "deep" / "er" / "just-now.txt", 0)
        self.age(base / "d007" / "deep" / "er", 0)
        got = inventory.measure(str(base), fresh_after=self.now - 7 * DAY)
        self.assertTrue(got.fresh)
        full = inventory.measure(str(base))
        self.assertFalse(full.fresh)
        self.assertLess(got.entries, full.entries, "the walk stopped early")

    def test_an_old_tree_is_measured_in_full_exactly_as_before(self):
        base = self.wide_tree(self.root / "unit", old_days=30)
        limited = inventory.measure(str(base), fresh_after=self.now - 7 * DAY)
        plain = inventory.measure(str(base))
        self.assertFalse(limited.fresh)
        self.assertEqual((limited.bytes, limited.entries, limited.mtime), (plain.bytes, plain.entries, plain.mtime))
        self.assertGreater(plain.entries, 500)

    def test_a_scratch_unit_younger_than_its_limit_is_dropped_without_a_walk(self):
        unit = self.tmpbase / "claude-501" / "-work-app" / "11111111-2222-3333-4444-555555555555"
        for i in range(40):
            self.touch(unit / "scratchpad" / ("d%02d" % i) / "f.txt", 0)
        spy = CountingScan()
        with mock.patch.object(inventory, "_scan_dir", spy):
            cands, _ = self.collect()
        self.assertEqual([c for c in cands if c["category"] == "D"], [])
        self.assertEqual([d for d in spy.dirs if str(unit) in d], [], "a fresh unit costs a single lstat, not a walk")

    def test_a_unit_old_enough_keeps_its_exact_size_and_age(self):
        unit = self.tmpbase / "claude-501" / "-work-app" / "11111111-2222-3333-4444-555555555555"
        for i in range(20):
            self.touch(unit / "scratchpad" / ("d%02d" % i) / "f.txt", 10, b"q" * 5000)
        self.age_tree(unit, 10)
        cands, _ = self.collect()
        c = self.one(cands, "claude.scratch", unit)
        self.assertEqual(c["evidence"]["age_days"], 10)
        self.assertEqual(c["bytes"], inventory.measure(str(unit)).bytes)
        self.assertEqual(c["evidence"]["size"]["entries"], inventory.measure(str(unit)).entries)

    def test_an_entry_just_inside_the_limit_is_not_dropped_by_the_early_exit(self):
        unit = self.tmpbase / "claude-501" / "-work-app" / "11111111-2222-3333-4444-555555555555"
        self.touch(unit / "scratchpad" / "f.txt", 7.2)  # 7.2 days: older than the 7 day limit
        self.age_tree(unit, 7.2)
        cands, _ = self.collect()
        self.assertEqual(len(self.by_kind(cands, "claude.scratch")), 1)


class NodeModulesIdleProbe(InvCase):
    def project(self, name, days):
        p = self.home / "work" / name
        self.touch(p / "package.json", days)
        self.touch(p / "bun.lock", days)
        self.touch(p / "node_modules" / "dep" / "index.js", days, b"x" * 5000)
        self.age_tree(p, days)
        return p

    def test_newest_mtime_stops_at_the_first_entry_newer_than_the_bar(self):
        base = self.root / "proj"
        for i in range(30):
            self.touch(base / ("d%02d" % i) / "f.txt", 50)
        self.touch(base / "now.txt", 0)
        seen = []
        real = inventory._entries
        with mock.patch.object(inventory, "_entries", lambda path: seen.append(str(path)) or real(path)):
            newest, truncated = inventory.newest_mtime(str(base), {"node_modules"}, stop_after=self.now - 30 * DAY)
        self.assertGreater(newest, self.now - DAY)
        self.assertFalse(truncated)
        self.assertEqual(seen, [str(base)], "the 30 subdirectories are not read once the answer is known")

    def test_a_project_edited_recently_never_reaches_git(self):
        p = self.project("busy", 90)
        self.touch(p / "src" / "app.ts", 1)
        ctx = self.ctx()
        cands, _ = self.collect(ctx=ctx)
        self.assertEqual(self.by_kind(cands, "node_modules"), [])
        self.assertEqual([c for c in ctx.run.calls if str(p) in c], [], "alive on a file edit: no git call needed")

    def test_an_idle_project_still_gets_the_full_proof(self):
        p = self.project("idle", 90)
        ctx = self.ctx()
        cands, _ = self.collect(ctx=ctx)
        c = self.one(cands, "node_modules", p / "node_modules")
        self.assertGreaterEqual(c["evidence"]["project_idle_days"], 89)
        self.assertTrue([call for call in ctx.run.calls if str(p) in call], "the last commit is still asked for")

    def test_idle_days_is_the_same_number_with_or_without_the_early_exit(self):
        p = self.project("same", 60)
        days, unproven = inventory._idle_days(self.ctx(), str(p))
        self.assertFalse(unproven)
        self.assertGreaterEqual(days, 59.9)
        self.assertLess(days, 61)

    def test_several_projects_are_probed_and_listed_in_a_stable_order(self):
        for name in ("p1", "p2", "p3", "p4"):
            self.project(name, 90)
        cands, _ = self.collect()
        got = [c["path"] for c in self.by_kind(cands, "node_modules")]
        self.assertEqual(len(got), 4)
        self.assertEqual(got, sorted(got, key=lambda x: (-os.lstat(x).st_blocks * 512, x)))


class CodeSignCloneCeiling(InvCase):
    def make(self, clones):
        x = self.root / "var" / "k2" / "X" / "com.google.Chrome.code_sign_clone"
        for name in clones:
            self.touch(x / name / "Google Chrome.app.bundle" / "Chrome", 1, b"c" * 8192)
        self.touch(x / "stray-file", 1)  # a file is not a clone
        return x

    def scripted(self):
        return {"getconf": (0, "%s/\n" % (self.root / "var" / "k2" / "T")), "tmutil": (0, "")}

    def test_count_and_bytes_are_an_explicit_ceiling_and_a_reboot_is_the_action(self):
        x = self.make(["code_sign_clone.AAA", "code_sign_clone.BBB", "code_sign_clone.CCC"])
        cands, _ = self.collect(scripted=self.scripted())
        c = self.one(cands, "os.code_sign_clone", x)
        ev = c["evidence"]
        self.assertEqual(ev["apparent_upper_bound"], {"bytes": c["bytes"], "clones": 3})
        self.assertGreater(ev["apparent_upper_bound"]["bytes"], 3 * 8192)
        self.assertEqual(ev["action"], "reboot frees these")
        self.assertEqual((c["action"], ev["recommend"], ev["gain_unknown"]), ("list_only", "reboot", True))
        self.assertIn("3 clone(s)", ev["reason"])
        self.assertIn("ceiling", ev["reason"])

    def test_one_clone_is_counted_as_one(self):
        x = self.make(["code_sign_clone.ONLY"])
        cands, _ = self.collect(scripted=self.scripted())
        self.assertEqual(self.one(cands, "os.code_sign_clone", x)["evidence"]["apparent_upper_bound"]["clones"], 1)


if __name__ == "__main__":
    unittest.main()
