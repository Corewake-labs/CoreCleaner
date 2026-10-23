"""Arrival time: a tree restored with old mtimes (cp -a, rsync -a, unzip, Time Machine) is not idle.

plan._stat_times(st) -> (birthtime | None, ctime) of the candidate ROOT is the one place the clock enters,
so these tests patch it: fixtures are created now and aged with os.utime, and no real clock can tell that
from a restore. Everything lives under tempfile.mkdtemp().
"""

import os
import shutil
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from corecleaner_lib import plan as plan_mod

from tests import REAL_STAT_TIMES

DAY = 86400.0


class ArrivalFixture(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-arrival-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.now = time.time()

    def tree(self, name, idle_days=60):
        """A folder whose files and root all say 'untouched for idle_days days'."""
        path = os.path.join(self.root, name)
        os.makedirs(path)
        Path(path, "f.bin").write_bytes(b"x" * 100)
        old = self.now - idle_days * DAY
        os.utime(os.path.join(path, "f.bin"), (old, old))
        os.utime(path, (old, old))
        return path

    def item(self, path, cat="D", born=None, changed=None):
        """_build_item with the root's (birthtime, ctime) given in seconds ago; None = no signal."""
        times = (
            None if born is None else self.now - born,
            0.0 if changed is None else self.now - changed,
        )
        cand = {"category": cat, "path": path, "bytes": 100, "mtime": os.lstat(path).st_mtime, "owner": "claude", "evidence": {}}
        with mock.patch.object(plan_mod, "_stat_times", return_value=times):
            return plan_mod._build_item(cand, self.now)


class StatTimes(ArrivalFixture):
    def test_real_function_reports_a_fresh_inode_as_just_arrived(self):
        path = self.tree("restored")  # utime'd back 60 days, as `cp -a` would leave it
        born, changed = REAL_STAT_TIMES(os.lstat(path))
        self.assertLess(self.now - changed, 3600)  # ctime cannot be set from user space
        # macOS/APFS drags the birthtime back to an older mtime set by utime: only ctime shows the arrival there
        self.assertTrue(born is None or isinstance(born, float))

    def test_birthtime_missing_or_junk_is_none_and_ctime_is_a_float(self):
        for junk in (None, 0, -5, float("nan"), float("inf"), True, "x"):
            st = types.SimpleNamespace(st_birthtime=junk, st_ctime=1234)
            self.assertEqual(REAL_STAT_TIMES(st), (None, 1234.0), junk)
        no_attr = types.SimpleNamespace(st_ctime=1234)  # Linux: the attribute does not exist
        self.assertEqual(REAL_STAT_TIMES(no_attr), (None, 1234.0))
        ok = types.SimpleNamespace(st_birthtime=99.5, st_ctime=100)
        self.assertEqual(REAL_STAT_TIMES(ok), (99.5, 100.0))


class LiveWindow(ArrivalFixture):
    def test_old_mtimes_but_born_ten_minutes_ago_is_group_3_like_live(self):
        path = self.tree("restored")
        it = self.item(path, born=600, changed=600)
        self.assertEqual((it["group"], it["action"]), (3, "list_only"))
        self.assertTrue(it["deny"].startswith("arrived less than 1 h ago"), it["deny"])
        self.assertIn("(live state, outside the plan)", it["deny"])

    def test_ctime_alone_counts_for_the_live_window_where_there_is_no_birthtime(self):
        path = self.tree("restored-linux")
        it = self.item(path, born=None, changed=600)
        self.assertEqual((it["group"], it["action"]), (3, "list_only"))
        self.assertTrue(it["deny"].startswith("arrived less than 1 h ago"), it["deny"])

    def test_a_ctime_bump_on_an_old_folder_waits_an_hour_and_no_longer(self):
        path = self.tree("chmodded")
        bumped = self.item(path, born=200 * DAY, changed=600)  # chmod, xattr, rename: conservative
        self.assertEqual(bumped["group"], 3)
        settled = self.item(path, born=200 * DAY, changed=2 * 3600)
        self.assertEqual((settled["group"], settled["action"], settled["deny"]), (1, "trash", None))

    def test_arrived_two_hours_ago_is_not_live(self):
        path = self.tree("two-hours")
        it = self.item(path, born=2 * 3600, changed=2 * 3600)
        self.assertEqual((it["group"], it["action"], it["deny"]), (1, "trash", None))

    def test_no_signal_at_all_changes_nothing(self):
        path = self.tree("plain")
        it = self.item(path, born=None, changed=None)
        self.assertEqual((it["group"], it["action"], it["deny"]), (1, "trash", None))

    def test_an_arrival_stamp_in_the_future_fails_closed(self):
        path = self.tree("skewed")
        it = self.item(path, born=-3 * 3600, changed=-3 * 3600)
        self.assertEqual(it["group"], 3)
        self.assertTrue(it["deny"].startswith("arrived less than 1 h ago"), it["deny"])

    def test_the_item_keeps_the_real_mtime_for_the_apply_side_recheck(self):
        path = self.tree("restored")
        it = self.item(path, born=600, changed=600)
        self.assertAlmostEqual(it["mtime"], os.lstat(path).st_mtime, places=3)


class FortyFiveDayFloor(ArrivalFixture):
    def test_history_worktree_clone_born_ten_days_ago_wait_for_the_floor(self):
        for cat in "ABC":
            path = self.tree("from-backup-" + cat)
            it = self.item(path, cat=cat, born=10 * DAY, changed=10 * DAY)
            self.assertEqual((it["group"], it["action"]), (3, "list_only"), cat)
            self.assertEqual(it["deny"], "arrived less than 45 days ago (history, worktree or clone: kept)", cat)

    def test_born_46_days_ago_passes_the_floor(self):
        path = self.tree("old-clone")
        it = self.item(path, cat="C", born=46 * DAY, changed=46 * DAY)
        self.assertEqual((it["group"], it["action"], it["deny"]), (2, "trash", None))

    def test_a_ctime_bump_does_not_push_the_floor_out(self):
        path = self.tree("spotlight-touched")
        it = self.item(path, cat="C", born=200 * DAY, changed=5 * DAY)  # Spotlight xattr 5 days ago
        self.assertEqual((it["group"], it["deny"]), (2, None))

    def test_without_a_birthtime_the_floor_is_the_mtime_alone(self):
        path = self.tree("linux-clone")
        it = self.item(path, cat="C", born=None, changed=10 * DAY)  # ctime is never used for the floor
        self.assertEqual((it["group"], it["deny"]), (2, None))

    def test_the_mtime_floor_still_wins_with_its_own_wording(self):
        path = self.tree("edited-recently", idle_days=10)
        it = self.item(path, cat="C", born=200 * DAY, changed=10 * DAY)
        self.assertEqual(it["deny"], "idle less than 45 days (history, worktree or clone: kept)")

    def test_other_categories_have_no_floor(self):
        for cat in "DE":
            path = self.tree("scratch-" + cat)
            it = self.item(path, cat=cat, born=10 * DAY, changed=10 * DAY)
            self.assertIsNone(it["deny"], cat)


class RootOnly(ArrivalFixture):
    def test_stat_times_is_asked_once_and_about_the_root(self):
        path = self.tree("big")
        os.makedirs(os.path.join(path, "inner", "deeper"))
        Path(path, "inner", "deeper", "new.bin").write_bytes(b"y")  # a young file inside does not matter here
        root_ino = os.lstat(path).st_ino
        cand = {"category": "D", "path": path, "bytes": 100, "mtime": 1.0, "owner": "claude", "evidence": {}}
        with mock.patch.object(plan_mod, "_stat_times", return_value=(None, 0.0)) as spy:
            plan_mod._build_item(cand, self.now)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(spy.call_args[0][0].st_ino, root_ino)

    def test_a_missing_path_never_reaches_the_clock(self):
        cand = {"category": "D", "path": os.path.join(self.root, "gone"), "bytes": 1, "mtime": 1.0, "owner": "claude",
                "evidence": {}}
        with mock.patch.object(plan_mod, "_stat_times") as spy:
            it = plan_mod._build_item(cand, self.now)
        self.assertEqual((it["group"], it["deny"]), (3, "missing"))
        spy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
