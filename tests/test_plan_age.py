"""A plan and an inventory go stale: refused after plan.MAX_AGE_HOURS (backlog "no expiry").

plan --candidates refuses an old inventory and trash --apply an old plan, both with exit 42 and "re-run
inventory"; the trash dry run only warns. A stamp that is missing, unreadable or in the future is refused too.
"""

import json
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import common, views  # noqa: E402
from corecleaner_lib import plan as plan_mod  # noqa: E402
from corecleaner_lib import trash as trash_mod  # noqa: E402
from tests.test_plan_ask import Base  # noqa: E402

CorecleanerError = common.CorecleanerError


def stamp(hours_ago: float) -> str:
    when = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class StaleReason(unittest.TestCase):
    def test_the_limit_is_twelve_hours(self):
        self.assertEqual(plan_mod.MAX_AGE_HOURS, 12)

    def test_fresh_and_just_under_the_limit_pass(self):
        self.assertIsNone(plan_mod.stale_reason("plan", common.now_iso()))
        self.assertIsNone(plan_mod.stale_reason("inventory", stamp(11.9)))

    def test_over_the_limit_says_how_old_and_to_re_run_inventory(self):
        for kind in ("plan", "inventory"):
            why = plan_mod.stale_reason(kind, stamp(13.5))
            self.assertIn("13.5 h old (limit 12 h)", why)
            self.assertIn("re-run inventory", why)
            self.assertIn(kind, why)

    def test_missing_unreadable_or_future_stamp_is_not_fresh(self):
        for bad in (None, "", "t", 12345, "2026-10-21", "2026-13-40T00:00:00Z", {"a": 1}):
            self.assertIn("re-run inventory", plan_mod.stale_reason("inventory", bad), repr(bad))
        ahead = plan_mod.stale_reason("plan", stamp(-2))
        self.assertIn("future", ahead)
        self.assertIn("re-run inventory", ahead)

    def test_a_little_clock_skew_is_tolerated(self):
        self.assertIsNone(plan_mod.stale_reason("plan", stamp(-0.02)))  # 72 s ahead

    def test_now_can_be_given(self):
        made = "2026-10-22T00:00:00Z"
        then = datetime(2026, 10, 22, 11, 0, tzinfo=timezone.utc).timestamp()
        self.assertIsNone(plan_mod.stale_reason("plan", made, now=then))
        self.assertIn("13.0 h old", plan_mod.stale_reason("plan", made, now=then + 2 * 3600))


class StaleInventory(Base):
    def saved(self, ts):
        name = "nm%d" % len(os.listdir(self.work))  # a fresh folder per call
        return views.agent_view("inventory", {"ts": ts, "candidates": [self.cand(self.mkdir(name))]})["inventory_file"]

    def test_plan_candidates_refuses_an_old_inventory_with_exit_42(self):
        cfile = self.saved(stamp(13))
        with self.assertRaises(CorecleanerError) as cm:
            plan_mod.run(types.SimpleNamespace(candidates=cfile))
        self.assertEqual(cm.exception.code, common.EXIT_STATE_CHANGED)
        self.assertIn("re-run inventory", cm.exception.message)
        self.assertEqual(os.listdir(str(common.state_subdir("plans"))), [])  # no plan was written

    def test_plan_candidates_takes_a_recent_inventory(self):
        out = plan_mod.run(types.SimpleNamespace(candidates=self.saved(stamp(11))))
        self.assertEqual(len(out["plan"]["items"]), 1)

    def test_an_inventory_without_a_date_is_refused(self):
        for ts in ("t", None):
            cfile = self.saved(ts)
            with self.assertRaises(CorecleanerError) as cm:
                plan_mod.run(types.SimpleNamespace(candidates=cfile))
            self.assertEqual(cm.exception.code, common.EXIT_STATE_CHANGED)

    def test_signature_is_checked_before_the_date(self):
        cfile = self.saved(common.now_iso())
        data = json.loads(Path(cfile).read_text())
        data["ts"] = stamp(40)  # edited after signing: tampering (41), not just old
        Path(cfile).write_text(json.dumps(data))
        with self.assertRaises(CorecleanerError) as cm:
            plan_mod.run(types.SimpleNamespace(candidates=cfile))
        self.assertEqual(cm.exception.code, common.EXIT_PLAN_TAMPERED)

    def test_run_without_a_file_builds_a_fresh_inventory_whatever_the_clock(self):
        d = self.mkdir("fresh")
        from unittest import mock
        from corecleaner_lib import inventory as inventory_mod

        with mock.patch.object(inventory_mod, "inventory", return_value=[self.cand(d)]):
            out = plan_mod.run(types.SimpleNamespace(candidates=None))
        self.assertEqual(len(out["plan"]["items"]), 1)


class StalePlan(Base):
    def targs(self, f, ids, apply=False):
        return types.SimpleNamespace(cmd="trash", plan=f, ids=list(ids), apply=apply)

    def aged_plan(self, hours):
        d = self.mkdir("victim")
        plan, f = self.make_plan([self.cand(d)])
        self.edit_plan(f, lambda data: data.update(created=stamp(hours)), rehash=True)
        return d, plan["items"][0]["id"], f

    def test_apply_refuses_an_old_plan_with_exit_42_and_moves_nothing(self):
        d, ident, f = self.aged_plan(12.5)
        with self.assertRaises(CorecleanerError) as cm:
            trash_mod.run(self.targs(f, [ident], apply=True))
        self.assertEqual(cm.exception.code, common.EXIT_STATE_CHANGED)
        self.assertIn("re-run inventory", cm.exception.message)
        self.assertIn("plan is 12.5 h old", cm.exception.message)
        self.assertEqual(self.moved, [])
        self.assertEqual(self.manifest, [])
        self.assertTrue(os.path.isdir(d))

    def test_apply_refuses_before_looking_at_the_ids(self):
        _, _, f = self.aged_plan(30)
        with self.assertRaises(CorecleanerError) as cm:
            trash_mod.run(self.targs(f, ["cnotthere"], apply=True))
        self.assertEqual(cm.exception.code, common.EXIT_STATE_CHANGED)

    def test_dry_run_warns_and_still_reports_each_item(self):
        d, ident, f = self.aged_plan(13)
        out = trash_mod.run(self.targs(f, [ident], apply=False))
        self.assertEqual([r["status"] for r in out["items"]], ["ok"])
        self.assertEqual(len(out["warnings"]), 1)
        self.assertIn("re-run inventory", out["warnings"][0])
        self.assertIn("--apply would be refused", out["warnings"][0])
        self.assertEqual(self.moved, [])
        self.assertTrue(os.path.isdir(d))

    def test_a_recent_plan_applies_and_the_dry_run_has_no_warning(self):
        d, ident, f = self.aged_plan(1)
        dry = trash_mod.run(self.targs(f, [ident], apply=False))
        self.assertNotIn("warnings", dry)
        done = trash_mod.run(self.targs(f, [ident], apply=True))
        self.assertEqual([r["status"] for r in done["items"]], ["ok"])
        self.assertEqual(self.moved, [d])

    def test_a_plan_with_a_stamp_in_the_future_is_refused_on_apply(self):
        d, ident, f = self.aged_plan(-5)
        with self.assertRaises(CorecleanerError) as cm:
            trash_mod.run(self.targs(f, [ident], apply=True))
        self.assertEqual(cm.exception.code, common.EXIT_STATE_CHANGED)
        self.assertEqual(self.moved, [])

    def test_the_plan_just_written_by_the_tool_is_fresh(self):
        d = self.mkdir("now")
        plan, f = self.make_plan([self.cand(d)])
        self.assertIsNone(plan_mod.stale_reason("plan", plan["created"]))


if __name__ == "__main__":
    unittest.main()
