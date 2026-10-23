"""A clean, published clone can hold ignored data nobody archives (models, `.wrangler/state`).

inventory.git_info records it (evidence.git.ignored_large), plan demotes a would-be group 1 clone to group 2
with reason "ignored data not archived: N file(s), X", and ask says so and never folds it into "Trash all N".
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, inventory  # noqa: E402
from corecleaner_lib import ask as ask_mod  # noqa: E402
from corecleaner_lib import plan as plan_mod  # noqa: E402
from tests.test_inventory import HAVE_GIT, InvCase, git  # noqa: E402
from tests.test_plan_ask import REPO_CLEAN, Base  # noqa: E402

IGNORE = b"models/\n.wrangler/\n*.bin\nnode_modules/\n"
SMALL = 1000  # the threshold the tests lower so no big file is written


@unittest.skipUnless(HAVE_GIT, "git is needed")
class GitInfoIgnoredLarge(InvCase):
    def published_clone(self, name="clone"):
        r = self.repo(self.home / ".cache" / name)
        remote = self.root / (name + "-remote.git")
        git(self.root, "init", "-q", "--bare", str(remote))
        self.touch(r / ".gitignore", 0, IGNORE)
        git(r, "add", ".")
        git(r, "commit", "-q", "-m", "ignore")
        git(r, "remote", "add", "origin", str(remote))
        git(r, "push", "-q", "origin", "main")
        return r

    def info(self, r):
        return inventory.git_info(self.ctx(), str(r))

    def test_a_published_clone_with_big_ignored_files_records_count_and_bytes(self):
        r = self.published_clone()
        self.touch(r / "models" / "a.bin", 0, b"x" * 3000)
        self.touch(r / "models" / "b.bin", 0, b"x" * 2000)
        self.touch(r / ".wrangler" / "state" / "tiny", 0, b"x" * 20)  # a whole folder under the threshold
        self.touch(r / "stray.bin", 0, b"x" * 10)
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            g = self.info(r)
        self.assertEqual((g["dirty"], g["unpushed"], g["stash"]), (False, 0, 0))
        self.assertTrue(g["origin"])
        self.assertEqual(g["ignored_large"], {"count": 2, "bytes": 5000})

    def test_a_folder_of_small_ignored_files_adds_up_as_one_entry(self):
        r = self.published_clone()
        for n in range(5):
            self.touch(r / ".wrangler" / "state" / ("f%d" % n), 0, b"x" * 300)
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            g = self.info(r)
        self.assertEqual(g["ignored_large"], {"count": 5, "bytes": 1500})

    def test_nothing_ignored_or_only_small_files_is_zero(self):
        r = self.published_clone()
        self.touch(r / "models" / "a.bin", 0, b"x" * 3000)
        self.assertEqual(self.info(r)["ignored_large"], {"count": 0, "bytes": 0})  # 3 KB is under the real 10 MiB

    def test_the_threshold_is_the_one_the_archive_lists(self):
        r = self.published_clone()
        for name, size in (("under.bin", archive.IGNORED_MIN_BYTES - 1), ("exact.bin", archive.IGNORED_MIN_BYTES)):
            with open(str(r / name), "wb") as fh:
                fh.truncate(size)  # sparse: no disk used
        self.assertEqual(self.info(r)["ignored_large"], {"count": 1, "bytes": archive.IGNORED_MIN_BYTES})
        listed = archive.ignored_large(str(r))
        self.assertEqual([i["path"] for i in listed], ["exact.bin"])

    def test_untracked_and_tracked_files_are_not_ignored_data(self):
        r = self.published_clone()
        self.touch(r / "notes.txt", 0, b"x" * 5000)  # untracked, not ignored
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            g = self.info(r)
        self.assertEqual(g["ignored_large"], {"count": 0, "bytes": 0})
        self.assertTrue(g["dirty"])

    def test_node_modules_an_install_rebuilds_is_not_data_but_a_bare_one_is(self):
        r = self.published_clone()
        self.touch(r / "web" / "package.json", 0, b"{}")
        self.touch(r / "web" / "package-lock.json", 0, b"{}")
        self.touch(r / "web" / "node_modules" / "dep" / "index.js", 0, b"x" * 4000)
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            self.assertEqual(self.info(r)["ignored_large"], {"count": 0, "bytes": 0})
        self.touch(r / "hand" / "node_modules" / "patched.js", 0, b"x" * 4000)  # no manifest: someone's own files
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            self.assertEqual(self.info(r)["ignored_large"], {"count": 1, "bytes": 4000})

    def test_a_failing_ignored_status_is_unverified_and_counts_nothing(self):
        r = self.published_clone()
        self.touch(r / "models" / "a.bin", 0, b"x" * 3000)
        real = inventory._git
        ctx = self.ctx()

        def fake(c, repo, *args):
            return (128, "") if "--ignored" in args else real(c, repo, *args)

        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL), mock.patch.object(inventory, "_git", fake):
            g = inventory.git_info(ctx, str(r))
        self.assertEqual(g["ignored_large"], {"count": 0, "bytes": 0})
        self.assertIn("git ignored files (status --ignored failed)", ctx.unverified)
        self.assertFalse(g["dirty"])

    def test_the_entry_budget_marks_the_count_approximate(self):
        r = self.published_clone()
        for n in range(6):
            self.touch(r / "models" / ("f%d.bin" % n), 0, b"x" * 400)
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL), mock.patch.object(archive, "SCAN_BUDGET", 3):
            g = self.info(r)
        self.assertTrue(g["ignored_large"].get("approx"))

    def test_a_non_repo_and_the_candidate_carry_the_field(self):
        self.assertEqual(inventory._no_git()["ignored_large"], {"count": 0, "bytes": 0})
        r = self.published_clone()
        self.touch(r / "models" / "a.bin", 0, b"x" * 3000)
        self.age_tree(r, 60)
        with mock.patch.object(archive, "IGNORED_MIN_BYTES", SMALL):
            cands, _ = self.collect()
        c = self.one(cands, "scratch.clone", r)
        self.assertEqual(c["evidence"]["git"]["ignored_large"], {"count": 1, "bytes": 3000})
        self.assertEqual(c["action"], "trash")  # the hint is unchanged: plan decides

    def test_aggregate_sums_the_repos_of_a_scratch_unit(self):
        a, b, c = inventory._no_git(), inventory._no_git(), inventory._no_git()
        for g, n in ((a, 2), (b, 3)):
            g.update(is_repo=True, ignored_large={"count": n, "bytes": n * 100})
        b["ignored_large"]["approx"] = True
        c.update(is_repo=True)
        agg = inventory._aggregate_git([a, b, c])
        self.assertEqual(agg["ignored_large"], {"count": 5, "bytes": 500, "approx": True})


class PlanDemotion(Base):
    BIG = {"count": 2, "bytes": 5000}

    def item(self, name="clone", cat="C", git_extra=None, **ev):
        d = self.mkdir("%s%d" % (name, len(os.listdir(self.work))))
        git_ev = dict(REPO_CLEAN, **(git_extra or {}))
        return plan_mod.build_plan([self.cand(d, cat=cat, git=git_ev, **ev)])["items"][0]

    def test_a_clean_published_clone_with_ignored_data_is_group_2_with_the_reason(self):
        it = self.item(git_extra={"ignored_large": self.BIG})
        self.assertEqual((it["group"], it["action"], it["deny"]), (2, "trash", None))
        self.assertEqual(it["reason"], "ignored data not archived: 2 file(s), 5 KB")
        self.assertEqual(it["evidence"]["git"]["ignored_large"], self.BIG)

    def test_the_same_clone_without_ignored_data_stays_group_1(self):
        for extra in ({}, {"ignored_large": {"count": 0, "bytes": 0}}):
            it = self.item(git_extra=extra)
            self.assertEqual((it["group"], it["reason"]), (1, None))
            self.assertEqual(it["evidence"]["git"]["ignored_large"], {"count": 0, "bytes": 0})

    def test_a_dirty_clone_keeps_archive_then_trash_and_no_reason_is_invented(self):
        it = self.item(git_extra={"ignored_large": self.BIG, "dirty": True})
        self.assertEqual((it["group"], it["action"], it["reason"]), (2, "archive_then_trash", None))
        self.assertEqual(it["evidence"]["git"]["ignored_large"], self.BIG)

    def test_a_citation_reason_is_not_overwritten(self):
        it = self.item(git_extra={"ignored_large": self.BIG}, referenced_by=["/x/script.sh"])
        self.assertEqual(it["group"], 2)
        self.assertTrue(it["reason"].startswith("live dependency"))

    def test_a_denied_clone_stays_group_3(self):
        it = self.item(git_extra={"ignored_large": self.BIG}, keep_note=True)
        self.assertEqual((it["group"], it["action"]), (3, "list_only"))

    def test_a_scratch_unit_of_category_d_is_demoted_too(self):
        it = self.item(name="unit", cat="D", git_extra={"ignored_large": self.BIG})
        self.assertEqual((it["group"], it["reason"]), (2, "ignored data not archived: 2 file(s), 5 KB"))

    def test_hostile_values_cannot_break_the_plan(self):
        for bad in ({"count": "9", "bytes": None}, {"count": True, "bytes": 1}, "many", None, {"count": -4, "bytes": 1}):
            it = self.item(git_extra={"ignored_large": bad})
            self.assertEqual(it["group"], 1, bad)

    def test_a_demoted_plan_survives_the_hash_round_trip(self):
        d = self.mkdir("clone")
        plan, f = self.make_plan([self.cand(d, cat="C", git=dict(REPO_CLEAN, ignored_large=self.BIG))])
        self.assertEqual(plan_mod.load_plan(f)["items"][0]["reason"], "ignored data not archived: 2 file(s), 5 KB")


class AskSaysSo(Base):
    BIG = {"count": 2, "bytes": 5000}

    def clone_plan(self, n=1, big=True):
        cands = []
        start = len(os.listdir(self.work))
        for i in range(n):
            d = self.mkdir("clone%d" % (start + i))
            git_ev = dict(REPO_CLEAN, **({"ignored_large": self.BIG} if big else {}))
            cands.append(self.cand(d, cat="C", git=git_ev))
        return plan_mod.build_plan(cands)

    def text(self, plan, lang="en"):
        return ask_mod.render(plan, "text", lang=lang)["text"]

    def test_the_question_names_what_leaves_without_a_copy(self):
        out = self.text(self.clone_plan(1))
        self.assertIn("IGNORED DATA NOT ARCHIVED: 2 file(s), 5 KB", out)
        self.assertIn("ignored data not archived: 2 file(s), 5 KB", out)  # the plan table row carries the reason too

    def test_portuguese(self):
        out = self.text(self.clone_plan(1), "pt")
        self.assertIn("DADOS IGNORADOS SEM ARQUIVO: 2 arquivo(s), 5 KB", out)

    def test_no_note_without_ignored_data(self):
        self.assertNotIn("IGNORED DATA", self.text(self.clone_plan(1, big=False)))

    def test_clones_with_ignored_data_are_never_folded_into_trash_all(self):
        plan = self.clone_plan(6)
        rendered = ask_mod.render(plan, "text")
        self.assertEqual([u for u in rendered["answer_map"] if len(u["options"]) == 3], [])  # no "all N" question
        self.assertEqual(rendered["text"].count("IGNORED DATA NOT ARCHIVED"), 6)
        plain = ask_mod.render(self.clone_plan(6, big=False), "text")
        self.assertTrue([u for u in plain["answer_map"] if len(u["options"]) == 3])  # six plain clones do fold


if __name__ == "__main__":
    unittest.main()
