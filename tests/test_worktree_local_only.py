"""A worktree whose branch is local on purpose gets keep_note, so plan shows it and never offers it (backlog).

Git alone cannot tell \"not published yet\" from \"never to be published\". repos.never_push already reads the
owner's word for that (README/NOTES/CLAUDE/docs lines such as \"never push\", \"local-only\", `branch.<b>.description`);
inventory now asks it for every worktree candidate, in the worktree and in its main repo.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dependency_search as tds  # noqa: E402
import test_inventory as ti  # noqa: E402

from corecleaner_lib import inventory  # noqa: E402

LOCAL_ONLY = "This branch is local-only: never push it, it holds client data.\n"
REASON = "kept: a note in the repo says this branch is local-only (never push)"


@unittest.skipUnless(ti.HAVE_GIT, "git is needed")
class LocalOnlyWorktree(tds.SearchCase):
    def setup_worktree(self, in_worktree=None, in_main=None, branch="a", detach=False, others=()):
        main = self.repo(self.home / "work" / "main")
        self.transcript("-work-main", 1, main)
        for other in others:
            ti.git(main, "branch", other)
        wt = main / ".claude" / "worktrees" / "a"
        if detach:
            ti.git(main, "worktree", "add", "-q", "--detach", str(wt))
        else:
            ti.git(main, "worktree", "add", "-q", str(wt), "-b", branch)
        if in_worktree:
            self.touch(wt / "NOTES.md", 0, in_worktree.encode())
        if in_main:
            self.touch(main / "README.md", 0, in_main.encode())
        self.age_tree(wt, 60)
        return main, wt

    def worktree(self, wt):
        cands, _ = self.collect()
        return self.one(cands, "worktree", wt), cands

    def kept(self, cand):
        return bool(cand["evidence"]["keep_note"]), bool(cand["evidence"].get("local_only_note"))

    def test_a_note_in_the_worktree_keeps_it_and_the_plan_shows_it_only(self):
        _, wt = self.setup_worktree(in_worktree=LOCAL_ONLY)
        cand, cands = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))
        self.assertIn("local-only", cand["evidence"]["reason"])
        item = self.plan_items(cands)[0][str(wt)]
        self.assertEqual((item["group"], item["action"], item["deny"]), (3, "list_only", REASON))
        self.assertEqual((item["evidence"]["keep_note"], item["evidence"]["local_only_note"]), (True, True))

    def test_the_same_worktree_without_the_note_is_offered(self):
        _, wt = self.setup_worktree()
        cand, cands = self.worktree(wt)
        self.assertEqual(self.kept(cand), (False, False))
        item = self.plan_items(cands)[0][str(wt)]
        self.assertEqual((item["group"], item["action"], item["deny"]), (2, "archive_then_trash", None))  # no remote
        self.assertFalse(item["evidence"]["local_only_note"])

    def test_a_note_in_the_main_repo_covers_its_worktrees(self):
        _, wt = self.setup_worktree(in_main="This repo is local-only.\n")
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))

    def test_a_note_that_names_this_branch_keeps_it(self):
        _, wt = self.setup_worktree(in_worktree="Branch `a`: do not push, ever.\n", others=("other",))
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))

    def test_a_note_that_names_another_branch_does_not(self):
        _, wt = self.setup_worktree(in_worktree="Branch `other` must never be pushed.\n", others=("other",))
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (False, False))

    def test_a_note_in_main_that_names_another_branch_does_not(self):
        _, wt = self.setup_worktree(in_main="Branch `other` must never be pushed.\n", others=("other",))
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (False, False))

    def test_a_branch_description_counts(self):
        main, wt = self.setup_worktree()
        ti.git(main, "config", "branch.a.description", "never push, client data")
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))

    def test_portuguese_notes_count(self):
        _, wt = self.setup_worktree(in_worktree="Esta branch é só local, nunca sobe.\n")
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))

    def test_a_detached_worktree_is_covered_only_by_a_note_that_names_no_branch(self):
        _, wt = self.setup_worktree(in_worktree="Branch `other` must never be pushed.\n", detach=True, others=("other",))
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (False, False))

    def test_a_detached_worktree_under_a_repo_wide_note_is_kept(self):
        _, wt = self.setup_worktree(in_worktree=LOCAL_ONLY, detach=True)
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, True))

    def test_the_note_survives_the_dependency_search(self):
        # _apply_refs used to overwrite keep_note with "a referencing line says keep"
        _, wt = self.setup_worktree(in_worktree=LOCAL_ONLY)
        cand, _ = self.worktree(wt)
        self.assertEqual(cand["evidence"]["referenced_by_total"], 0)
        self.assertTrue(cand["evidence"]["keep_note"])

    def test_a_keep_line_in_another_file_still_sets_keep_note(self):
        _, wt = self.setup_worktree()
        self.touch(self.home / "Documents" / "proj" / "CLAUDE.md", 30, ("keep %s, do not delete\n" % wt).encode())
        if not ti.HAVE_RG:
            self.skipTest("needs rg")
        cand, _ = self.worktree(wt)
        self.assertEqual(self.kept(cand), (True, False))

    def test_a_live_worktree_is_not_examined(self):
        main, wt = self.setup_worktree(in_worktree=LOCAL_ONLY)
        self.touch(wt / "just-now.txt", 0)  # touched within the hour: list_only already
        ctx = self.ctx()
        cands, _ = inventory.collect(ctx)
        cand = self.one(cands, "worktree", wt)
        self.assertEqual(cand["action"], "list_only")
        self.assertFalse(cand["evidence"].get("local_only_note"))
        self.assertFalse([c for c in ctx.run.calls if c[0] == "git" and "grep" in c])

    def test_no_network_verb_runs_for_the_note(self):
        _, wt = self.setup_worktree(in_worktree=LOCAL_ONLY)
        ctx = self.ctx()
        self.settle()
        inventory.collect(ctx)
        verbs = {a for c in ctx.run.calls if c[0] == "git" for a in c[1:] if a in {"fetch", "pull", "push", "ls-remote"}}
        self.assertEqual(verbs, set())

    def test_the_main_repo_is_read_once_for_all_its_worktrees(self):
        main, wt = self.setup_worktree(in_main="Branch `other` must never be pushed.\n", others=("other",))
        second = main / ".claude" / "worktrees" / "b"
        ti.git(main, "worktree", "add", "-q", str(second), "-b", "b")
        self.age_tree(second, 60)
        ctx = self.ctx()
        self.settle()
        cands, _ = inventory.collect(ctx)
        self.assertEqual(len(self.by_kind(cands, "worktree")), 2)
        main_reads = [c for c in ctx.run.calls if c[0] == "git" and "-C" in c and c[c.index("-C") + 1] == str(main)
                      and "grep" in c]
        self.assertEqual(len(main_reads), 1, main_reads)

    def test_git_that_cannot_be_read_is_left_to_the_other_evidence(self):
        _, wt = self.setup_worktree(in_worktree=LOCAL_ONLY)
        cands, _ = self.collect(scripted={"git": (128, "")})
        cand = self.one(cands, "worktree", wt)
        self.assertIn("error", cand["evidence"]["git"])
        self.assertFalse(cand["evidence"].get("local_only_note"))
        self.assertTrue(cand["evidence"]["git"]["dirty"])


if __name__ == "__main__":
    unittest.main()
