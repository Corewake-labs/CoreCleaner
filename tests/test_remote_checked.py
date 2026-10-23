"""\"Published\" is read from local remote-tracking refs only: the evidence says so and `ask` says so.

inventory never contacts a server, so a branch deleted there still counts as published here. Every git fact carries
remote_checked=False, plan keeps it, and the question for a clean clone, worktree or scratch unit that goes to the
Trash with no archive says it counts as "published by local refs, not checked against the server".
"""

import os
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import ask as ask_mod  # noqa: E402
from corecleaner_lib import inventory  # noqa: E402
from corecleaner_lib import plan as plan_mod  # noqa: E402
from tests.test_inventory import HAVE_GIT, InvCase, git  # noqa: E402
from tests.test_plan_ask import REPO_CLEAN, Base  # noqa: E402

PHRASE = "published by local refs, not checked against the server"
NETWORK_VERBS = {"fetch", "pull", "push", "clone", "ls-remote", "remote-update", "submodule"}


@unittest.skipUnless(HAVE_GIT, "git is needed")
class InventoryNeverAsksTheServer(InvCase):
    def published(self, rel):
        r = self.repo(self.home / rel)
        remote = self.root / "remote.git"
        git(self.root, "init", "-q", "--bare", str(remote))
        git(r, "remote", "add", "origin", str(remote))
        git(r, "push", "-q", "origin", "main")
        self.age_tree(r, 60)
        return r

    def test_every_git_fact_says_the_remote_was_not_checked(self):
        self.assertIs(inventory._no_git()["remote_checked"], False)
        r = self.published(".cache/clone")
        ctx = self.ctx()
        g = inventory.git_info(ctx, str(r))
        self.assertEqual((g["is_repo"], g["unpushed"], g["remote_checked"]), (True, 0, False))
        agg = inventory._aggregate_git([g, g])
        self.assertIs(agg["remote_checked"], False)

    def test_git_info_runs_no_network_verb(self):
        r = self.published(".cache/clone2")
        ctx = self.ctx()
        inventory.git_info(ctx, str(r))
        verbs = {arg for call in ctx.run.calls if call[0] == "git" for arg in call[1:] if arg in NETWORK_VERBS}
        self.assertEqual(verbs, set())

    def test_clones_and_worktrees_carry_it_in_their_evidence(self):
        main = self.repo(self.home / "work" / "main")
        self.transcript("-work-main", 1, main)
        wt = main / ".claude" / "worktrees" / "a"
        git(main, "worktree", "add", "-q", str(wt), "-b", "a")
        self.age_tree(wt, 60)
        clone = self.published(".cache/clone3")
        cands, _ = self.collect()
        self.assertIs(self.one(cands, "worktree", wt)["evidence"]["git"]["remote_checked"], False)
        self.assertIs(self.one(cands, "scratch.clone", clone)["evidence"]["git"]["remote_checked"], False)

    def test_a_git_failure_still_carries_the_field(self):
        r = self.repo(self.home / ".cache" / "broken")
        g = inventory.git_info(self.ctx(scripted={"git": (128, "")}), str(r))
        self.assertIs(g["remote_checked"], False)
        self.assertTrue(g["dirty"])


class PlanKeepsIt(Base):
    def item(self, name, **git_extra):
        d = self.mkdir(name)
        return plan_mod.build_plan([self.cand(d, cat="C", git=dict(REPO_CLEAN, **git_extra))])["items"][0]

    def test_compact_evidence_has_it_and_defaults_to_false(self):
        self.assertIs(self.item("a")["evidence"]["git"]["remote_checked"], False)
        self.assertIs(self.item("b", remote_checked=False)["evidence"]["git"]["remote_checked"], False)
        self.assertIs(self.item("c", remote_checked=True)["evidence"]["git"]["remote_checked"], True)
        self.assertIs(self.item("d", remote_checked="yes please")["evidence"]["git"]["remote_checked"], True)

    def test_a_non_repo_item_is_unchanged(self):
        d = self.mkdir("plain")
        it = plan_mod.build_plan([self.cand(d, cat="E")])["items"][0]
        self.assertIs(it["evidence"]["git"]["remote_checked"], False)


class AskSaysPublishedByLocalRefs(Base):
    def plan_of(self, cat="C", n=1, **git_extra):
        cands = []
        start = len(os.listdir(self.work))
        for i in range(n):
            d = self.mkdir("item%d" % (start + i))
            cands.append(self.cand(d, cat=cat, git=dict(REPO_CLEAN, **git_extra)))
        return plan_mod.build_plan(cands)

    def text(self, plan, lang="en"):
        return ask_mod.render(plan, "text", lang=lang)["text"]

    def test_a_clean_published_clone_says_it_rests_on_local_refs(self):
        out = self.text(self.plan_of("C"))
        self.assertIn(PHRASE, out)
        self.assertEqual(out.count(PHRASE), 1)

    def test_worktree_and_scratch_unit_say_it_too(self):
        self.assertIn(PHRASE, self.text(self.plan_of("B")))
        self.assertIn(PHRASE, self.text(self.plan_of("D")))

    def test_claude_format_carries_it_in_the_option_description(self):
        rendered = ask_mod.render(self.plan_of("C"), "claude")
        yes = rendered["questions"][0]["options"][0]["description"]
        self.assertIn(PHRASE, yes)

    def test_portuguese(self):
        out = self.text(self.plan_of("C"), "pt")
        self.assertIn("Conta como publicado pelas refs locais, sem checar no servidor", out)
        self.assertNotIn(PHRASE, out)

    def test_a_group_question_says_it_once(self):
        plan = self.plan_of("C", n=6)
        out = self.text(plan)
        self.assertIn("Trash all 6", out)
        self.assertEqual(out.count(PHRASE), 1)

    def test_no_note_where_published_is_not_what_makes_it_safe(self):
        self.assertNotIn(PHRASE, self.text(self.plan_of("C", dirty=True)))  # archived first anyway
        self.assertNotIn(PHRASE, self.text(self.plan_of("C", origin=None)))  # no remote: archived first
        self.assertNotIn(PHRASE, self.text(self.plan_of("E")))  # node_modules: git state says nothing about it
        self.assertNotIn(PHRASE, self.text(self.plan_of("C", remote_checked=True)))  # a future check of the server

    def test_a_non_repo_candidate_has_no_note(self):
        d = self.mkdir("generated")
        plan = plan_mod.build_plan([self.cand(d, cat="D")])
        self.assertNotIn(PHRASE, self.text(plan))


if __name__ == "__main__":
    unittest.main()
