"""The "possibly cited" guess is narrow: a specific folder name, and never a log (backlog: `mine`/`theirs` in a Chrome log).

Measured on the author's Mac: six 80 KB scratch folders named `mine` and `theirs` went to group 2 "possibly cited"
because a Chrome .log named the temp folder two levels above them. A name of fewer than 6 characters or a generic
word gets no guess patterns (the full path is still searched), and a *.log never produces a guess; a log that
cites the whole path still counts as a proven citation.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_dependency_search as tds  # noqa: E402
import test_inventory as ti  # noqa: E402

from corecleaner_lib import inventory  # noqa: E402

PARENT = "~/.cache/claude-trabalho/x/tmp.zzz"
BUILT = 'path.join(os.homedir(), ".cache", "claude-trabalho", "x", "tmp.zzz", "%s", "k.js")\n'


class WeakName(unittest.TestCase):
    def test_short_and_generic_names_get_no_guess(self):
        for name in ("mine", "theirs", "Theirs", "repo", "tmp", "lib", "clone", "build", "cache", "scratch", "worktree",
                     "checkout", "origin", "dist", "x", "ab123"):
            self.assertFalse(inventory._weak_name_ok("/h/.cache/a/b/" + name), name)

    def test_a_specific_name_of_six_characters_or_more_keeps_it(self):
        for name in ("library", "reference", "tmp.AbC123", "ct-t4-9f2", "my-app", "kernel", "models2"):
            self.assertTrue(inventory._weak_name_ok("/h/.cache/a/b/" + name), name)

    def test_a_trailing_separator_and_the_length_rule(self):
        self.assertFalse(inventory._weak_name_ok("/h/a/b/mine/"))
        self.assertTrue(inventory._weak_name_ok("/h/a/b/kernel/"))
        self.assertEqual(inventory.REF_WEAK_MIN_NAME, 6)
        self.assertIn("theirs", inventory.REF_WEAK_STOP_NAMES)  # six characters long: only the stop list stops it


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class GuessNeedsASpecificName(tds.SearchCase):
    def maybe_notes(self, ev):
        return [u for u in ev["unverified"] if u.startswith("referenced_by: possibly cited")]

    def refs_in(self, lib, text, name="script.mjs"):
        self.project_script(text, name=name)
        ctx, cand = self.cand_of(lib)
        inventory._apply_refs(ctx, [cand], [])
        return cand["evidence"]

    def test_a_generic_folder_name_is_not_guessed_from_its_parent_or_its_pieces(self):
        for name in ("mine", "theirs", "repo"):
            lib = self.clone(".cache/claude-trabalho/x/tmp.zzz/" + name)
            for label, text in (("parent", "cd %s && ./%s/k.js\n" % (PARENT, name)), ("pieces", BUILT % name)):
                with self.subTest(name=name, form=label):
                    ev = self.refs_in(lib, text)
                    self.assertEqual((ev["referenced_by_total"], self.maybe_notes(ev)), (0, []))
                    self.assertNotIn("referenced_maybe", ev)

    def test_the_same_text_still_flags_a_specific_name(self):
        lib = self.clone(".cache/claude-trabalho/x/tmp.zzz/kernel-lib")
        for label, text in (("parent", "cd %s && ./kernel-lib/k.js\n" % PARENT), ("pieces", BUILT % "kernel-lib")):
            with self.subTest(form=label):
                ev = self.refs_in(lib, text)
                self.assertEqual(len(self.maybe_notes(ev)), 1, ev["unverified"])
                self.assertEqual(len(ev["referenced_maybe"]), 1)

    def test_a_generic_name_is_still_found_by_its_whole_path(self):
        lib = self.clone(".cache/claude-trabalho/x/tmp.zzz/mine")
        ev = self.refs_in(lib, "cd %s && ls\n" % lib)
        self.assertEqual(ev["referenced_by_total"], 1)

    def test_the_backlog_case_stays_sure_junk_after_the_plan(self):
        lib = self.clone(".cache/claude-trabalho/x/tmp.zzz/mine")
        self.project_script("cd %s && ./mine/k.js\n" % PARENT, name="chrome_debug.log")
        cands, _ = self.collect()
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual((item["group"], item["reason"]), (1, None))


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class LogsProveNothingByGuess(tds.SearchCase):
    NAME = ".cache/claude-trabalho/x/reference/library"
    GUESS = "cd ~/.cache/claude-trabalho/x/reference && ./library/kernel.js\n"

    def maybe_notes(self, ev):
        return [u for u in ev["unverified"] if u.startswith("referenced_by: possibly cited")]

    def refs_in(self, lib, text, name):
        self.project_script(text, name=name)
        ctx, cand = self.cand_of(lib)
        inventory._apply_refs(ctx, [cand], [])
        return cand["evidence"]

    def test_a_log_never_makes_a_guess_but_the_same_line_in_a_script_does(self):
        lib = self.clone(self.NAME)
        for name in ("chrome_debug.log", "run.LOG", "server.log.1", "a.log.20"):
            with self.subTest(name=name):
                ev = self.refs_in(lib, self.GUESS, name)
                self.assertEqual((ev["referenced_by_total"], self.maybe_notes(ev)), (0, []))
        for name in ("run.sh", "notes.txt", "catalog.logic", "log"):
            with self.subTest(name=name):
                ev = self.refs_in(lib, self.GUESS, name)
                self.assertEqual(len(self.maybe_notes(ev)), 1, (name, ev["unverified"]))

    def test_a_log_that_cites_the_whole_path_is_still_a_dependency(self):
        lib = self.clone(self.NAME)
        ev = self.refs_in(lib, "loaded %s/kernel.js\n" % lib, "app.log")
        self.assertEqual(ev["referenced_by_total"], 1)
        self.assertEqual(self.maybe_notes(ev), [])

    def test_a_guess_from_a_log_does_not_hide_a_guess_from_a_script(self):
        lib = self.clone(self.NAME)
        self.project_script(self.GUESS, name="chrome_debug.log")
        ev = self.refs_in(lib, self.GUESS, "build.sh")
        self.assertEqual(len(ev["referenced_maybe"]), 1)
        self.assertTrue(ev["referenced_maybe"][0].endswith("build.sh"))


if __name__ == "__main__":
    unittest.main()
