"""Repos nested inside a folder that goes to the Trash (BACKLOG: ".git aninhado dentro de pasta enviada a
Lixeira so e arquivado no topo (submodulo/worktree hoje e recusado)").

Three shapes, all with real repos under temp dirs (Sandbox: fake HOME, state dir, git identity, fake Trash):
  1. a scratch unit (not a repo) holding repos at any depth: each one is archived before the unit moves;
  2. a repo holding a submodule or a linked worktree with work: refused, as before;
  3. a repo holding another repo inside an IGNORED folder (`vendor/`): git ignores it, so no bundle and no tar
     of the outer repo holds its work; it used to reach the Trash with it. Now the outer repo is refused.
"""

import json
import os
import stat
import sys
import tarfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, safety  # noqa: E402
from tests.test_review_fixes import POSIX, Sandbox  # noqa: E402

DIRTY = {"is_repo": True, "dirty": True, "unpushed": 1, "stash": 0, "origin": None}
CLEAN = {"is_repo": True, "dirty": False, "unpushed": 0, "stash": 0, "origin": "git@example.com:me/x.git"}


class Nested(Sandbox):
    def unsaved_repo(self, path, name="UNSAVED.py"):
        repo = self.repo(path)
        self.write(repo / name, "print('only copy of %s')\n" % Path(path).name)
        return repo

    def archive_dir(self, out):
        manifest = [json.loads(x) for x in (self.state / "runs" / (out["run_id"] + ".jsonl")).read_text().splitlines()]
        return Path(manifest[0]["archive"])

    def archived_by_name(self, out):
        """{repo folder name: archive folder} for a unit that held several repos."""
        root = self.archive_dir(out)
        return {p.name.split("-", 1)[1]: p for p in root.iterdir() if p.is_dir()}

    def tar_names(self, path):
        with tarfile.open(str(path), "r:gz") as tf:
            return set(tf.getnames())

    def assert_archived_with_work(self, folder, name="UNSAVED.py"):
        self.assertTrue((folder / "bundle.git").is_file(), sorted(p.name for p in folder.iterdir()))
        self.assertIn(name, self.tar_names(folder / "untracked.tar.gz"))


# =============================================================================== 1. repos inside a scratch unit


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class RepoTwoLevelsInsideAScratchUnit(Nested):
    def unit(self, *rels):
        unit = self.work / "unit"
        for rel in rels:
            self.unsaved_repo(unit / rel)
        self.write(unit / "notes.txt", "scratch notes\n")
        self.age(unit)
        return unit, self.cand(unit, cat="D", git=DIRTY)

    def test_a_repo_two_levels_deep_is_archived_before_the_unit_moves(self):
        unit, cand = self.unit("group/sub/proj")
        item, row, out = self.one(cand)
        self.assertEqual(item["action"], "archive_then_trash")
        self.assertEqual(row["status"], "ok", row)
        self.assertIn("after archiving", row["reason"])
        self.assertEqual(self.moved, [str(unit)])
        self.assertFalse(unit.exists())
        found = self.archived_by_name(out)
        self.assertEqual(list(found), ["proj"])
        self.assert_archived_with_work(found["proj"])

    def test_repos_at_different_depths_each_get_their_own_archive(self):
        unit, cand = self.unit("one", "a/two", "a/b/c/three")
        _item, row, out = self.one(cand)
        self.assertEqual(row["status"], "ok", row)
        found = self.archived_by_name(out)
        self.assertEqual(sorted(found), ["one", "three", "two"])
        for folder in found.values():
            self.assert_archived_with_work(folder)
        self.assertEqual(self.moved, [str(unit)])

    def test_the_dry_run_counts_every_nested_repo_and_writes_nothing(self):
        _unit, cand = self.unit("group/sub/proj", "other")
        _item, row, _out = self.one(cand, apply=False)
        self.assertEqual(row["status"], "ok")
        self.assertIn("would archive 2 repo(s)", row["reason"])
        self.assertFalse((self.home / "corecleaner-archive").exists())
        self.assertEqual(self.moved, [])

    def test_a_clean_published_repo_deep_in_the_unit_needs_no_archive(self):
        unit = self.work / "unit"
        self.repo(unit / "group" / "sub" / "proj", published=True)
        self.age(unit)
        _item, row, _out = self.one(self.cand(unit, cat="D", git=CLEAN))
        self.assertEqual((row["status"], row["reason"]), ("ok", "moved to the Trash"), row)
        self.assertFalse((self.home / "corecleaner-archive").exists())

    def test_a_repo_below_the_search_depth_stops_the_move_instead_of_being_missed(self):
        unit = self.work / "unit"
        self.unsaved_repo(unit / "a" / "b" / "c" / "d" / "e" / "f" / "g")  # 7 levels: out of reach
        self.age(unit)
        _item, row, _out = self.one(self.cand(unit, cat="D", git=DIRTY))
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("hit its limit", row["reason"])
        self.assertEqual(self.moved, [])
        self.assertFalse((self.home / "corecleaner-archive").exists())


# =============================================================================== 2. submodule and worktree stay refused


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class SubmoduleAndWorktreeWithWorkAreStillRefused(Nested):
    def refused(self, row):
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("work outside what an archive covers", row["reason"])
        self.assertEqual(self.moved, [])
        self.assertFalse((self.home / "corecleaner-archive").exists())

    def test_a_submodule_with_work_inside_a_repo_nested_in_a_unit(self):
        lib = self.repo(self.base / "lib", published=True)
        unit = self.work / "unit"
        outer = self.repo(unit / "a" / "outer")
        self.git(outer, "submodule", "add", "-q", str(lib), "sub")
        self.git(outer, "commit", "-q", "-m", "add sub")
        self.write(outer / "sub" / "unsaved.txt", "work in the submodule\n")
        self.age(unit)
        _item, row, _out = self.one(self.cand(unit, cat="D", git=DIRTY))
        self.refused(row)
        self.assertIn("submodule", row["reason"])

    def test_a_linked_worktree_with_work_inside_a_unit(self):
        unit = self.work / "unit"
        outer = self.repo(unit / "outer")
        wt = unit / "wt"
        self.git(outer, "worktree", "add", "-q", "-b", "side", str(wt))
        self.write(wt / "work.txt", "only in the worktree\n")
        self.age(unit)
        _item, row, _out = self.one(self.cand(unit, cat="D", git=DIRTY))
        self.refused(row)
        self.assertIn("linked worktree", row["reason"])

    def test_a_clean_submodule_does_not_block_a_published_repo(self):
        lib = self.repo(self.base / "lib", published=True)
        outer = self.repo(self.work / "outer", published=True)
        self.git(outer, "submodule", "add", "-q", str(lib), "sub")
        self.git(outer, "commit", "-q", "-m", "add sub")
        self.git(outer, "push", "-q", "origin", "main")
        self.age(outer)
        self.assertEqual(archive.incomplete(str(outer)), [])


# =============================================================================== 3. a repo inside an ignored folder


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class RepoInsideAnIgnoredFolder(Nested):
    def outer(self, ignore="vendor/\n"):
        """A clean, published repo: nothing of its own to save."""
        outer = self.repo(self.work / "outer", published=True)
        self.write(outer / ".gitignore", ignore)
        self.git(outer, "add", ".gitignore")
        self.git(outer, "commit", "-q", "-m", "ignore")
        self.git(outer, "push", "-q", "origin", "main")
        return outer

    def test_the_outer_repo_alone_needs_nothing(self):
        outer = self.outer()
        self.assertEqual(archive.needs_archive(str(outer)), (False, "clean, published, no stash"))

    def test_an_ignored_repo_with_unsaved_work_stops_the_trash_of_the_outer_repo(self):
        outer = self.outer()
        self.unsaved_repo(outer / "vendor" / "inner")
        self.age(outer)
        _item, row, _out = self.one(self.cand(outer, cat="C", git=CLEAN))
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("nested in an ignored folder", row["reason"])
        self.assertIn("not trashed", row["reason"])
        self.assertEqual(self.moved, [])
        self.assertTrue((outer / "vendor" / "inner" / "UNSAVED.py").is_file())
        self.assertFalse((self.home / "corecleaner-archive").exists())

    def test_the_dry_run_says_the_same(self):
        outer = self.outer()
        self.unsaved_repo(outer / "vendor" / "inner")
        self.age(outer)
        _item, row, _out = self.one(self.cand(outer, cat="C", git=CLEAN), apply=False)
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("would not be moved", row["reason"])
        self.assertIn("nested in an ignored folder", row["reason"])

    def test_a_deeper_ignored_repo_is_found_too(self):
        outer = self.outer()
        self.unsaved_repo(outer / "vendor" / "a" / "b" / "inner")
        labels = archive.incomplete(str(outer))
        self.assertEqual(len(labels), 1, labels)
        self.assertIn("nested in an ignored folder", labels[0])

    def test_a_clean_published_ignored_repo_does_not_block(self):
        outer = self.outer()
        self.repo(outer / "vendor" / "inner", published=True)
        self.age(outer)
        self.assertEqual(archive.incomplete(str(outer)), [])
        _item, row, _out = self.one(self.cand(outer, cat="C", git=CLEAN))
        self.assertEqual((row["status"], row["reason"]), ("ok", "moved to the Trash"), row)

    def test_a_repo_under_a_regenerable_name_is_not_searched(self):
        outer = self.outer(ignore="node_modules/\n")
        self.unsaved_repo(outer / "node_modules" / "pkg")
        self.assertEqual(archive.incomplete(str(outer)), [])

    def test_a_linked_worktree_in_an_ignored_folder_is_counted_once_as_a_worktree(self):
        outer = self.outer(ignore=".claude/\n")
        wt = outer / ".claude" / "worktrees" / "x"
        self.git(outer, "worktree", "add", "-q", "-b", "side", str(wt))
        self.write(wt / "work.txt", "only in the worktree\n")
        labels = archive.incomplete(str(outer))
        self.assertEqual(len(labels), 1, labels)
        self.assertIn("linked worktree", labels[0])

    def test_an_untracked_repo_that_is_not_ignored_is_still_stored_by_the_untracked_tar(self):
        outer = self.outer()
        self.unsaved_repo(outer / "tools" / "inner")
        self.assertEqual(archive.incomplete(str(outer)), [])  # not this check's business: the tar has it
        wants, why = archive.needs_archive(str(outer))
        self.assertTrue(wants, why)
        info = archive.archive_repo(str(outer), str(self.base / "arch"))
        names = self.tar_names(info["untracked_tar"])
        self.assertIn("tools/inner/UNSAVED.py", names)
        self.assertIn("tools/inner/.git/HEAD", names)

    def test_an_unreadable_ignored_folder_is_not_proven_empty_of_repos(self):
        outer = self.outer(ignore="cache/\n")
        locked = outer / "cache" / "locked"
        locked.mkdir(parents=True)
        self.write(outer / "cache" / "ok.txt", "x\n")
        os.chmod(str(locked), 0)
        self.addCleanup(os.chmod, str(locked), stat.S_IRWXU)
        self.assertIn(archive.NESTED_CUT_NOTE, archive.incomplete(str(outer)))

    def test_an_ignored_folder_bigger_than_the_scan_budget_is_not_proven_either(self):
        outer = self.outer(ignore="cache/\n")
        for n in range(10):
            self.write(outer / "cache" / ("f%d.txt" % n), "x\n")
        self.assertEqual(archive.incomplete(str(outer)), [])
        with mock.patch.object(safety, "FIND_CAP", 3):
            self.assertIn(archive.NESTED_CUT_NOTE, archive.incomplete(str(outer)))

    def test_archive_repo_reports_the_nested_work_as_incomplete(self):
        outer = self.outer()
        self.write(outer / "mine.txt", "so the outer repo needs an archive too\n")
        self.unsaved_repo(outer / "vendor" / "inner")
        info = archive.archive_repo(str(outer), str(self.base / "arch"))
        self.assertTrue(any("nested in an ignored folder" in x for x in info["incomplete"]), info["incomplete"])
        self.assertEqual(info["incomplete"], [w for w in info["warnings"] if "nested" in w])

    def test_an_item_that_needs_an_archive_and_has_nested_work_is_refused_before_anything_is_written(self):
        outer = self.outer()
        self.write(outer / "mine.txt", "uncommitted\n")
        self.unsaved_repo(outer / "vendor" / "inner")
        self.age(outer)
        _item, row, _out = self.one(self.cand(outer, cat="C", git=DIRTY))
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("nested in an ignored folder", row["reason"])
        self.assertFalse((self.home / "corecleaner-archive").exists())
        self.assertEqual(self.moved, [])


if __name__ == "__main__":
    unittest.main()
