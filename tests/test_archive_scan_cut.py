"""A protected-name scan that did not finish refuses the trash (BACKLOG: "protected_cut ... vira so aviso").

An ignored tree too big to scan for `.env` and keys used to be a warning in the archive MANIFEST while the
repo still went to the Trash: a key past the scan cap was lost with no copy. Real repos, a fake Trash and
a fake HOME, all under temp dirs (Sandbox).
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, safety, trash as trash_mod  # noqa: E402
from tests.test_review_fixes import POSIX, Sandbox  # noqa: E402

CLEAN_PUBLISHED = {"is_repo": True, "dirty": False, "unpushed": 0, "stash": 0, "origin": "git@example.com:me/x.git"}


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class ScanCutRefusesTheTrash(Sandbox):
    def clone(self, keys=0):
        """A clean, published repo with an ignored `certs/` of `keys` key files and an ignored `cache/`."""
        repo = self.repo(self.work / "clone", published=True)
        self.write(repo / ".gitignore", "certs/\ncache/\n")
        self.git(repo, "add", ".gitignore")
        self.git(repo, "commit", "-q", "-m", "ignore")
        self.git(repo, "push", "-q", "origin", "main")
        self.write(repo / "cache" / "blob.bin", "cached\n")
        for n in range(keys):
            self.write(repo / "certs" / ("k%02d.pem" % n), "key %d\n" % n)
        self.age(repo)
        return repo

    def cut(self):
        return mock.patch.object(archive.safety, "find_protected_inside", return_value=([], True))

    def test_a_clean_repo_whose_ignored_tree_cannot_be_scanned_is_not_trashed(self):
        repo = self.clone()
        self.assertEqual(archive.needs_archive(str(repo))[0], False)  # control: nothing else to save
        with self.cut():
            wants, why = archive.needs_archive(str(repo))
            _item, row, _out = self.one(self.cand(repo, cat="C", git=CLEAN_PUBLISHED))
        self.assertFalse(wants)
        self.assertIn(archive.PROTECTED_CUT_NOTE, why)
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("too big to scan", row["reason"])
        self.assertIn("not trashed", row["reason"])
        self.assertTrue(repo.is_dir())
        self.assertEqual(self.moved, [])
        self.assertFalse((self.home / "corecleaner-archive").exists())

    def test_the_dry_run_says_the_same(self):
        repo = self.clone()
        with self.cut():
            _item, row, _out = self.one(self.cand(repo, cat="C", git=CLEAN_PUBLISHED), apply=False)
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("would not be moved", row["reason"])
        self.assertIn("too big to scan", row["reason"])

    def test_more_keys_than_the_scan_reports_are_refused_not_archived_in_part(self):
        repo = self.clone(keys=safety.FIND_MAX_HITS + 5)
        wants, why = archive.needs_archive(str(repo))
        self.assertTrue(wants)  # the keys alone already say "archive"
        self.assertIn(archive.PROTECTED_CUT_NOTE, why)
        _item, row, _out = self.one(self.cand(repo, cat="C", git=CLEAN_PUBLISHED))
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("too big to scan", row["reason"])
        self.assertTrue((repo / "certs" / ("k%02d.pem" % (safety.FIND_MAX_HITS + 4))).is_file())
        self.assertEqual(self.moved, [])
        self.assertFalse((self.home / "corecleaner-archive").exists())  # refused before any archive was written

    def test_a_scan_that_finishes_still_archives_the_keys_and_trashes(self):
        repo = self.clone(keys=3)
        _item, row, out = self.one(self.cand(repo, cat="C", git=CLEAN_PUBLISHED))
        self.assertEqual(row["status"], "ok", row)
        self.assertIn("after archiving", row["reason"])
        self.assertEqual(self.moved, [str(repo)])

    def test_a_clean_repo_with_a_finished_scan_is_trashed_plainly(self):
        repo = self.clone()
        _item, row, _out = self.one(self.cand(repo, cat="C", git=CLEAN_PUBLISHED))
        self.assertEqual((row["status"], row["reason"]), ("ok", "moved to the Trash"))

    def test_archive_repo_reports_the_cut_as_incomplete_and_the_caller_keeps_the_repo(self):
        repo = self.clone()
        dest = self.base / "arch"
        with self.cut():
            info = archive.archive_repo(str(repo), str(dest))
        self.assertEqual(info["incomplete"], [archive.PROTECTED_CUT_NOTE])
        self.assertIn(archive.PROTECTED_CUT_NOTE, info["warnings"])
        self.assertIn(archive.PROTECTED_CUT_NOTE, (dest / archive.MANIFEST_NAME).read_text())

    def test_a_cut_that_appears_only_while_archiving_still_stops_the_move(self):
        repo = self.clone()
        plan, plan_file = self.plan_for(self.cand(repo, cat="C", git=CLEAN_PUBLISHED))
        item = plan["items"][0]
        # the early check saw nothing; the cut shows up inside archive_repo (a tree that grew meanwhile)
        with mock.patch.object(trash_mod, "_archive_needs", return_value=([(str(repo), "dirty")], None)), self.cut():
            out = self.trash(plan_file, [item["id"]])
        row = out["items"][0]
        self.assertEqual(row["status"], "skipped", row)
        self.assertIn("would not cover everything", row["reason"])
        self.assertTrue(repo.is_dir())
        self.assertEqual(self.moved, [])


if __name__ == "__main__":
    unittest.main()
