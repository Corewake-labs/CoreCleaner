"""Shallow clones (BACKLOG: "Clone raso (--depth 1) ... archive falha no verify").

`git bundle` of a shallow repo cannot be cloned back ("remote did not send all necessary objects"), so the
item never went; and the graft commit of a clone made by `git fetch --depth 1 <url> <sha>` counted as "1
commit on no remote". Real repos under temp dirs; HOME and the git config are redirected (GitCase, Sandbox).
"""

import os
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, common  # noqa: E402
from tests.test_archive import GitCase, snapshot, tar_extract, tree_files  # noqa: E402
from tests.test_review_fixes import POSIX, Sandbox  # noqa: E402

MIB = 1024 * 1024
DIRTY = {"is_repo": True, "dirty": True, "unpushed": 0, "stash": 0, "origin": "git@example.com:me/x.git"}
CLEAN = dict(DIRTY, dirty=False)


class ShallowFixtures(GitCase):
    def source(self):
        """A repo with three commits to clone from."""
        src = self.new_repo("src")
        for n in (1, 2, 3):
            self.write(src, "f%d.txt" % n, "commit %d\n" % n)
            self.commit_all(src, "commit %d" % n)
        return src

    def depth1_clone(self, name="clone"):
        """git clone --depth 1: shallow, with a remote and a remote-tracking branch."""
        src = self.source() if not (self.base / "src").exists() else self.base / "src"
        dst = self.base / name
        self.git(self.base, "clone", "-q", "--depth", "1", "file://" + str(src), str(dst))
        return dst

    def fetched_by_sha(self, name="fetched"):
        """git init + fetch --depth 1 <url> main: shallow, no remote configured, no remote-tracking ref."""
        src = self.source() if not (self.base / "src").exists() else self.base / "src"
        dst = self.base / name
        dst.mkdir()
        self.git(dst, "init", "-q")
        self.git(dst, "fetch", "-q", "--depth", "1", "file://" + str(src), "main")
        self.git(dst, "reset", "-q", "--hard", "FETCH_HEAD")
        return dst

    def is_shallow(self, repo):
        return self.git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class ShallowDetection(ShallowFixtures):
    def test_a_clean_depth_1_clone_needs_no_archive(self):
        clone = self.depth1_clone()
        self.assertTrue(self.is_shallow(clone))
        wants, why = archive.needs_archive(str(clone))
        self.assertFalse(wants, why)
        self.assertIn("shallow clone", why)

    def test_the_graft_commit_is_not_a_commit_on_no_remote(self):
        fetched = self.fetched_by_sha()
        self.assertTrue(self.is_shallow(fetched))
        # what git alone says (the old answer): the one commit we hold is "on no remote"
        self.assertEqual(self.git(fetched, "rev-list", "--count", "HEAD", "--branches", "--not", "--remotes").strip(), "1")
        wants, why = archive.needs_archive(str(fetched))
        self.assertFalse(wants, why)
        self.assertNotIn("no remote", why)

    def test_a_local_commit_on_top_of_the_graft_counts_once(self):
        fetched = self.fetched_by_sha()
        self.write(fetched, "mine.txt", "local work\n")
        self.commit_all(fetched, "mine")
        wants, why = archive.needs_archive(str(fetched))
        self.assertTrue(wants)
        self.assertIn("1 commit(s) on no remote", why)

    def test_a_local_tag_on_the_graft_commit_is_not_tag_only_work_but_one_on_a_new_commit_is(self):
        fetched = self.fetched_by_sha()
        self.git(fetched, "tag", "v-fetched")
        self.assertFalse(archive.needs_archive(str(fetched))[0])
        self.git(fetched, "checkout", "-q", "--detach")
        self.write(fetched, "orphan.txt", "x\n")
        self.commit_all(fetched, "orphan")
        self.git(fetched, "tag", "v-local")
        self.git(fetched, "checkout", "-q", "main")
        wants, why = archive.needs_archive(str(fetched))
        self.assertTrue(wants)
        self.assertIn("local tags", why)

    def test_uncommitted_untracked_and_stash_still_count_in_a_shallow_clone(self):
        clone = self.depth1_clone()
        self.write(clone, "f3.txt", "edited\n")
        self.write(clone, "new.txt", "untracked\n")
        wants, why = archive.needs_archive(str(clone))
        self.assertTrue(wants)
        self.assertIn("1 uncommitted change(s)", why)
        self.assertIn("1 untracked file(s)", why)
        self.assertIn("shallow clone: archived as one tar", why)
        self.git(clone, "stash", "push", "-q")
        self.assertIn("stash entr", archive.needs_archive(str(clone))[1])

    def test_a_hand_edited_shallow_file_cannot_hide_local_commits(self):
        repo = self.new_repo("local")
        for n in (1, 2):
            self.write(repo, "f%d.txt" % n, "%d\n" % n)
            self.commit_all(repo, "c%d" % n)
        head = self.git(repo, "rev-parse", "HEAD").strip()
        (repo / ".git" / "shallow").write_text(head + "\n")  # claims HEAD is a fetched boundary
        self.assertTrue(self.is_shallow(repo))
        wants, why = archive.needs_archive(str(repo))
        self.assertTrue(wants, why)  # its parent is present, so it was made here
        self.assertIn("no remote", why)

    def test_a_root_commit_listed_as_a_boundary_is_still_local_work(self):
        repo = self.new_repo("root")
        self.write(repo, "a.txt", "a\n")
        self.commit_all(repo, "root")
        (repo / ".git" / "shallow").write_text(self.git(repo, "rev-parse", "HEAD").strip() + "\n")
        wants, why = archive.needs_archive(str(repo))
        self.assertTrue(wants, why)  # it names no parent, so it cannot be a cut-off commit

    def test_garbage_in_the_shallow_file_is_ignored_and_fails_toward_archiving(self):
        repo = self.new_repo("junk")
        self.write(repo, "a.txt", "a\n")
        self.commit_all(repo, "root")
        (repo / ".git" / "shallow").write_bytes(b"not a sha\n\xff\xfe\n" + b"0" * 40 + b"\n")
        wants, _why = archive.needs_archive(str(repo))
        self.assertTrue(wants)

    def test_an_ordinary_repo_is_not_shallow(self):
        wants, why = archive.needs_archive(str(self.pushed_repo()))
        self.assertEqual((wants, why), (False, "clean, published, no stash"))


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class ShallowArchive(ShallowFixtures):
    def dirty_clone(self):
        clone = self.depth1_clone()
        self.write(clone, ".gitignore", "cache/\n.env\n")
        self.git(clone, "add", ".gitignore")
        self.write(clone, "f3.txt", "edited, staged\n")
        self.git(clone, "add", "f3.txt")
        self.write(clone, "f2.txt", "edited, unstaged\n")
        self.write(clone, "new dir/untracked ü.txt", "untracked\n")
        self.write(clone, ".env", "SECRET=only-copy\n")
        self.write(clone, "cache/big.dat", b"x" * 5000)
        return clone

    def test_a_dirty_shallow_clone_is_archived_as_one_whole_repo_tar(self):
        clone = self.dirty_clone()
        before = snapshot(clone)
        dest = self.base / "arch"
        info = archive.archive_repo(str(clone), str(dest))
        self.assertTrue(info["shallow"] and info["verified"])
        self.assertIsNone(info["bundle"])
        self.assertIsNone(info["diff"])
        self.assertIsNone(info["untracked_tar"])
        self.assertIsNone(info["protected_tar"])
        self.assertEqual(info["repo_tar"], str(dest / archive.SHALLOW_TAR_NAME))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), [archive.MANIFEST_NAME, archive.SHALLOW_TAR_NAME])
        self.assertEqual(info["incomplete"], [])
        self.assertIn("listed to the end", info["restore_test"])
        self.assertEqual(snapshot(clone), before)  # the source is not touched

        restored = self.base / "restored"
        restored.mkdir()
        tar_extract(dest / archive.SHALLOW_TAR_NAME, restored)
        self.assertEqual(tree_files(restored), tree_files(clone))  # every file, ignored and .env included
        self.assertEqual(tree_files(restored)[".env"], b"SECRET=only-copy\n")
        self.assertTrue(self.is_shallow(restored))
        self.assertEqual(self.git(restored, "status", "--porcelain"), self.git(clone, "status", "--porcelain"))
        self.assertEqual(self.git(restored, "rev-parse", "HEAD"), self.git(clone, "rev-parse", "HEAD"))
        self.assertEqual(self.git(restored, "rev-list", "--count", "HEAD").strip(), "1")

        text = (dest / archive.MANIFEST_NAME).read_text()
        self.assertIn("shallow: yes", text)
        self.assertIn("tar -xzf %s" % archive.SHALLOW_TAR_NAME, text)
        self.assertNotIn("git clone bundle.git", text)
        self.assertEqual(info["counts"]["uncommitted_changes"], 3)  # .gitignore, f3.txt staged, f2.txt unstaged

    def test_a_local_commit_in_a_clone_fetched_by_sha_comes_back_from_the_tar(self):
        fetched = self.fetched_by_sha()
        self.write(fetched, "mine.txt", "local work\n")
        self.commit_all(fetched, "my only copy")
        dest = self.base / "arch"
        info = archive.archive_repo(str(fetched), str(dest))
        self.assertEqual(info["counts"]["unpublished_commits"], 1)
        restored = self.base / "restored"
        restored.mkdir()
        tar_extract(dest / archive.SHALLOW_TAR_NAME, restored)
        self.assertEqual(self.git(restored, "log", "-1", "--format=%s").strip(), "my only copy")
        self.assertEqual(tree_files(restored)["mine.txt"], b"local work\n")

    def test_the_estimate_is_the_whole_tree_for_a_shallow_clone(self):
        clone = self.depth1_clone()
        self.write(clone, ".gitignore", "cache/\n")
        self.write(clone, "cache/big.dat", b"x" * (3 * MIB))
        self.assertGreaterEqual(archive.estimate_archive_bytes(str(clone)), 3 * MIB)
        ordinary = self.pushed_repo("ordinary")
        self.write(ordinary, ".gitignore", "cache/\n")
        self.write(ordinary, "cache/big.dat", b"x" * (3 * MIB))
        self.assertLess(archive.estimate_archive_bytes(str(ordinary)), 3 * MIB)  # ignored data is not archived there

    def test_a_linked_worktree_of_a_shallow_clone_is_refused_not_half_archived(self):
        clone = self.depth1_clone()
        wt = self.base / "wt"
        self.git(clone, "worktree", "add", "-q", "-b", "side", str(wt))
        self.write(wt, "work.txt", "only here\n")
        with self.assertRaises(common.CorecleanerError) as ctx:
            archive.archive_repo(str(wt), str(self.base / "arch"))
        self.assertIn("not a folder", ctx.exception.message)
        self.assertFalse((self.base / "arch" / archive.MANIFEST_NAME).exists())

    def test_the_tar_must_list_head_and_shallow(self):
        good = self.base / "good.tar.gz"
        src = self.base / "tree"
        (src / ".git").mkdir(parents=True)
        (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (src / ".git" / "shallow").write_text("x\n")
        with tarfile.open(str(good), "w:gz") as tf:
            tf.add(str(src / ".git"), arcname=".git")
        self.assertIn("HEAD and", archive._verify_whole_tar(good, False))
        bad = self.base / "bad.tar.gz"
        with tarfile.open(str(bad), "w:gz") as tf:
            tf.add(str(src / ".git" / "HEAD"), arcname=".git/HEAD")
        with self.assertRaises(common.CorecleanerError) as ctx:
            archive._verify_whole_tar(bad, False)
        self.assertIn(".git/shallow", ctx.exception.message)

    def test_an_ordinary_dirty_repo_still_gets_a_bundle(self):
        repo = self.dirty_repo()
        info = archive.archive_repo(str(repo), str(self.base / "arch"))
        self.assertTrue(info["bundle"] and info["diff"])
        self.assertNotIn("shallow", info)
        self.assertFalse((self.base / "arch" / archive.SHALLOW_TAR_NAME).exists())


@unittest.skipUnless(POSIX, "git fixtures with POSIX paths")
class ShallowThroughTrash(Sandbox):
    def clone(self, name="clone"):
        src = self.repo(self.work / "src")
        self.write(src / "b.txt", "b\n")
        self.git(src, "add", ".")
        self.git(src, "commit", "-q", "-m", "c2")
        dst = self.work / name
        self.git(self.work, "clone", "-q", "--depth", "1", "file://" + str(src), str(dst))
        return dst

    def test_a_clean_shallow_clone_goes_to_the_trash_without_an_archive(self):
        clone = self.clone()
        self.age(clone)
        _item, row, _out = self.one(self.cand(clone, cat="C", git=CLEAN))
        self.assertEqual((row["status"], row["reason"]), ("ok", "moved to the Trash"), row)
        self.assertEqual(self.moved, [str(clone)])
        self.assertFalse((self.home / "corecleaner-archive").exists())

    def test_a_dirty_shallow_clone_is_archived_then_trashed(self):
        clone = self.clone()
        self.write(clone / "mine.txt", "unsaved\n")
        self.age(clone)
        _item, row, out = self.one(self.cand(clone, cat="C", git=DIRTY))
        self.assertEqual(row["status"], "ok", row)
        self.assertIn("after archiving", row["reason"])
        self.assertEqual(self.moved, [str(clone)])
        archives = list((self.home / "corecleaner-archive").glob("*/*/" + archive.SHALLOW_TAR_NAME))
        self.assertEqual(len(archives), 1)
        with tarfile.open(str(archives[0]), "r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn("mine.txt", names)
        self.assertIn(".git/shallow", names)

    def test_the_dry_run_promises_the_archive_of_a_dirty_shallow_clone(self):
        clone = self.clone()
        self.write(clone / "mine.txt", "unsaved\n")
        self.age(clone)
        _item, row, _out = self.one(self.cand(clone, cat="C", git=DIRTY), apply=False)
        self.assertEqual(row["status"], "ok")
        self.assertIn("would archive 1 repo", row["reason"])
        self.assertFalse((self.home / "corecleaner-archive").exists())


if __name__ == "__main__":
    unittest.main()
