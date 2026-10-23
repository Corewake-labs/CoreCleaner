"""Regressions from the 2026-10-22 dogfood and lens review (PROBLEMS_AND_RESOLUTIONS.md).

Every fixture lives under a temp dir this file creates; nothing here touches HOME or the real state dir.
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import sys

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, ask as ask_mod, gitguard, inventory, plan as plan_mod, safety, trash  # noqa: E402
from tests.test_plan_ask import OLD, evidence, plan_of, item  # noqa: E402

HAVE_GIT = shutil.which("git") is not None
POSIX = os.name == "posix"
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def git(cwd, *args, check=True):
    env = dict(os.environ)
    env.update(GIT_ENV)
    p = subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", *args],
                       cwd=str(cwd), env=env, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise AssertionError("git %s: %s" % (" ".join(args), p.stderr))
    return p


def repo(path, files=None):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    for name, data in (files or {"README.md": "hi\n"}).items():
        full = path / name
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(data)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "first")
    return path


class TempCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-dogfood-")))
        self.addCleanup(shutil.rmtree, str(self.root), True)  # a temp dir this test created
        self.state = self.root / "state"
        patcher = mock.patch.dict(os.environ, {"CORECLEANER_STATE_DIR": str(self.state), "HOME": str(self.root / "home")})
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "home").mkdir()


class PlanHonoursListOnly(TempCase):
    def test_a_list_only_candidate_is_shown_only_never_group_2(self):
        models = self.root / "models"
        models.mkdir()
        (models / "w.bin").write_bytes(b"x" * 10)
        for q in (models / "w.bin", models):
            os.utime(q, (OLD, OLD))  # old enough: only the list_only rule may deny it
        cand = {"category": "G", "kind": "model.ollama", "path": str(models), "bytes": 10, "mtime": OLD, "owner": "user",
                "evidence": evidence(), "action": "list_only"}
        it = plan_mod.build_plan([cand])["items"][0]
        self.assertEqual((it["group"], it["action"]), (3, "list_only"))
        self.assertIn("listed only", it["deny"])


@unittest.skipUnless(HAVE_GIT and POSIX, "needs git and POSIX")
class RepoDiscovery(TempCase):
    def test_a_repo_at_the_depth_limit_is_found_and_the_cut_is_reported(self):
        unit = self.root / "unit"
        deep = unit / "a" / "b" / "c" / "d" / "e" / "f"  # depth 6 below the unit
        repo(deep)
        found, truncated = inventory.find_repos(str(unit), 6)
        self.assertEqual(found, [str(deep)])
        deeper = unit / "x" / "y" / "z" / "w" / "v" / "u" / "t"
        repo(deeper)  # depth 7: out of reach, so the walk must say it is not complete
        found, truncated = inventory.find_repos(str(unit), 6)
        self.assertEqual(found, [str(deep)])
        self.assertTrue(truncated)

    def test_a_clone_named_like_a_tool_cache_is_still_a_repo(self):
        unit = self.root / "unit"
        for name in ("whisper", "bun", "uv"):
            repo(unit / name)
        (unit / "node_modules" / "pkg").mkdir(parents=True)
        found, _ = inventory.find_repos(str(unit), 6)
        self.assertEqual(sorted(os.path.basename(p) for p in found), ["bun", "uv", "whisper"])

    def test_a_worktree_entry_whose_folder_has_no_git_file_is_shown_only(self):
        main = repo(self.root / "main")
        wt = self.root / "wt"
        git(main, "worktree", "add", "-q", str(wt))
        (wt / ".git").unlink()  # a stale entry: git still lists it (prunable), the folder is just a folder now
        out = []
        inventory._worktree_cand(inventory.default_ctx(), str(wt), "user", str(main), True, out, set())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["action"], "list_only")
        self.assertTrue(out[0]["evidence"]["not_a_worktree"])

    def test_a_symlinked_scratch_root_is_refused(self):
        tmpbase = self.root / "tmp"
        tmpbase.mkdir()
        target = self.root / "home" / "Documents"
        target.mkdir()
        os.symlink(str(target), str(tmpbase / ("claude-%d" % os.getuid())))
        ctx = inventory.default_ctx()
        ctx.tmp_bases = [str(tmpbase)]
        self.assertEqual(inventory.claude_tmp_roots(ctx), [])


@unittest.skipUnless(HAVE_GIT and POSIX, "needs git and POSIX")
class ArchiveCoversMore(TempCase):
    def test_older_stashes_ride_in_the_bundle(self):
        r = repo(self.root / "r")
        (r / "README.md").write_text("one\n")
        git(r, "stash", "-q")
        (r / "README.md").write_text("two\n")
        git(r, "stash", "-q")
        older = git(r, "rev-parse", "stash@{1}").stdout.strip()
        dest = self.root / "arch"
        archive.archive_repo(str(r), str(dest))
        clone = self.root / "clone"
        git(self.root, "clone", "-q", str(dest / archive.BUNDLE_NAME), str(clone))
        self.assertEqual(git(clone, "cat-file", "-e", older + "^{commit}", check=False).returncode, 0)

    def test_a_commit_only_under_a_local_tag_needs_archive(self):
        r = repo(self.root / "r")
        remote = self.root / "remote.git"
        git(self.root, "init", "-q", "--bare", str(remote))
        git(r, "remote", "add", "origin", str(remote))
        git(r, "push", "-q", "origin", "main")
        self.assertFalse(archive.needs_archive(str(r))[0])
        git(r, "checkout", "-q", "--detach")
        (r / "orphan.txt").write_text("x\n")
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "orphan")
        git(r, "tag", "v-local")
        git(r, "checkout", "-q", "main")
        needs, why = archive.needs_archive(str(r))
        self.assertTrue(needs)
        self.assertIn("local tags", why)

    def test_hidden_edits_and_bare_gitlinks_make_the_archive_incomplete(self):
        r = repo(self.root / "r", {"a.txt": "a\n", "b.txt": "b\n"})
        git(r, "update-index", "--assume-unchanged", "a.txt")
        (r / "a.txt").write_text("edited behind status\n")
        self.assertEqual(git(r, "status", "--porcelain").stdout.strip(), "")  # git itself cannot see it
        labels = archive.incomplete(str(r))
        self.assertTrue(any("hidden from status" in x for x in labels), labels)
        inner = repo(r / "vendor" / "lib")
        git(r, "add", "vendor/lib")  # a gitlink with no .gitmodules entry
        git(r, "commit", "-q", "-m", "embed")
        (inner / "new.txt").write_text("unsaved\n")
        labels = archive.incomplete(str(r))
        self.assertTrue(any("submodule" in x for x in labels), labels)

    def test_a_conditional_include_in_a_submodule_config_is_unsafe(self):
        lib = repo(self.root / "lib")
        outer = repo(self.root / "outer")
        git(outer, "submodule", "add", "-q", str(lib), "sub")
        git(outer, "commit", "-q", "-m", "sub")
        cfg = outer / ".git" / "modules" / "sub" / "config"
        with open(cfg, "a") as fh:
            fh.write('[includeIf "gitdir:**/modules/sub"]\n    path = /nonexistent/inc\n')

        def run_git(*args):
            p = git(outer, *args, check=False)
            return p.returncode, p.stdout

        self.assertIn(gitguard.CONDITIONAL, gitguard.unsafe_config(run_git, str(outer)))


class ProtectedScanCap(TempCase):
    def test_the_hit_cap_is_reported_as_a_cut(self):
        certs = self.root / "unit" / "certs"
        certs.mkdir(parents=True)
        for i in range(25):
            (certs / ("k%02d.pem" % i)).write_text("key\n")
        hits, cut = safety.find_protected_inside(str(self.root / "unit"))
        self.assertEqual(len(hits), safety.FIND_MAX_HITS)
        self.assertTrue(cut)


class DuplicatesSkipBundles(TempCase):
    def test_copies_inside_node_modules_or_an_app_bundle_are_not_duplicates(self):
        home = self.root / "home"
        data = os.urandom(1 << 20) + b"x"
        for rel in ("Downloads/a/node_modules/x/bin.dat", "Downloads/b/node_modules/x/bin.dat",
                    "Downloads/Foo.app/Contents/lib", "Downloads/Foo 2.app/Contents/lib",
                    "Downloads/loose1.dat", "Downloads/loose2.dat"):
            p = home / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        ctx = inventory.default_ctx()
        ctx.home = home
        out = []
        inventory._detect_I(ctx, out)
        paths = sorted(c["path"] for c in out)
        self.assertEqual(len(paths), 1, paths)
        self.assertTrue(paths[0].endswith(("loose1.dat", "loose2.dat")))


class TrashLooksOnceMore(TempCase):
    def test_an_item_that_changed_during_the_archive_step_is_not_moved(self):
        self.state.mkdir(parents=True, exist_ok=True)
        folder = self.root / "cache-x"
        folder.mkdir()
        (folder / "f").write_text("x")
        st = os.lstat(folder)
        it = {"id": "cabc1234", "group": 1, "category": "F", "path": str(folder), "display": "cache-x", "bytes": 10,
              "inode": st.st_ino + 1, "mtime": OLD, "owner": "user", "evidence": {}, "action": "trash", "tool_command": None,
              "deny": None, "keeper": None}

        def trasher(path):
            raise AssertionError("the move must not happen")

        res, stop = trash._apply_item(it, "run-test", trasher)
        self.assertEqual(res["status"], "deny")
        self.assertIn("changed before the move", res["reason"])

    def test_finder_noise_after_the_plan_is_not_an_edit_but_a_new_file_is(self):
        folder = self.root / "proj" / "node_modules"
        (folder / "pkg").mkdir(parents=True)
        (folder / "pkg" / "index.js").write_text("x")
        for q in (folder / "pkg" / "index.js", folder / "pkg", folder):
            os.utime(q, (OLD, OLD))
        it = {"id": "cabc1234", "path": str(folder), "inode": os.lstat(folder).st_ino, "mtime": OLD}
        later = OLD + 86400 * 30
        for d in (folder, folder / "pkg"):  # Finder browsing: a .DS_Store per folder, both folders' mtime moves
            (d / ".DS_Store").write_bytes(b"\0")
            os.utime(d / ".DS_Store", (later, later))
            os.utime(d, (later, later))
        self.assertLessEqual(plan_mod.recheck_item(it)["newest_mtime"], OLD)
        (folder / "pkg" / "new.js").write_text("y")
        with self.assertRaises(plan_mod.CorecleanerError) as ctx:
            plan_mod.recheck_item(it)
        self.assertIn("modified after the plan", str(ctx.exception))


class AskSaysWhereAndExpandsOneCategory(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(safety, "sanitize_name", side_effect=lambda s, maxlen=120: str(s)[:maxlen])
        p.start()
        self.addCleanup(p.stop)

    def test_item_question_names_the_folder_and_the_kept_copy(self):
        it = item(1, 2, cat="I", display="x.pdf", path="/tmp/x/Downloads/x (1).pdf")
        it["keeper"] = {"path": "/tmp/x/Downloads/x.pdf"}
        q = ask_mod.render(plan_of([it]), "claude")["batch_questions"][0][0]
        self.assertIn("in `/tmp/x/Downloads`", q["question"])
        yes = [o for o in q["options"] if "Keep" not in o["label"]][0]
        self.assertIn("The copy at `/tmp/x/Downloads/x.pdf` stays.", yes["description"])

    def test_one_by_one_expands_only_that_category(self):
        items = [item(i, 2, cat="A") for i in range(1, 6)] + [item(i, 2, cat="I") for i in range(6, 12)]
        out = ask_mod.render(plan_of(items), "claude")
        one = [o for m in out["answer_map"] for o in m["options"] if o["effect"] == "expand"]
        self.assertEqual([o["expand"] for o in one], ["2/A", "2/I"])
        out = ask_mod.render(plan_of(items), "claude", expand=ask_mod._parse_expand("2/A"))
        headers = [q["header"] for q in out["batch_questions"][0]]
        self.assertIn("Group 2/I", headers)  # I stays collapsed
        self.assertNotIn("Group 2/A", headers)  # A is now item by item
        self.assertEqual(sum(1 for b in out["batch_questions"] for q in b if q["header"].startswith("Item")), 5)
        with self.assertRaises(Exception):
            ask_mod._parse_expand("2/Z")


if __name__ == "__main__":
    unittest.main()
