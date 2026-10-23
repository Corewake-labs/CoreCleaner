"""M1 of docs/SPEC-migrate.md: `repos` audit. Fake HOME and state dir under mkdtemp; real git; nothing else touched."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
CLI = SCRIPTS / "corecleaner.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import common, inventory, repos  # noqa: E402

DAY = 86400
OLD = time.time() - 90 * DAY
HAVE_GIT = bool(shutil.which("git"))


def age_tree(path, when=OLD):
    for dirpath, dirs, files in os.walk(path, topdown=False):
        for n in files + dirs:
            os.utime(os.path.join(dirpath, n), (when, when), follow_symlinks=False)
    os.utime(path, (when, when), follow_symlinks=False)


class GitCase(unittest.TestCase):
    """A fake HOME with real git repos. Subclasses build fixtures with `git()` and `repo()`."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-repos-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.home = os.path.join(self.root, "home")
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.home)
        env = {"HOME": self.home, "USERPROFILE": self.home, "CORECLEANER_STATE_DIR": self.state,
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def git(self, repo, *args, when=None):
        env = dict(os.environ)
        if when:
            stamp = "@%d +0000" % int(when)
            env.update(GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                               "-c", "init.defaultBranch=main", "-C", repo, *args],
                              check=True, capture_output=True, env=env).stdout.decode()

    def repo(self, rel, files=None, when=OLD):
        path = os.path.join(self.home, rel)
        os.makedirs(path)
        self.git(path, "init", "-q")
        for name, data in (files or {"README.md": b"hi\n"}).items():
            full = os.path.join(path, name)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            Path(full).write_bytes(data)
        self.git(path, "add", "-A")
        self.git(path, "commit", "-q", "-m", "first", when=when)
        return path

    def ctx(self):
        ctx = inventory.default_ctx()
        ctx.ref_seconds = 20.0
        return ctx


@unittest.skipUnless(HAVE_GIT and os.name == "posix", "needs git and POSIX")
class AuditFixture(GitCase):
    def setUp(self):
        super().setUp()
        self.big = self.repo("Documents/old-big", {"data.bin": os.urandom(300_000), ".gitignore": b"node_modules/\n",
                                                   "package.json": b"{}\n", "package-lock.json": b"{}\n"})
        nm = os.path.join(self.big, "node_modules", "pkg")
        os.makedirs(nm)
        Path(nm, "index.js").write_bytes(b"x" * 200_000)
        Path(self.big, ".DS_Store").write_bytes(b"\0")
        Path(self.big, ".git", "FETCH_HEAD").write_text("x\n")
        age_tree(self.big)
        os.utime(os.path.join(nm, "index.js"))  # a fresh install: not an edit of the project
        os.utime(os.path.join(self.big, ".DS_Store"))  # Finder browsed it today: not an edit
        os.utime(os.path.join(self.big, ".git", "FETCH_HEAD"))  # an editor auto-fetched today: not an edit
        os.utime(os.path.join(self.big, ".git", "index"))  # a `git status` refreshed it today: not an edit
        Path(self.big, "assets", ".DS_Store").parent.mkdir()  # Finder browsed a subfolder today: its mtime moves
        Path(self.big, "assets", ".DS_Store").write_bytes(b"\0")
        self.new = self.repo("Documents/new-small", when=time.time())
        self.wt_main = self.repo("Documents/with-worktree")
        self.outside = os.path.join(self.root, "elsewhere", "wt")
        self.git(self.wt_main, "worktree", "add", "-q", "-b", "side", self.outside)
        age_tree(self.wt_main)

    def test_order_age_blockers_and_signature(self):
        result = repos.audit([self.home], 45, ctx=self.ctx())
        paths = [r["path"] for r in result["repos"]]
        self.assertEqual(paths[0], self.big)  # biggest first
        self.assertEqual(set(paths), {self.big, self.new, self.wt_main})
        by = {r["path"]: r for r in result["repos"]}
        big = by[self.big]
        self.assertGreaterEqual(big["idle_days"], 89)  # node_modules touched today does not count
        self.assertGreater(big["node_modules_bytes"], 150_000)
        self.assertEqual(big["copy_bytes"], big["bytes"] - big["node_modules_bytes"])
        self.assertTrue(big["offered"], big["blockers"])
        self.assertEqual(by[self.new]["idle_days"], 0)
        self.assertFalse(by[self.new]["offered"])
        self.assertIn("linked worktree outside the tree (moving would break it)", by[self.wt_main]["blockers"])
        self.assertFalse(by[self.wt_main]["offered"])
        saved = repos.save(result)
        self.assertEqual(repos.load(str(saved))["repos"][0]["path"], self.big)

    def test_last_commit_counts_as_activity(self):
        self.git(self.big, "commit", "-q", "--allow-empty", "-m", "today", when=time.time())
        age_tree(self.big)  # files old again, but the commit is from today
        row = next(r for r in repos.audit([self.home], 45, ctx=self.ctx())["repos"] if r["path"] == self.big)
        self.assertEqual(row["idle_days"], 0)
        self.assertFalse(row["offered"])

    def test_hand_written_or_edited_repos_file_is_rejected(self):
        saved = repos.save(repos.audit([self.home], 45, ctx=self.ctx()))
        data = json.loads(Path(saved).read_text())
        data["repos"][0]["path"] = "/etc"
        forged = Path(saved).with_name("repos-forged.json")
        fd = os.open(str(forged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        with self.assertRaises(common.CorecleanerError) as cm:
            repos.load(str(forged))
        self.assertEqual(cm.exception.code, common.EXIT_PLAN_TAMPERED)

    def test_cli_prints_a_sanitized_summary_and_saves_the_file(self):
        env = dict(os.environ)
        proc = subprocess.run([sys.executable, "-I", "-B", str(CLI), "repos", "--roots", self.home],
                              capture_output=True, text=True, timeout=300, env=env, cwd=self.root)
        out = json.loads(proc.stdout)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["count"], 3)
        self.assertEqual(out["offered"], 1)
        self.assertTrue(out["repos"][0]["display"].startswith("~/Documents/old-big"), out["repos"][0])
        self.assertTrue(out["repos_file"].startswith(os.path.join(self.state, "repos")))
        self.assertNotIn(self.home, proc.stdout.replace(out["repos_file"], ""))


@unittest.skipUnless(HAVE_GIT and os.name == "posix", "needs git and POSIX")
class Blockers(GitCase):
    def test_program_running_config_is_not_read(self):
        path = self.repo("p/filtered")
        self.git(path, "config", "filter.x.clean", "touch /tmp/never-run-%d" % os.getpid())
        self.assertEqual(repos.blockers(self.ctx(), path), ["repo config can run programs (filter driver)"])

    def test_alternates_and_linked_worktree_checkout(self):
        path = self.repo("p/alt")
        Path(path, ".git", "objects", "info", "alternates").write_text("/somewhere/objects\n")
        self.assertIn("borrows objects from another repo (alternates)", repos.blockers(self.ctx(), path))
        wt = os.path.join(self.home, "p", "wt")
        self.git(path, "worktree", "add", "-q", "-b", "w", wt)
        self.assertTrue(repos.blockers(self.ctx(), wt)[0].startswith("its .git is a file or link"))

    def test_never_push_note_names_a_branch_or_covers_all(self):
        path = self.repo("p/notes", {"README.md": b"Branch `local-exp`: never push, it has client data.\n"})
        self.git(path, "branch", "local-exp")
        self.git(path, "branch", "feature")
        run = lambda *a: inventory._git(self.ctx(), path, *a)  # noqa: E731
        self.assertEqual(repos.never_push(path, ["main", "local-exp", "feature"], run), {"all": False, "branches": ["local-exp"]})
        Path(path, "NOTES.md").write_text("Este repo é só local, nunca sobe.\n")
        self.assertTrue(repos.never_push(path, ["main", "local-exp", "feature"], run)["all"])

    def test_remote_owner_parsing(self):
        cases = {
            "git@github.com:Marks-ZYZ/proj.git": ("github.com", "Marks-ZYZ"),
            "https://user:tok@github.com/acme/proj": ("github.com", "acme"),
            "ssh://git@gitlab.example:2222/group/sub/proj.git": ("gitlab.example", "sub"),
            "/srv/remotes/owner1/proj.git": ("local", "owner1"),
            "file:///srv/remotes/owner2/proj.git": ("local", "owner2"),
            "proj": ("", ""),
        }
        for url, want in cases.items():
            self.assertEqual(repos.parse_remote(url), want, url)


if __name__ == "__main__":
    unittest.main()
