"""Regression tests for the adversarial review of `migrate` (M8 of docs/SPEC-migrate.md).

Same sandbox as test_migrate: mkdtemp HOME and state dir, a temp folder as the "external disk" (st_dev and volume
faked by mock), local bare repos as remotes, a fake Trash. Program-running configs only ever `touch` a marker
under the temp root, and every URL that names a network host is used in dry runs or with a fake ssh.
"""

import os
import stat
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_common import fake_module, run_main  # noqa: E402
from test_migrate import DATE, MigrateCase  # noqa: E402
from test_repos import HAVE_GIT, age_tree  # noqa: E402

from corecleaner_lib import common, gitguard, inventory, migrate, repos, trash  # noqa: E402
from corecleaner_lib import migrate_copy as mc  # noqa: E402

POSIX = HAVE_GIT and os.name == "posix"


def last_phase(run_id, ident):
    return [r for r in trash._read_manifest(run_id) if r["id"] == ident][-1]["phase"]


@unittest.skipUnless(POSIX, "needs git and POSIX")
class NodeModules(MigrateCase):
    def test_node_modules_with_no_lockfile_is_copied_and_seen(self):
        path = self.repo("Documents/nm", {".gitignore": b"node_modules/\n", "README.md": b"x\n"})
        patched = os.path.join(path, "tools", "node_modules", "hand-patched", "only-copy.js")
        os.makedirs(os.path.dirname(patched))
        Path(patched).write_bytes(b"patched by hand\n")
        os.symlink(os.path.join(self.root, "localpkg"), os.path.join(path, "tools", "node_modules", "localpkg"))
        age_tree(path)
        self.assertIn("tools/node_modules/hand-patched/only-copy.js", mc.fingerprint(path))
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertEqual(it["copy_bytes"], it["bytes"])
        out = self.migrate(f, [it["id"]])
        self.assertEqual(out["items"][0]["status"], "ok", out)
        final = os.path.join(self.dest, "Documents", "nm")
        self.assertEqual(Path(final, "tools", "node_modules", "hand-patched", "only-copy.js").read_bytes(), b"patched by hand\n")
        self.assertTrue(os.path.islink(os.path.join(final, "tools", "node_modules", "localpkg")))

    def test_lockfile_node_modules_is_left_out_unless_a_link_leaves_the_repo(self):
        files = {".gitignore": b"node_modules/\n", "package.json": b"{}\n", "package-lock.json": b"{}\n",
                 "web/package.json": b"{}\n", "app/package.json": b"{}\n", "app/yarn.lock": b"\n"}
        path = self.repo("Documents/js", files)
        for rel in ("node_modules/pkg/i.js", "web/node_modules/w/i.js", "app/node_modules/a/i.js"):
            os.makedirs(os.path.dirname(os.path.join(path, rel)))
            Path(path, rel).write_bytes(b"m\n" * 500)
        os.symlink(os.path.join(self.root, "linked-lib"), os.path.join(path, "app", "node_modules", "linked"))
        age_tree(path)
        seen = mc.fingerprint(path)
        self.assertFalse(any(r.startswith(("node_modules", "web/node_modules")) for r in seen), sorted(seen))
        self.assertIn("app/node_modules/a/i.js", seen)  # a link out of the repo is not rebuilt by an install
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertLess(it["copy_bytes"], it["bytes"])
        view = migrate.plan_view(plan, Path(f))
        self.assertIn("node_modules", view["batches"][0][0]["question"])


@unittest.skipUnless(POSIX, "needs git and POSIX")
class LateEdit(MigrateCase):
    def test_edit_right_before_the_trash_keeps_the_original(self):
        path = self.project(with_remote=False)
        plan, f = self.make_plan()
        ident = self.item(plan, path)["id"]
        real_identity = trash._identity

        def edit_then(p):
            with open(os.path.join(path, "src", "app.py"), "a") as fh:
                fh.write("+EDIT\n")
            return real_identity(p)

        with mock.patch.object(trash, "_identity", edit_then):
            out = self.migrate(f, [ident])
        self.assertEqual(out["items"][0]["status"], "copied", out)
        self.assertEqual(self.trashed, [])
        self.assertIn("+EDIT", Path(path, "src", "app.py").read_text())
        self.assertEqual(mc.read_manifest(os.path.join(self.dest, "Documents", "proj"))["status"], "stale")
        self.assertEqual(last_phase(out["run_id"], ident), "fail")


@unittest.skipUnless(POSIX, "needs git and POSIX")
class DestinationPerItem(MigrateCase):
    def test_symlinked_folder_on_the_disk_is_refused_at_plan_and_at_apply(self):
        path = self.project(with_remote=False)
        elsewhere = os.path.join(self.home, "elsewhere")
        os.makedirs(elsewhere)
        plan, f = self.make_plan()
        os.makedirs(self.dest)
        os.symlink(elsewhere, os.path.join(self.dest, "Documents"))
        with self.assertRaises(common.CorecleanerError) as cm:
            self.migrate(f, [self.item(plan, path)["id"]])
        row = cm.exception.details["items"][0]
        self.assertEqual(row["status"], "deny", row)
        self.assertEqual((self.trashed, os.listdir(elsewhere)), ([], []))
        it = self.item(self.make_plan()[0], path)
        self.assertEqual(it["group"], 3)
        self.assertIn("link", it["deny"])

    def test_disk_gone_before_the_copy_writes_nothing(self):
        path = self.project(with_remote=False)
        plan, f = self.make_plan()
        real_publish = migrate.publish

        def detach(*a, **k):
            self.same_dev = True  # the mount point is now a plain folder on the internal disk
            return real_publish(*a, **k)

        with mock.patch.object(migrate, "publish", detach), self.assertRaises(common.CorecleanerError) as cm:
            self.migrate(f, [self.item(plan, path)["id"]])
        self.assertEqual(cm.exception.details["items"][0]["status"], "deny")
        self.assertFalse(os.path.exists(os.path.join(self.dest, "Documents")))
        self.assertEqual(self.trashed, [])

    def test_disk_gone_after_the_copy_keeps_the_original(self):
        path = self.project(with_remote=False)
        plan, f = self.make_plan()
        real_verify = mc.verify

        def detach(*a):
            res = real_verify(*a)
            self.same_dev = True
            return res

        with mock.patch.object(mc, "verify", detach), self.assertRaises(common.CorecleanerError) as cm:
            self.migrate(f, [self.item(plan, path)["id"]])
        self.assertEqual(cm.exception.details["items"][0]["status"], "copied")
        self.assertEqual(self.trashed, [])
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))


@unittest.skipUnless(POSIX, "needs git and POSIX")
class Resume(MigrateCase):
    def test_resume_after_a_stop_verifies_and_moves(self):
        path = self.project(with_remote=False)
        plan, f = self.make_plan()
        with mock.patch.object(migrate.platform_info, "trash_available", lambda p: (False, "none")):
            with self.assertRaises(common.CorecleanerError):
                self.migrate(f, [self.item(plan, path)["id"]])
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertTrue(it["resume"])
        out = self.migrate(f, [it["id"]])
        self.assertEqual(out["items"][0]["status"], "ok", out)
        self.assertEqual(self.trashed, [path])

    def test_leftover_partial_copy_is_reported(self):
        path = self.project(with_remote=False)
        os.makedirs(os.path.join(self.dest, "Documents", "proj.corecleaner-partial-20260101-000000-abcd"))
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertEqual(it["partials"], 1)
        self.assertIn("interrupted", migrate.plan_view(plan, Path(f))["batches"][0][0]["question"])


@unittest.skipUnless(POSIX, "needs git and POSIX")
class ProgramRunningConfig(MigrateCase):
    def marker(self, name):
        return os.path.join(self.root, name)

    def test_repo_ssh_command_is_never_run_by_the_push(self):
        path = self.repo("Documents/ssh")
        marker = self.marker("ssh-ran")
        script = os.path.join(self.root, "fake-ssh.sh")
        Path(script).write_text("#!/bin/sh\ntouch '%s'\nexit 1\n" % marker)
        os.chmod(script, 0o755)
        self.git(path, "config", "core.sshCommand", script)
        self.git(path, "remote", "add", "origin", "git@github.com:owner1/proj.git")
        env = {k: v for k, v in os.environ.items() if k not in ("GIT_SSH_COMMAND", "GIT_SSH")}
        with mock.patch.dict(os.environ, env, clear=True):
            pub = migrate.publish(path, frozenset({"owner1"}), DATE, apply=True)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(pub["pushed"], [])
        self.assertIn("config do repo roda programa no push", pub["where"])

    def test_push_config_kinds_are_flagged(self):
        path = self.repo("Documents/kinds")
        for key, value in (("credential.helper", "!touch x"), ("core.askPass", "x"), ("core.gitProxy", "x"),
                           ("protocol.ext.allow", "always"), ("remote.origin.receivepack", "x")):
            self.git(path, "config", key, value)
        run = lambda *a: inventory._git(self.ctx(), path, *a)  # noqa: E731
        self.assertEqual(gitguard.unsafe_config(run, path), [])  # reading the repo stays allowed
        self.assertTrue(gitguard.unsafe_config(run, path, push=True))

    def test_include_that_matches_only_on_the_disk_never_runs(self):
        path = self.repo("Documents/inc", {"a.txt": b"hello\n", ".gitattributes": b"*.txt filter=evil\n"})
        marker = self.marker("include-ran")
        Path(path, ".git", "evil.cfg").write_text("[filter \"evil\"]\n\tclean = sh -c 'touch %s; cat'\n" % marker)
        self.git(path, "config", "includeIf.gitdir:%s/.path" % self.dest, "evil.cfg")
        age_tree(path)
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertEqual(it["group"], 2, it["deny"])  # at home nothing matches
        out = self.migrate(f, [it["id"]])
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(out["items"][0]["status"], "failed", out)
        self.assertEqual(self.trashed, [])
        self.assertEqual(os.listdir(os.path.join(self.dest, "Documents")), [])

    def test_embedded_submodule_config_is_checked_before_status(self):
        path = self.repo("Documents/outer")
        sub = os.path.join(path, "sub")
        os.makedirs(sub)
        self.git(sub, "init", "-q")
        Path(sub, ".gitattributes").write_text("*.txt filter=evil\n")
        Path(sub, "f.txt").write_text("x\n")
        self.git(sub, "add", "-A")
        self.git(sub, "commit", "-q", "-m", "s")
        Path(path, ".gitmodules").write_text("[submodule \"sub\"]\n\tpath = sub\n\turl = ./sub\n")
        self.git(path, "add", ".gitmodules", "sub")
        self.git(path, "commit", "-q", "-m", "with sub")
        marker = self.marker("submodule-ran")
        self.git(sub, "config", "filter.evil.clean", "sh -c 'touch %s; cat'" % marker)
        age_tree(path)
        self.assertIn("repo config can run programs (filter driver)", repos.blockers(self.ctx(), path))
        repos.audit([self.home], 45, ctx=self.ctx())
        self.assertFalse(os.path.exists(marker))


@unittest.skipUnless(POSIX, "needs git and POSIX")
class RemoteHosts(MigrateCase):
    def test_owner_on_another_host_or_a_longer_path_is_not_allowed(self):
        path = self.repo("Documents/hosts")
        self.git(path, "remote", "add", "origin", "git@github.com:owner1/proj.git")
        pub = migrate.publish(path, frozenset({"owner1"}), DATE, apply=False)
        self.assertEqual([p["branch"] for p in pub["pushed"]], ["main"])
        for url in ("git@gitlab.com:owner1/p", "https://evil.example/owner1/p", "https://github.com@evil.example/owner1/p",
                    "http://127.0.0.1:9/owner1/proj.git", "https://github.com/owner1/p/extra", "/srv/owner1/proj.git"):
            self.git(path, "remote", "set-url", "origin", url)
            pub = migrate.publish(path, frozenset({"owner1"}), DATE, apply=False)
            self.assertEqual(pub["pushed"], [], url)
            self.assertIn("dono do remoto fora da lista", pub["where"], url)
        self.git(path, "remote", "set-url", "origin", "git@gitlab.com:owner1/p")
        pub = migrate.publish(path, migrate.parse_owners("gitlab.com/owner1"), DATE, apply=False)
        self.assertEqual([p["branch"] for p in pub["pushed"]], ["main"])


@unittest.skipUnless(POSIX, "needs git and POSIX")
class NeverPushNotes(MigrateCase):
    def setUp(self):
        super().setUp()
        self.path = self.repo("Documents/notes")
        self.git(self.path, "branch", "exp")

    def never(self):
        return migrate.pending_work(self.path)["never"]

    def test_note_committed_only_on_the_branch_tip(self):
        self.git(self.path, "checkout", "-q", "exp")
        Path(self.path, "docs", "dev").mkdir(parents=True)
        Path(self.path, "docs", "dev", "plan.md").write_text("never push exp: client data\n")
        self.git(self.path, "add", "-A")
        self.git(self.path, "commit", "-q", "-m", "note")
        self.git(self.path, "checkout", "-q", "main")
        self.assertFalse(os.path.exists(os.path.join(self.path, "docs")))
        self.assertIn("exp", self.never()["branches"])

    def test_wider_phrases_and_places(self):
        for rel, text in (("README.md", "This branch must never be pushed.\n"), ("README.md", "Do not publish.\n"),
                          ("README.md", "Nunca envie isto.\n"), ("README.md", "NUNCA dê push aqui.\n"),
                          ("NOTES", "never push\n"), ("notes/x.md", "never push\n"), (".claude/x.md", "never push\n"),
                          ("docs/dev/x.md", "never push\n")):
            full = os.path.join(self.path, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            Path(full).write_text(text)
            self.assertTrue(self.never()["all"], (rel, text))
            os.unlink(full)
        self.assertFalse(self.never()["all"])


@unittest.skipUnless(POSIX, "needs git and POSIX")
class Crashes(MigrateCase):
    def test_unwritable_folder_on_the_disk_is_a_failed_row_and_the_run_id_survives(self):
        a = self.repo("Projects/a")
        b = self.repo("Documents/deep/b")  # its parent folder must be created on the disk
        age_tree(a)
        age_tree(b)
        locked = os.path.join(self.dest, "Documents")
        os.makedirs(locked)
        os.chmod(locked, 0o555)
        self.addCleanup(os.chmod, locked, 0o755)
        plan, f = self.make_plan()
        out = self.migrate(f, [self.item(plan, a)["id"], self.item(plan, b)["id"]])
        self.assertTrue(out["run_id"])
        self.assertEqual([r["status"] for r in out["items"]], ["ok", "failed"], out)
        self.assertEqual(self.trashed, [a])

    def test_last_resort_error_is_scrubbed_for_scrubbed_commands(self):
        def boom(args):
            raise RuntimeError("/Users/someone/\x1b[31mevil\x07 name")

        code, out, _err = run_main(["migrate", "--plan", "p.json", "--ids", "c123456"], {"migrate": fake_module(boom)})
        self.assertEqual(code, common.EXIT_ERROR)
        self.assertNotIn("\x1b", out["error"]["message"] if isinstance(out.get("error"), dict) else str(out))


if __name__ == "__main__":
    unittest.main()
