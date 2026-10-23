"""M2-M6 of docs/SPEC-migrate.md: `migrate-plan` and `migrate`.

Everything lives under mkdtemp: a fake HOME, the state dir, the "external disk" (a temp folder whose st_dev and
volume are faked by mock), a local bare repo playing GitHub, and a fake Trash folder named `.Trash`.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_repos import HAVE_GIT, GitCase, age_tree  # noqa: E402

from corecleaner_lib import common, migrate, platform_info, repos, trash  # noqa: E402
from corecleaner_lib import migrate_copy as mc  # noqa: E402

MAC = sys.platform == "darwin"
DATE = time.strftime("%Y-%m-%d")


class MigrateCase(GitCase):
    def setUp(self):
        super().setUp()
        self.disk = os.path.join(self.root, "disk")
        os.makedirs(self.disk)
        self.dest = os.path.join(self.disk, "Repos-arquivados")
        self.fs, self.free, self.same_dev = "apfs", 1 << 42, False
        self.trashdir = os.path.join(self.root, ".Trash")
        os.makedirs(self.trashdir)
        self.trashed = []
        disk = self.disk

        def dev(p):
            return 1 if self.same_dev or not repos._inside(os.path.realpath(p), disk) else 2

        for target, attr, value in (
            (migrate, "_dev_of", dev),
            (migrate, "_free_bytes", lambda p: self.free),
            (platform_info, "_volume", lambda p: {"mount": disk, "fs": self.fs, "opts": {"local"}}),
            (platform_info, "trash_available", lambda p: (True, "fake")),
            (trash, "_user_trash_roots", lambda near: [self.trashdir]),  # undo accepts only the user's Trash folders
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def trasher(self, path):
        dest = os.path.join(self.trashdir, os.path.basename(path))
        os.rename(path, dest)
        self.trashed.append(path)
        return dest

    def bare(self, owner):
        path = os.path.join(self.root, "remotes", owner, "proj.git")
        os.makedirs(path)
        subprocess.run(["git", "init", "-q", "--bare", path], check=True, capture_output=True)
        return path

    def remote_refs(self, bare):
        out = subprocess.run(["git", "-C", bare, "for-each-ref", "--format=%(refname)"], check=True,
                             capture_output=True, text=True).stdout
        return set(out.split())

    def project(self, with_remote=True):
        files = {"src/app.py": b"print('hi')\n", "bin/run.sh": b"#!/bin/sh\necho run\n", ".gitignore": b"node_modules/\n",
                 "package.json": b"{}\n", "package-lock.json": b"{}\n", "src/package.json": b"{}\n",
                 "README.md": b"Branch `local-exp` is local-only: never push it.\n"}
        path = self.repo("Documents/proj", files)
        os.chmod(os.path.join(path, "bin", "run.sh"), 0o755)
        os.symlink("src/app.py", os.path.join(path, "link-in"))
        os.symlink("/etc/hosts", os.path.join(path, "link-out"))
        for nm in ("node_modules/pkg/index.js", "src/node_modules/x/y.js"):
            full = os.path.join(path, nm)
            os.makedirs(os.path.dirname(full))
            Path(full).write_bytes(b"module\n" * 1000)
        self.git(path, "add", "-A")
        self.git(path, "commit", "-q", "-m", "links", when=time.time() - 90 * 86400)
        if MAC:
            subprocess.run(["/usr/bin/xattr", "-w", "com.corecleaner.test", "hello", os.path.join(path, "src", "app.py")], check=True)
        elif hasattr(os, "setxattr"):
            try:
                os.setxattr(os.path.join(path, "src", "app.py"), "user.corecleaner", b"hello")
            except OSError:
                pass
        self.owner1 = None
        if with_remote:
            self.owner1 = self.bare("owner1")
            self.git(path, "remote", "add", "origin", self.owner1)
            self.git(path, "push", "-q", "origin", "main")
            self.git(path, "fetch", "-q", "origin")
            for b in ("feature", "sec/key", "local-exp"):
                self.git(path, "checkout", "-q", "-b", b, "main")
                Path(path, b.replace("/", "-") + ".txt").write_text(b)
                self.git(path, "add", "-A")
                self.git(path, "commit", "-q", "-m", b, when=time.time() - 90 * 86400)
            self.git(path, "checkout", "-q", "main")
        age_tree(path)
        return path

    def make_plan(self, dest=None):
        result = repos.audit([self.home], 45, ctx=self.ctx())
        plan = migrate.build_plan(result, dest or self.dest)
        return plan, str(migrate.write_plan(plan))

    def item(self, plan, path):
        return next(it for it in plan["items"] if it["path"] == path)

    def migrate(self, f, ids, apply=True, owners=None):
        args = types.SimpleNamespace(cmd="migrate", plan=f, ids=ids, apply=apply, push_owners=owners)
        return migrate.run(args, trasher=self.trasher)


@unittest.skipUnless(HAVE_GIT and os.name == "posix", "needs git and POSIX")
class Destination(MigrateCase):
    def refused(self, code=common.EXIT_BAD_DESTINATION, dest=None):
        with self.assertRaises(common.CorecleanerError) as cm:
            migrate.check_destination(dest or self.dest)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception.message

    def test_good_destination_passes(self):
        info = migrate.check_destination(self.dest)
        self.assertEqual((info["fs"], info["path"]), ("APFS", self.dest))

    def test_fat32_is_refused(self):
        self.fs = "msdos"
        self.assertIn("FAT32", self.refused())

    def test_exfat_is_refused(self):
        self.fs = "exfat"
        self.assertIn("exFAT", self.refused())

    def test_unknown_filesystem_is_refused(self):
        self.fs = "fuseblk"
        self.assertIn("not one of", self.refused())

    def test_same_device_as_home_is_refused(self):
        self.same_dev = True
        self.assertIn("same device", self.refused())

    def test_inside_home_is_refused(self):
        self.assertIn("inside HOME", self.refused(dest=os.path.join(self.home, "Backup")))

    def test_too_little_space_refuses_the_plan(self):
        self.project()
        self.free = 10 << 20
        with self.assertRaises(common.CorecleanerError) as cm:
            self.make_plan()
        self.assertEqual(cm.exception.code, common.EXIT_NO_SPACE_FOR_ARCHIVE)

    def test_case_collision_puts_the_repo_in_group_3(self):
        path = self.project()
        os.makedirs(os.path.join(self.dest, "DOCUMENTS"))
        it = self.item(self.make_plan()[0], path)
        self.assertEqual(it["group"], 3)
        self.assertIn("case collision", it["deny"])

    def test_taken_folder_is_refused_unless_it_is_a_verified_copy_of_this_repo(self):
        path = self.project()
        final = os.path.join(self.dest, "Documents", "proj")
        os.makedirs(final)
        self.assertIn("already exists", self.item(self.make_plan()[0], path)["deny"])
        mc.write_manifest(final, {"origin": path, "status": "verified"})
        it = self.item(self.make_plan()[0], path)
        self.assertEqual((it["group"], it["resume"]), (2, True))

    def test_edited_plan_is_rejected(self):
        self.project()
        _plan, f = self.make_plan()
        data = json.loads(Path(f).read_text())
        data["dest"] = "/"
        Path(f).write_text(json.dumps(data))
        with self.assertRaises(common.CorecleanerError) as cm:
            migrate.load_plan(f)
        self.assertEqual(cm.exception.code, common.EXIT_PLAN_TAMPERED)

    def test_view_batches_offered_repos_by_four_names_sanitized(self):
        path = self.project()
        plan, f = self.make_plan()
        view = migrate.plan_view(plan, Path(f))
        self.assertEqual(view["offered"], 1)
        q = view["batches"][0][0]
        self.assertEqual(q["id"], self.item(plan, path)["id"])
        self.assertIn("Move proj", q["question"])
        self.assertEqual([o["ids"] for o in q["options"]], [[], [q["id"]]])  # keep first, as everywhere
        self.assertIn("proj, in ~/Documents", q["question"])
        self.assertNotIn(self.home, json.dumps(view).replace(f, ""))


@unittest.skipUnless(HAVE_GIT and os.name == "posix", "needs git and POSIX")
class Publication(MigrateCase):
    def test_only_allowed_branches_go_to_an_allowed_owner_and_are_checked(self):
        path = self.project()
        pub = migrate.publish(path, frozenset({"local/owner1"}), DATE, apply=True)
        refs = self.remote_refs(self.owner1)
        self.assertIn("refs/tags/arquivo-%s/feature" % DATE, refs)
        self.assertFalse(any("sec/" in r or "local-exp" in r for r in refs if r.startswith("refs/tags/")), refs)
        self.assertEqual([(p["branch"], p["verified"]) for p in pub["pushed"]], [("feature", True)])
        self.assertIn("branch sec/key: sec/* nunca sobe", pub["where"])
        self.assertIn("branch local-exp: nota diz que não sobe", pub["where"])

    def test_branch_carrying_commits_of_a_held_branch_is_not_pushed(self):
        path = self.project()
        self.git(path, "checkout", "-q", "-b", "mixed", "sec/key")
        Path(path, "more.txt").write_text("more")
        self.git(path, "add", "-A")
        self.git(path, "commit", "-q", "-m", "on top of sec")
        self.git(path, "checkout", "-q", "main")
        pub = migrate.publish(path, frozenset({"local/owner1"}), DATE, apply=True)
        self.assertEqual([p["branch"] for p in pub["pushed"]], ["feature"])
        self.assertIn("branch mixed: leva commits de uma branch que não sobe", pub["where"])
        self.assertNotIn("refs/tags/arquivo-%s/mixed" % DATE, self.remote_refs(self.owner1))

    def test_owner_not_in_the_list_or_no_list_pushes_nothing(self):
        path = self.project()
        for owners, why in ((frozenset(), "branch feature: sem lista --push-owners"),
                            (frozenset({"someone-else"}), "branch feature: dono do remoto fora da lista")):
            pub = migrate.publish(path, owners, DATE, apply=True)
            self.assertEqual(pub["pushed"], [])
            self.assertTrue(pub["where"].startswith(migrate.WHERE_PENDING))
            self.assertIn(why, pub["where"])
        self.assertFalse(any(r.startswith("refs/tags/") for r in self.remote_refs(self.owner1)))

    def test_push_url_to_another_owner_blocks_the_remote(self):
        path = self.project()
        evil = self.bare("evil")
        self.git(path, "remote", "set-url", "--add", "--push", "origin", self.owner1)
        self.git(path, "remote", "set-url", "--add", "--push", "origin", evil)  # one allowed URL is not enough
        pub = migrate.publish(path, frozenset({"local/owner1"}), DATE, apply=True)
        self.assertEqual(pub["pushed"], [])
        self.assertIn("dono do remoto fora da lista", pub["where"])
        self.assertFalse(any(r.startswith("refs/tags/") for r in self.remote_refs(evil) | self.remote_refs(self.owner1)))

    def test_sec_branch_is_never_pushed_even_when_it_is_the_only_one(self):
        path = self.repo("Documents/solo")
        remote = self.bare("owner1-solo")
        self.git(path, "remote", "add", "origin", remote)
        self.git(path, "push", "-q", "origin", "main")
        self.git(path, "checkout", "-q", "-b", "sec/token")
        Path(path, "t.txt").write_text("secret")
        self.git(path, "add", "-A")
        self.git(path, "commit", "-q", "-m", "s")
        pub = migrate.publish(path, frozenset({"local/owner1-solo"}), DATE, apply=True)
        self.assertEqual(pub["pushed"], [])
        self.assertFalse(any(r.startswith("refs/tags/") for r in self.remote_refs(remote)))

    def test_where_else_values(self):
        lonely = self.repo("Documents/lonely")
        self.assertEqual(migrate.publish(lonely, frozenset({"x"}), DATE, apply=False)["where"], migrate.WHERE_NO_REMOTE)
        path = self.project()
        for b in ("sec/key", "local-exp", "feature"):
            self.git(path, "branch", "-D", b)
        Path(path, "README.md").write_text("no note\n")
        self.git(path, "commit", "-q", "-am", "drop the note")
        self.git(path, "checkout", "-q", "-b", "feature")  # born after the note: a tip that still carried it would hold every branch
        Path(path, "feature.txt").write_text("feature")
        self.git(path, "add", "-A")
        self.git(path, "commit", "-q", "-m", "feature")
        self.git(path, "checkout", "-q", "main")
        self.assertEqual(migrate.publish(path, frozenset({"local/owner1"}), DATE, apply=True)["where"], migrate.WHERE_PUSHED)
        self.git(path, "push", "-q", "origin", "main", "feature")
        self.assertEqual(migrate.publish(path, frozenset({"local/owner1"}), DATE, apply=False)["where"], "limpo no remoto")


@unittest.skipUnless(HAVE_GIT and os.name == "posix", "needs git and POSIX")
class CopyVerifyTrash(MigrateCase):
    def test_full_run_copies_verifies_indexes_trashes_and_undo_restores(self):
        path = self.project()
        plan, f = self.make_plan()
        ident = self.item(plan, path)["id"]
        dry = self.migrate(f, [ident], apply=False, owners="local/owner1")
        self.assertEqual(dry["items"][0]["status"], "ok", dry)
        self.assertFalse(os.path.exists(self.dest))  # dry-run writes nothing
        self.assertFalse(any(r.startswith("refs/tags/") for r in self.remote_refs(self.owner1)))
        out = self.migrate(f, [ident], owners="local/owner1")
        row = out["items"][0]
        self.assertEqual(row["status"], "ok", out)
        self.assertEqual(self.trashed, [path])
        final = os.path.join(self.dest, "Documents", "proj")
        self.assertFalse(os.path.exists(os.path.join(final, "node_modules")))
        self.assertFalse(os.path.exists(os.path.join(final, "src", "node_modules")))
        self.assertEqual(os.readlink(os.path.join(final, "link-in")), "src/app.py")
        self.assertEqual(os.readlink(os.path.join(final, "link-out")), "/etc/hosts")
        self.assertTrue(os.stat(os.path.join(final, "bin", "run.sh")).st_mode & stat.S_IXUSR)
        if MAC:
            got = subprocess.run(["/usr/bin/xattr", "-p", "com.corecleaner.test", os.path.join(final, "src", "app.py")],
                                 capture_output=True, text=True).stdout.strip()
            self.assertEqual(got, "hello")
        man = mc.read_manifest(final)
        self.assertEqual((man["status"], man["origin"]), ("verified", path))
        self.assertEqual(len(man["merkle_sha256"]), 64)
        self.assertEqual([t["branch"] for t in man["tags"]], ["feature"])
        index = Path(self.dest, "INDEX.md").read_text()
        self.assertTrue(index.startswith(mc.INDEX_TITLE + "\n"))
        self.assertIn(mc.INDEX_HEADER, index)
        self.assertIn("| Documents/proj | ", index)
        self.assertIn("| ~/Documents/proj | pendência não enviada: branch local-exp: nota diz que não sobe; "
                      "branch sec/key: sec/* nunca sobe | %s |" % DATE, index)
        self.assertIn("| Documents/proj/.corecleaner-migrated.json |", index)
        cloned = os.path.join(self.root, "from-copy")
        subprocess.run(["git", "clone", "-q", final, cloned], check=True, capture_output=True)
        self.assertEqual(Path(cloned, "src", "app.py").read_text(), "print('hi')\n")
        undone = trash.undo(out["run_id"])
        self.assertEqual([r["src"] for r in undone["restored"]], [path])
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertTrue(os.path.isdir(final))  # the copy stays

    def test_corrupted_copy_is_deleted_and_nothing_moves(self):
        path = self.project()
        plan, f = self.make_plan()
        real_copy = mc.copy_tree

        def corrupting(src, dst):
            res = real_copy(src, dst)
            target = os.path.join(dst, "src", "app.py")
            os.chmod(target, 0o644)
            data = bytearray(Path(target).read_bytes())
            data[0] ^= 0xFF
            Path(target).write_bytes(bytes(data))  # same size, other bytes
            return res

        with mock.patch.object(mc, "copy_tree", corrupting):
            out = self.migrate(f, [self.item(plan, path)["id"]], owners="local/owner1")
        row = out["items"][0]
        self.assertEqual(row["status"], "failed", out)
        self.assertIn("sha256 differs", row["reason"])
        self.assertEqual(self.trashed, [])
        self.assertTrue(os.path.isdir(path))
        parent = os.path.join(self.dest, "Documents")
        self.assertEqual(os.listdir(parent), [])  # staging deleted, no final folder
        self.assertFalse(os.path.exists(os.path.join(self.dest, "INDEX.md")))

    def test_original_changed_after_verification_is_not_moved_and_copy_is_stale(self):
        path = self.project()
        plan, f = self.make_plan()
        real_verify = mc.verify

        def then_edit(src, dst):
            res = real_verify(src, dst)
            Path(src, "src", "late.py").write_text("written after the copy\n")
            return res

        with mock.patch.object(mc, "verify", then_edit):
            out = self.migrate(f, [self.item(plan, path)["id"]], owners="local/owner1")
        row = out["items"][0]
        self.assertEqual(row["status"], "copied", out)
        self.assertEqual(self.trashed, [])
        self.assertTrue(os.path.exists(os.path.join(path, "src", "late.py")))
        self.assertEqual(mc.read_manifest(os.path.join(self.dest, "Documents", "proj"))["status"], "stale")
        self.assertIn("cópia desatualizada", Path(self.dest, "INDEX.md").read_text())

    def test_change_since_the_plan_is_denied_before_anything_is_written(self):
        path = self.project()
        plan, f = self.make_plan()
        Path(path, "src", "new.py").write_text("x")
        os.utime(os.path.join(path, "src", "new.py"), (time.time() - 7200, time.time() - 7200))
        out = self.migrate(f, [self.item(plan, path)["id"]], owners="local/owner1")
        self.assertEqual((out["items"][0]["status"], out["items"][0]["code"]), ("deny", common.EXIT_STATE_CHANGED))
        self.assertFalse(os.path.exists(self.dest))

    def test_resume_reverifies_an_existing_copy_and_never_deletes_it(self):
        path = self.project(with_remote=False)
        plan, f = self.make_plan()
        ident = self.item(plan, path)["id"]
        with mock.patch.object(platform_info, "trash_available", lambda p: (False, "none")):
            with self.assertRaises(common.CorecleanerError):
                self.migrate(f, [ident])  # copied and verified, the Trash is missing: batch stops, original kept
        final = os.path.join(self.dest, "Documents", "proj")
        self.assertEqual(mc.read_manifest(final)["status"], "verified")
        plan, f = self.make_plan()
        it = self.item(plan, path)
        self.assertTrue(it["resume"])
        Path(final, "src", "app.py").write_bytes(b"tampered on the disk\n")
        out = self.migrate(f, [it["id"]])
        self.assertEqual(out["items"][0]["status"], "failed")
        self.assertIn("left as is", out["items"][0]["reason"])
        self.assertTrue(os.path.isdir(final))
        self.assertEqual(self.trashed, [])


class IndexMerge(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.dir = tempfile.mkdtemp(prefix="corecleaner-index-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_row_replaced_rest_intact_new_rows_appended_atomically(self):
        old = ("# Repos arquivados (CoreCleaner)\n\nNotas do dono, a mão.\n\n" + mc.INDEX_HEADER + "\n" + mc.INDEX_RULE + "\n"
               "| a/x | 10 | ~/a/x | limpo no GitHub | 2026-09-24 | a/x/.corecleaner-migrated.json |\n"
               "| b/y | 20 | ~/b/y | só no HD (sem remoto) | 2026-09-24 | - |\n\nRodapé.\n")
        Path(self.dir, "INDEX.md").write_text(old)
        mc.merge_index(self.dir, "a/x", mc.index_row("a/x", 5_000_000, "~/a/x", "enviado e conferido", "2026-10-21", "m"))
        mc.merge_index(self.dir, "c|z", mc.index_row("c|z", 0, "~/c|z", "limpo no GitHub", "2026-10-21", "m"))
        new = Path(self.dir, "INDEX.md").read_text()
        self.assertIn("| a/x | 5 | ~/a/x | enviado e conferido | 2026-10-21 | m |", new)
        self.assertNotIn("| a/x | 10 |", new)
        self.assertIn("| b/y | 20 | ~/b/y | só no HD (sem remoto) | 2026-09-24 | - |", new)
        self.assertTrue(new.startswith("# Repos arquivados (CoreCleaner)\n\nNotas do dono, a mão.\n"))
        self.assertTrue(new.endswith("\n\nRodapé.\n"))
        lines = new.splitlines()
        self.assertEqual(lines.index("| b/y | 20 | ~/b/y | só no HD (sem remoto) | 2026-09-24 | - |") + 1,
                         lines.index("| c\\|z | 0 | ~/c\\|z | limpo no GitHub | 2026-10-21 | m |"))
        mc.merge_index(self.dir, "c|z", mc.index_row("c|z", 2_000_000, "~/c|z", "x", "d", "m"))
        self.assertEqual(Path(self.dir, "INDEX.md").read_text().count("c\\|z"), 2)  # one row, two cells
        self.assertEqual([n for n in os.listdir(self.dir) if n != "INDEX.md"], [])  # no temp left behind

    def test_new_file_has_title_and_header(self):
        mc.merge_index(self.dir, "a", mc.index_row("a", 1, "~/a", "w", "d", "m"))
        self.assertEqual(Path(self.dir, "INDEX.md").read_text().splitlines()[:4],
                         [mc.INDEX_TITLE, "", mc.INDEX_HEADER, mc.INDEX_RULE])


if __name__ == "__main__":
    unittest.main()
