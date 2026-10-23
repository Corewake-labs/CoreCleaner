"""Archive store cap and the listing of old archives (BACKLOG: "~/corecleaner-archive sem cota nem expiracao").

Every repo, archive folder and Trash here lives under a temp dir the test creates; HOME and the git
config are redirected into it (GitCase, Base).
"""

import contextlib
import json
import os
import shutil
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import archive, common, trash  # noqa: E402
from tests.test_archive import GitCase  # noqa: E402
from tests.test_trash import LONG_AGO, Base, plan_item  # noqa: E402

DAY = 86400
HAVE_GIT = shutil.which("git") is not None


def make_archive(root, day, name, size=10, age_days=0):
    """<root>/<day>/<name>/MANIFEST.txt of `size` bytes, folder mtime `age_days` ago."""
    folder = Path(root) / day / name
    folder.mkdir(parents=True)
    (folder / "MANIFEST.txt").write_bytes(b"m" * size)
    stamp = time.time() - age_days * DAY
    os.utime(str(folder), (stamp, stamp))
    return folder


@unittest.skipUnless(HAVE_GIT, "needs git")
class CheckQuota(GitCase):
    def store(self, size):
        store = self.base / "store"
        (store / "20260101" / "old").mkdir(parents=True)
        (store / "20260101" / "old" / "bundle.git").write_bytes(b"x" * size)
        return store

    def test_an_archive_that_would_pass_the_cap_is_refused_with_44(self):
        repo = self.dirty_repo()
        store = self.store(3 * archive.MIB)
        with mock.patch.object(archive, "ARCHIVE_CAP_BYTES", 3 * archive.MIB + 1000):
            with self.assertRaises(common.CorecleanerError) as ctx:
                archive.check_quota(store, [str(repo)])
        exc = ctx.exception
        self.assertEqual(exc.code, common.EXIT_NO_SPACE_FOR_ARCHIVE)
        self.assertTrue(exc.details["quota"])
        self.assertEqual(exc.details["used_bytes"], 3 * archive.MIB)
        self.assertEqual(exc.details["cap_bytes"], 3 * archive.MIB + 1000)
        self.assertIn("cap", exc.message)
        self.assertEqual([p.name for p in store.iterdir()], ["20260101"])  # nothing was created

    def test_an_archive_that_fits_passes(self):
        repo = self.dirty_repo()
        store = self.store(1000)
        archive.check_quota(store, [str(repo)])  # the default cap is 20 GiB
        archive.check_quota(self.base / "no-such-store", [str(repo)])  # a store that does not exist yet is empty

    def test_the_estimate_of_every_repo_of_an_item_counts(self):
        one, two = self.dirty_repo(), self.pushed_repo("pushed")
        store = self.store(0)
        each = archive.estimate_archive_bytes(str(one))
        with mock.patch.object(archive, "ARCHIVE_CAP_BYTES", each + archive.MIB // 2):
            archive.check_quota(store, [str(one)])
            with self.assertRaises(common.CorecleanerError):
                archive.check_quota(store, [str(one), str(two)])

    def test_an_unreadable_repo_counts_as_the_minimum_and_is_left_to_archive_repo(self):
        broken = self.base / "broken"
        (broken / ".git").mkdir(parents=True)
        store = self.store(0)
        archive.check_quota(store, [str(broken)])  # does not raise: archive_repo will refuse it with its own reason
        with mock.patch.object(archive, "ARCHIVE_CAP_BYTES", archive.MIN_ESTIMATE - 1):
            with self.assertRaises(common.CorecleanerError):
                archive.check_quota(store, [str(broken)])

    def test_the_cap_can_be_set_in_gib_and_a_bad_value_keeps_the_default(self):
        self.assertEqual(archive.archive_cap_bytes(), 20 * archive.GIB)
        for raw, want in (("5", 5 * archive.GIB), ("0.5", archive.GIB // 2), ("0", 20 * archive.GIB),
                          ("-3", 20 * archive.GIB), ("many", 20 * archive.GIB), ("", 20 * archive.GIB)):
            with mock.patch.dict(os.environ, {archive.ARCHIVE_CAP_ENV: raw}):
                self.assertEqual(archive.archive_cap_bytes(), want, raw)


class StoreReport(unittest.TestCase):
    def setUp(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory(prefix="corecleaner-quota-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))

    def test_only_archives_90_days_or_older_are_listed_oldest_first(self):
        oldest = make_archive(self.root, "20250101", "a-1", size=300, age_days=400)
        old = make_archive(self.root, "20260601", "b-1", size=200, age_days=90)
        make_archive(self.root, "20260602", "c-1", size=100, age_days=89)
        make_archive(self.root, "20260603", "d-1", size=50, age_days=0)
        report = archive.store_report(self.root)
        self.assertEqual([r["path"] for r in report["old"]], [str(oldest), str(old)])
        self.assertEqual([r["age_days"] for r in report["old"]], [400, 90])
        self.assertEqual([r["bytes"] for r in report["old"]], [300, 200])
        self.assertEqual((report["archives"], report["old_count"], report["old_bytes"]), (4, 2, 500))
        self.assertEqual(report["bytes"], 650)
        self.assertEqual((report["cap_bytes"], report["older_than_days"]), (archive.ARCHIVE_CAP_BYTES, 90))

    def test_listing_never_removes_anything(self):
        folder = make_archive(self.root, "20250101", "a-1", size=300, age_days=400)
        archive.store_report(self.root)
        self.assertTrue((folder / "MANIFEST.txt").is_file())

    def test_a_long_list_is_cut_but_counted(self):
        for n in range(archive.STALE_LISTED + 5):
            make_archive(self.root, "20250101", "a-%03d" % n, size=1, age_days=200 + n)
        report = archive.store_report(self.root)
        self.assertEqual(len(report["old"]), archive.STALE_LISTED)
        self.assertEqual(report["old_count"], archive.STALE_LISTED + 5)
        self.assertEqual(report["old"][0]["age_days"], 200 + archive.STALE_LISTED + 4)

    def test_a_symlink_inside_the_store_is_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "big.bin").write_bytes(b"x" * 5000)
        store = self.root / "store"
        store.mkdir()
        os.symlink(str(outside), str(store / "20250101"))
        report = archive.store_report(store)
        self.assertEqual(report["archives"], 0)
        self.assertLess(report["bytes"], 5000)  # the link itself, not the 5000 bytes behind it

    def test_a_missing_store_is_empty(self):
        report = archive.store_report(self.root / "nothing")
        self.assertEqual((report["bytes"], report["archives"], report["old"]), (0, 0, []))


class TrashEnforcesTheCap(Base):
    """The cap through trash: the item is skipped with code 44 before anything is created."""

    def setUp(self):
        super().setUp()
        self.store = Path(self.root) / "archive"  # Base points trash._archive_root here

    def go(self, items, ids, apply=True):
        plan = {"version": 1, "created": common.now_iso(), "items": items, "sha256": "x"}
        args = types.SimpleNamespace(cmd="trash", plan="plan.json", ids=ids, apply=apply)
        with mock.patch.object(trash.plan_mod, "load_plan", return_value=plan):
            return trash.run(args, trasher=self.fake)

    def repo_item(self, name="repo"):
        path = self.mkdir(name)
        os.mkdir(os.path.join(path, ".git"))
        os.utime(os.path.join(path, ".git"), (LONG_AGO, LONG_AGO))
        os.utime(path, (LONG_AGO, LONG_AGO))
        return plan_item(path, "c001", action="archive_then_trash")

    @contextlib.contextmanager
    def dirty(self):
        with mock.patch.object(archive, "needs_archive", return_value=(True, "dirty")), mock.patch.object(
            archive, "archive_repo", return_value={"dest": "x", "verified": True}
        ) as archived:
            yield archived

    def test_apply_skips_the_item_and_creates_nothing_when_the_cap_would_be_passed(self):
        make_archive(self.store, "20260101", "old", size=archive.MIB, age_days=1)
        item = self.repo_item()
        other = plan_item(self.mkfile("other.txt"), "c002")
        with self.dirty() as archived, mock.patch.object(archive, "ARCHIVE_CAP_BYTES", archive.MIB + 1000):
            res = self.go([item, other], ["c001", "c002"])
        self.assertEqual([r["status"] for r in res["items"]], ["skipped", "ok"])
        first = res["items"][0]
        self.assertEqual(first["code"], common.EXIT_NO_SPACE_FOR_ARCHIVE)
        self.assertIn("cap", first["reason"])
        self.assertIn("not trashed", first["reason"])
        archived.assert_not_called()
        self.assertTrue(os.path.lexists(item["path"]))
        self.assertEqual(self.fake.calls, [other["path"]])
        self.assertEqual(sorted(p.name for p in self.store.iterdir()), ["20260101"])  # no new day or archive folder
        rows = [r for r in self.manifest(res["run_id"]) if r["id"] == "c001"]
        self.assertEqual([r["phase"] for r in rows], ["fail"])

    def test_apply_archives_when_the_store_has_room(self):
        make_archive(self.store, "20260101", "old", size=archive.MIB, age_days=1)
        item = self.repo_item()
        with self.dirty() as archived:
            res = self.go([item], ["c001"])
        self.assertEqual(res["items"][0]["status"], "ok")
        archived.assert_called_once()

    def test_the_dry_run_tells_the_same_story(self):
        make_archive(self.store, "20260101", "old", size=archive.MIB, age_days=1)
        item = self.repo_item()
        with self.dirty() as archived, mock.patch.object(archive, "ARCHIVE_CAP_BYTES", archive.MIB + 1000):
            res = self.go([item], ["c001"], apply=False)
        row = res["items"][0]
        self.assertEqual((row["status"], row["code"]), ("skipped", common.EXIT_NO_SPACE_FOR_ARCHIVE))
        self.assertIn("would not be moved", row["reason"])
        self.assertIn("cap", row["reason"])
        archived.assert_not_called()
        self.assertEqual(res["would_trash_bytes"], 0)

    def test_a_plain_item_needs_no_archive_so_the_cap_does_not_touch_it(self):
        make_archive(self.store, "20260101", "old", size=archive.MIB, age_days=1)
        plain = plan_item(self.mkfile("plain.txt"), "c001")
        with mock.patch.object(archive, "ARCHIVE_CAP_BYTES", 10):
            res = self.go([plain], ["c001"])
        self.assertEqual(res["items"][0]["status"], "ok")


class TrashListsOldArchives(Base):
    def setUp(self):
        super().setUp()
        self.store = Path(self.root) / "archive"

    def run_plain(self):
        item = plan_item(self.mkfile("plain.txt"), "c001")
        plan = {"version": 1, "created": common.now_iso(), "items": [item], "sha256": "x"}
        args = types.SimpleNamespace(cmd="trash", plan="plan.json", ids=["c001"], apply=True)
        with mock.patch.object(trash.plan_mod, "load_plan", return_value=plan):
            return trash.run(args, trasher=self.fake)

    def test_the_result_lists_old_archives_with_a_command_for_the_user_and_removes_none(self):
        old = make_archive(self.store, "20250101", "c009", size=40, age_days=200)
        fresh = make_archive(self.store, "20261020", "c010", size=60, age_days=2)
        res = self.run_plain()
        store = res["archive_store"]
        self.assertEqual(store["root"], str(self.store))
        self.assertEqual([r["path"] for r in store["old"]], [str(old)])
        self.assertEqual((store["old_count"], store["bytes"], store["cap_bytes"]), (1, 100, archive.ARCHIVE_CAP_BYTES))
        cmd = store["prune_command"]
        self.assertTrue(cmd.startswith("find -H "), cmd)
        self.assertIn(str(self.store), cmd)
        self.assertIn("-mindepth 2 -maxdepth 2 -type d -mtime +89", cmd)
        self.assertIn("/usr/bin/trash -s -v {} +", cmd)
        self.assertLess(len(cmd), 300)  # the agent view cuts longer strings
        self.assertIn("never deletes", store["note"])
        self.assertTrue(old.is_dir() and fresh.is_dir())

    def test_no_old_archive_means_no_command(self):
        make_archive(self.store, "20261020", "c010", size=60, age_days=2)
        store = self.run_plain()["archive_store"]
        self.assertEqual((store["old"], store["old_count"], store["prune_command"]), ([], 0, None))

    def test_no_archive_folder_means_no_key(self):
        self.assertNotIn("archive_store", self.run_plain())

    def test_the_listing_is_in_the_dry_run_result_too(self):
        make_archive(self.store, "20250101", "c009", size=40, age_days=200)
        item = plan_item(self.mkfile("plain.txt"), "c001")
        plan = {"version": 1, "created": common.now_iso(), "items": [item], "sha256": "x"}
        args = types.SimpleNamespace(cmd="trash", plan="plan.json", ids=["c001"], apply=False)
        with mock.patch.object(trash.plan_mod, "load_plan", return_value=plan):
            res = trash.run(args, trasher=self.fake)
        self.assertEqual(res["archive_store"]["old_count"], 1)

    def test_a_path_with_a_quote_is_quoted_in_the_command(self):
        weird = Path(self.root) / "it's archive"
        make_archive(weird, "20250101", "c009", size=40, age_days=200)
        with mock.patch.object(trash, "_archive_root", return_value=weird):
            cmd = trash._archive_store_note()["prune_command"]
        self.assertIn("'\"'\"'", cmd)  # shlex.quote of the apostrophe


class PruneCommandPerOs(Base):
    def test_linux_uses_gio_and_windows_prints_none(self):
        root = Path(self.root) / "archive"
        with mock.patch.object(trash.platform_info, "os_kind", return_value="linux"):
            self.assertIn("-exec gio trash -- {} +", trash._prune_command(root))
        with mock.patch.object(trash.platform_info, "os_kind", return_value="windows"):
            self.assertIsNone(trash._prune_command(root))


class ResultSurvivesTheAgentView(Base):
    def test_scrub_keeps_the_command_whole(self):
        from corecleaner_lib import views

        store = Path(self.root) / "archive"
        make_archive(store, "20250101", "c009", size=40, age_days=200)
        note = trash._archive_store_note()
        scrubbed = views.scrub(json.loads(json.dumps(note)))
        self.assertEqual(scrubbed["prune_command"], note["prune_command"])


if __name__ == "__main__":
    unittest.main()
