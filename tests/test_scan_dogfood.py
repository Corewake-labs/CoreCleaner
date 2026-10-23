"""scan dogfood: defects measured by running `scan` on the real Mac (2026-10-21), one test each.

D1  read_bytes was 8.3 GB of 477 GB: a dua call over ONE directory prints its children plus
    `total` (not one row per input), dua marks names with "<N IO Error>", and exit 1 means
    "some entries unreadable" while the sizes are still printed.
D2  a slow dua call is a slow disk, not a broken dua; at most two passes per root; --timeout.
D3  the Trash cannot be listed without Full Disk Access: say so, or ask Finder.
D5  swap (and snapshots) are reported in `system_holds` and subtracted in gap.explained_by.

Everything runs inside tempfile.mkdtemp(); the fake dua is the one from test_scan (real 2.46.0 shape).
"""

import argparse
import errno
import json
import os
import sys
import types
import unittest
from unittest import mock

from tests.test_scan import FAKE_DUA, POSIX, Base, scan, write

# Literal output of `dua aggregate -f bytes -x --deduplicate-apfs-clones -- ~/Pictures` on the Mac.
REAL_PICTURES = (
    "         0 b .localized\n"
    "         0 b Photos Library.photoslibrary  <1 IO Error>\n"
    "      4096 b Fototeca do Photo Booth\n"
    "      8192 b .DS_Store\n"
    "  18518016 b LightCraft Library\n"
    "  18530304 b total  <1 IO Error>\n"
)
REAL_TWO_PATHS = (
    "         0 b /Users/u/.Trash  <1 IO Error>\n"
    "  18530304 b /Users/u/Pictures  <1 IO Error>\n"
    "  18530304 b total  <2 IO Errors>\n"
)
REAL_SWAPUSAGE = "total = 12288.00M  used = 10773.25M  free = 1514.75M  (encrypted)\n"
REAL_PROC_SWAPS = (
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    "/swap file                              file\t\t2097148\t\t512\t\t-2\n"
    "/dev/zram0                              partition\t8388604\t\t12\t\t100\n"
)
MIB = 1 << 20


class RealDuaShape(unittest.TestCase):
    def test_io_error_suffix_is_cut_from_names_and_counted(self):
        rows = scan.parse_dua_rows(REAL_PICTURES)
        self.assertEqual(rows[1], (0, "Photos Library.photoslibrary", 1))
        self.assertEqual(rows[-1], (18530304, "total", 1))
        self.assertEqual(scan.parse_dua_output(REAL_TWO_PATHS)[0], (0, "/Users/u/.Trash"))
        self.assertEqual(scan.parse_dua_rows(REAL_TWO_PATHS)[-1], (18530304, "total", 2))

    def test_one_directory_input_is_total_plus_children(self):
        total, kids = scan.split_listing(scan.parse_dua_output(REAL_PICTURES))
        self.assertEqual(total, 18530304)
        self.assertEqual(kids["LightCraft Library"], 18518016)
        self.assertIn("Photos Library.photoslibrary", kids)
        self.assertNotIn("total", kids)

    def test_single_child_has_no_total_line_and_empty_folder_prints_nothing(self):
        self.assertEqual(scan.split_listing([(8332271616, "homebrew")]), (8332271616, {"homebrew": 8332271616}))
        self.assertEqual(scan.split_listing([]), (0, {}))

    def test_a_child_named_total_does_not_hide_the_real_total(self):
        rows = [(30, "total"), (50, "zz"), (80, "total")]
        self.assertEqual(scan.split_listing(rows), (80, {"total": 30, "zz": 50}))


@unittest.skipUnless(POSIX, "fake dua is a POSIX executable")
class DuaOnTheRealShape(Base):
    def setUp(self):
        super().setUp()
        self.fake = self.path("bin", "dua")
        os.makedirs(os.path.dirname(self.fake))
        with open(self.fake, "w") as fh:
            fh.write(FAKE_DUA % {"python": sys.executable})
        os.chmod(self.fake, 0o755)
        self.log = self.path("calls.jsonl")
        env = mock.patch.dict(os.environ, {"FAKE_DUA_LOG": self.log, "FAKE_DUA_MODE": "ok"})
        env.start()
        self.addCleanup(env.stop)
        write(self.path("root", "loose.bin"), 1000)
        write(self.path("root", "sub", "s.bin"), 30000)
        write(self.path("root", "sub", "inner", "i.bin"), 5000)
        write(self.path("root", "other", "o.bin"), 7000)
        write(self.path("root", "third", "t.bin"), 400)
        write(self.path("root", "third", "deep", "d.bin"), 600)
        self.root = self.path("root")
        self.info = {"found": True, "path": self.fake, "version": "2.46.0", "managed": False}

    def aggregate_calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            calls = [json.loads(line) for line in fh if line.strip()]
        return [c for c in calls if c[:1] == ["aggregate"]]

    def run_scan(self, **extra):
        args = argparse.Namespace(roots=[self.root], no_dua=False, **extra)
        with mock.patch.object(scan.platform_info, "check", return_value={"dua": self.info}), mock.patch.object(
            scan, "PRUNE_BYTES", 0  # the fixtures are a few KB: keep their folders in the tree
        ):
            return scan.run(args)

    def test_root_with_several_children_keeps_its_total_and_depth_one(self):
        # Before: the single-input call returned children + total, no row named like the root: 0 bytes.
        result = self.run_scan()
        root = result["tree"]["children"][0]
        self.assertEqual(root["bytes"], 1000 + 30000 + 5000 + 7000 + 1000)
        self.assertEqual(result["read_bytes"], root["bytes"])
        kids = {os.path.basename(c["path"]): c["bytes"] for c in root["children"]}
        self.assertEqual(kids, {"sub": 35000, "other": 7000, "third": 1000})
        self.assertEqual(len(self.aggregate_calls()), 1)  # no big folder: nothing left to attribute

    def test_at_most_two_passes_and_every_folder_read_once(self):
        with mock.patch.object(scan, "DRILL_MIN_BYTES", 0):
            result = self.run_scan()
        calls = self.aggregate_calls()
        self.assertLessEqual(len(calls), 2)
        batch = [a for a in calls[1] if a.startswith(self.root + os.sep)]
        self.assertEqual(sorted(batch), [self.path("root", "sub", "inner"), self.path("root", "third", "deep")])
        sub = next(c for c in result["tree"]["children"][0]["children"] if c["path"].endswith("sub"))
        self.assertEqual([c["bytes"] for c in sub["children"]], [5000])

    def test_exit_1_with_sizes_uses_the_numbers_and_warns(self):
        os.environ["FAKE_DUA_MODE"] = "partial"
        result = self.run_scan()
        self.assertEqual(result["read_bytes"], 44000)
        self.assertEqual(result["errors_total"], 0)
        self.assertGreaterEqual(result["unreadable_entries"], 1)
        self.assertRegex(result["warnings"][0]["warning"], r"^partial: \d+ unreadable entries$")
        self.assertEqual(result["warnings"][0]["path"], self.root)

    def test_permission_denied_root_is_an_error_not_a_reason_to_drop_dua(self):
        os.environ["FAKE_DUA_MODE"] = "eperm"
        result = self.run_scan()
        self.assertEqual((result["tool"], result["fallback"]), ("dua", None))
        self.assertEqual(result["read_bytes"], 0)
        self.assertTrue(result["errors"][0]["error"].startswith("unreadable: "))
        self.assertEqual(result["tree"]["children"][0]["note"], "no size from dua")

    def test_a_timeout_is_an_error_not_a_reason_to_drop_dua(self):
        def slow(argv, timeout=0):
            return None, "", "timed out after %ds" % timeout

        with mock.patch.object(scan, "_run_cmd", side_effect=slow):
            result = self.run_scan(timeout=5)
        self.assertEqual((result["tool"], result["fallback"]), ("dua", None))
        self.assertIn("timed out after 5s", result["errors"][0]["error"])

    def test_timeout_reaches_every_dua_call_flag_then_env_then_default(self):
        seen = []
        real = scan._run_cmd

        def spy(argv, timeout=0):
            seen.append(timeout)
            return real(argv, timeout)

        with mock.patch.object(scan, "DRILL_MIN_BYTES", 0), mock.patch.object(scan, "_run_cmd", side_effect=spy):
            result = self.run_scan(timeout=77)
        self.assertEqual(set(seen), {77})
        self.assertEqual(result["timeout_s"], 77)
        with mock.patch.dict(os.environ, {scan.TIMEOUT_ENV: "42"}):
            self.assertEqual(self.run_scan()["timeout_s"], 42)
            self.assertEqual(self.run_scan(timeout=9)["timeout_s"], 9)
        with mock.patch.dict(os.environ, {scan.TIMEOUT_ENV: "soon"}):
            self.assertEqual(self.run_scan()["timeout_s"], scan.DUA_TIMEOUT_S)
        self.assertEqual(scan.DUA_TIMEOUT_S, 540)

    def test_a_long_batch_is_split_by_argv_budget_without_repeating_paths(self):
        paths = []
        for i in range(5):
            paths.append(self.path("many", "d%d" % i))
            write(self.path("many", "d%d" % i, "f.bin"), 100 * (i + 1))
        dua = scan._make_dua(self.info)
        with mock.patch.object(scan, "BATCH_MAX_PATHS", 2):
            sizes = dua.sizes(paths, [], scan._Ctx(dua))
        self.assertEqual([sizes[p] for p in paths], [100, 200, 300, 400, 500])
        called = [a for c in self.aggregate_calls() for a in c if a.startswith(self.path("many"))]
        self.assertEqual(sorted(called), sorted(paths))

    def test_run_reports_seconds_and_per_root_timing(self):
        result = self.run_scan()
        self.assertIsInstance(result["seconds"], float)
        self.assertEqual([t["root"] for t in result["timing"]], [self.root])
        json.dumps(result)


class TrashHold(Base):
    mock_holds = False

    def setUp(self):
        super().setUp()
        self.home = self.path("home")
        self.trash = os.path.join(self.home, ".Trash")
        os.makedirs(self.trash)
        patcher = mock.patch.object(scan, "_home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def unreadable(self, code=errno.EPERM):
        real = os.scandir

        def scandir(path):
            if os.fspath(path) == self.trash:
                raise PermissionError(code, "Operation not permitted")
            return real(path)

        return mock.patch.object(scan.os, "scandir", side_effect=scandir)

    def finder(self, rc, out="", err=""):
        return mock.patch.object(scan, "_run_cmd", return_value=(rc, out, err))

    def test_finder_size_when_the_scan_cannot_list_the_trash(self):
        with self.unreadable(), self.finder(0, "1048576, 2048\n") as cmd:
            holds = scan._trash_hold([self.home], ask_finder=True)
        self.assertEqual(cmd.call_args[0][0][:2], ["osascript", "-e"])
        self.assertIn("physical size of every item of trash", cmd.call_args[0][0][2])
        item = holds[0]
        self.assertEqual((item["kind"], item["bytes"], item["measured"], item["in_gap"]), ("trash", 1050624, True, True))
        self.assertEqual(item["measured_by"], "Finder (osascript)")
        self.assertIn("Empty the Trash", item["action"])

    def test_without_finder_it_says_full_disk_access_is_needed(self):
        with self.unreadable(), self.finder(1, "", "execution error: Not authorized to send Apple events (-1743)"):
            item = scan._trash_hold([self.home], ask_finder=True)[0]
        self.assertEqual((item["bytes"], item["measured"], item["in_gap"]), (None, False, False))
        self.assertEqual(
            item["note"],
            "Trash: not measurable without Full Disk Access "
            "(System Settings > Privacy & Security > Full Disk Access > add your terminal)",
        )

    def test_finder_blank_answer_is_an_empty_trash_and_missing_value_a_lower_bound(self):
        with self.unreadable(), self.finder(0, "\n"):
            self.assertEqual(scan._trash_hold([self.home], ask_finder=True)[0]["bytes"], 0)
        with self.unreadable(), self.finder(0, "4096, missing value\n"):
            item = scan._trash_hold([self.home], ask_finder=True)[0]
        self.assertEqual((item["bytes"], item["lower_bound"]), (4096, True))
        with self.unreadable(), self.finder(0, "lots\n"):
            self.assertIsNone(scan._trash_hold([self.home], ask_finder=True)[0]["bytes"])

    def test_readable_trash_other_os_and_outside_roots_ask_nothing(self):
        with self.finder(0, "1\n") as cmd:
            self.assertEqual(scan._trash_hold([self.home], ask_finder=True), [])  # readable: dua counted it
            with self.unreadable():
                self.assertEqual(scan._trash_hold([self.path("elsewhere")], ask_finder=True), [])
                self.os_kind = "linux"
                self.assertEqual(scan._trash_hold([self.home], ask_finder=True), [])
        cmd.assert_not_called()

    def test_other_errors_than_permission_are_not_a_privacy_wall(self):
        with self.unreadable(errno.EIO), self.finder(0, "1\n") as cmd:
            self.assertEqual(scan._trash_hold([self.home], ask_finder=True), [])
        cmd.assert_not_called()


class SwapAndSnapshotHolds(Base):
    mock_holds = False

    def test_macos_swap_uses_the_vm_volume_files_and_reports_use(self):
        usage = scan.parse_swapusage(REAL_SWAPUSAGE)
        self.assertEqual(usage, {"total": 12288 * MIB, "used": int(10773.25 * MIB), "free": int(1514.75 * MIB)})
        with mock.patch.object(scan, "_run_cmd", return_value=(0, REAL_SWAPUSAGE, "")), mock.patch.object(
            scan, "_files_allocated", return_value=13631488 * 1024
        ) as listed:
            item = scan._swap_macos(["/Users/u"])[0]
        listed.assert_called_once_with("/System/Volumes/VM")
        self.assertEqual((item["kind"], item["bytes"], item["in_gap"]), ("swap", 13631488 * 1024, True))
        self.assertEqual(item["used_bytes"], usage["used"])
        self.assertIn("Restart the Mac", item["action"])
        self.assertIn("closing", item["action"])

    def test_macos_swap_falls_back_to_the_sysctl_total_and_skips_when_roots_cover_it(self):
        with mock.patch.object(scan, "_run_cmd", return_value=(0, REAL_SWAPUSAGE, "")), mock.patch.object(
            scan, "_files_allocated", return_value=None
        ):
            item = scan._swap_macos(["/Users/u"])[0]
            self.assertEqual(item["bytes"], 12288 * MIB)
            self.assertIn("estimate", item["note"])
            self.assertFalse(scan._swap_macos(["/System"])[0]["in_gap"])  # a root over it already counted it
        with mock.patch.object(scan, "_run_cmd", return_value=(1, "", "")), mock.patch.object(
            scan, "_files_allocated", return_value=None
        ):
            self.assertEqual(scan._swap_macos(["/Users/u"]), [])

    def test_linux_proc_swaps_files_count_partitions_do_not(self):
        entries = scan.parse_proc_swaps(REAL_PROC_SWAPS)
        self.assertEqual(entries[0], {"path": "/swap file", "type": "file", "size_bytes": 2097148 * 1024, "used_bytes": 512 * 1024})
        self.assertEqual(entries[1]["type"], "partition")
        self.os_kind = "linux"
        with mock.patch.object(scan, "_read_proc_swaps", return_value=REAL_PROC_SWAPS), mock.patch.object(
            scan.os, "stat", side_effect=OSError("gone")
        ):
            item = scan._swap_linux(["/home/u"])[0]
        self.assertEqual((item["bytes"], item["partitions_bytes"], item["in_gap"]), (2097148 * 1024, 8388604 * 1024, True))
        with mock.patch.object(scan, "_read_proc_swaps", return_value=""):
            self.assertEqual(scan._swap_linux([]), [])

    def test_windows_pagefile_json_one_object_or_a_list(self):
        one = '{"Name":"C:\\\\pagefile.sys","AllocatedBaseSize":4096,"CurrentUsage":512}'
        self.assertEqual(
            scan.parse_pagefile_json(one), [{"path": "C:\\pagefile.sys", "size_bytes": 4096 * MIB, "used_bytes": 512 * MIB}]
        )
        self.assertEqual(len(scan.parse_pagefile_json("[%s,%s]" % (one, one))), 2)
        self.os_kind = "windows"
        with mock.patch.object(scan, "_run_cmd", return_value=(0, one, "")) as cmd:
            item = scan._swap_windows(["C:\\Users\\u"])[0]
        self.assertIn("Win32_PageFileUsage", cmd.call_args[0][0][-1])
        self.assertEqual((item["bytes"], item["in_gap"]), (4096 * MIB, True))
        with mock.patch.object(scan, "_run_cmd", return_value=(1, "", "denied")):
            self.assertEqual(scan._swap_windows([]), [])

    def test_snapshots_have_a_count_and_no_bytes(self):
        self.assertEqual(scan._snapshots_hold({"count": 0}), [])
        self.assertEqual(scan._snapshots_hold(None), [])
        item = scan._snapshots_hold({"count": 2})[0]
        self.assertEqual((item["kind"], item["count"], item["bytes"], item["in_gap"]), ("snapshots", 2, None, False))
        self.assertIn("tmutil deletelocalsnapshots", item["action"])

    def test_a_failing_probe_never_breaks_the_scan(self):
        with mock.patch.object(scan, "_swap_macos", side_effect=OSError("boom")), mock.patch.object(
            scan, "_trash_hold", return_value=[{"kind": "trash"}]
        ):
            holds = scan.system_holds([], {"count": 1})
        self.assertEqual([h["kind"] for h in holds], ["snapshots", "trash"])


class GapExplainedBy(Base):
    usage = types.SimpleNamespace(total=1000, used=700, free=300)

    def gap(self, holds, read=400):
        os.makedirs(self.path("a"), exist_ok=True)
        holds = [dict(h, path=self.path("a")) for h in holds] if holds else holds  # same volume as the scan
        with mock.patch.object(scan.shutil, "disk_usage", return_value=self.usage):
            return scan._gap([{"path": self.path("a"), "bytes": read}], scan._Ctx(None), holds)

    def test_measured_holds_outside_the_roots_are_subtracted(self):
        holds = [
            {"kind": "swap", "bytes": 120, "in_gap": True},
            {"kind": "trash", "bytes": 30, "in_gap": True},
            {"kind": "snapshots", "bytes": None, "in_gap": False},
            {"kind": "swap", "bytes": 999, "in_gap": False},  # already inside a scanned root
        ]
        gap = self.gap(holds)
        self.assertEqual(
            gap["explained_by"],
            [{"kind": "swap", "bytes": 120, "volume": self.path("a")}, {"kind": "trash", "bytes": 30, "volume": self.path("a")}],
        )
        self.assertEqual((gap["explained_bytes"], gap["raw_unexplained_bytes"], gap["unexplained_bytes"]), (150, 300, 150))
        self.assertEqual(gap["volumes"][0]["unexplained_bytes"], 300)  # volumes[] stay before the subtraction

    def test_no_holds_keeps_the_old_figure_and_the_sign(self):
        gap = self.gap(None)
        self.assertEqual((gap["explained_by"], gap["unexplained_bytes"]), ([], 300))
        # a hold never makes a negative volume more negative: that figure is what the scan over-counted
        self.assertEqual(self.gap([{"kind": "swap", "bytes": 50, "in_gap": True}], read=900)["unexplained_bytes"], -200)

    def test_run_carries_holds_into_the_gap(self):
        write(self.path("root", "a", "x.bin"), 3 << 20)
        swap = {
            "kind": "swap", "label": "Swap", "bytes": 4096, "measured": True, "in_gap": True, "note": "", "action": "",
            "path": self.path("root"),
        }
        with mock.patch.object(scan, "system_holds", return_value=[swap]):
            result = scan.run(argparse.Namespace(roots=[self.path("root")], no_dua=True))
        self.assertEqual(result["system_holds"], [swap])
        gap = result["gap"]
        self.assertEqual(gap["unexplained_bytes"], gap["raw_unexplained_bytes"] - 4096)
        self.assertEqual(gap["explained_by"], [{"kind": "swap", "bytes": 4096, "volume": self.path("root")}])
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()
