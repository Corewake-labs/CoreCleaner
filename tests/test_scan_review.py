"""scan review round (2026-10-21): one regression test per finding, each failing on the code before the fix.

R1  a partial dua answer (exit 1 with sizes) was only a `warnings` entry that the agent view never showed,
    and any other exit code with rows (crash, SIGKILL) was accepted as a total.
R2  a timeout or a permission error left a root at 0 bytes with nothing saying it was not measured;
    `--timeout` was promised by the message and the docstring but not registered in the CLI.
R3  no wall-clock budget, no heartbeat, a per-call default above the 600 s foreground cap of an agent shell.
R4  swap / Trash were subtracted from a volume they do not live on (negative GAP on an external disk).
R5  names with a trailing or leading space, a newline, or colliding keys got the wrong size (or 0).
R6  the Finder question for the Trash (a macOS permission prompt) ran by default with a 120 s timeout.

Everything runs inside tempfile.mkdtemp() through the fake dua of test_scan.
"""

import argparse
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.test_scan import FAKE_DUA, POSIX, Base, scan, write

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
import corecleaner  # noqa: E402
from corecleaner_lib import views  # noqa: E402


class FakeDuaCase(Base):
    """A root with two folders, a fake dua on a private path, scan.run wired to it."""

    def setUp(self):
        super().setUp()
        self.fake = self.path("bin", "dua")
        os.makedirs(os.path.dirname(self.fake))
        with open(self.fake, "w") as fh:
            fh.write(FAKE_DUA % {"python": sys.executable})
        os.chmod(self.fake, 0o755)
        env = mock.patch.dict(os.environ, {"FAKE_DUA_LOG": self.path("calls.jsonl"), "FAKE_DUA_MODE": "ok"})
        env.start()
        self.addCleanup(env.stop)
        write(self.path("root", "sub", "s.bin"), 30000)
        write(self.path("root", "other", "o.bin"), 7000)
        self.root = self.path("root")
        self.info = {"found": True, "path": self.fake, "version": "2.46.0", "managed": False}

    def run_scan(self, roots=None, **extra):
        args = argparse.Namespace(roots=roots or [self.root], no_dua=False, **extra)
        with mock.patch.object(scan.platform_info, "check", return_value={"dua": self.info}), mock.patch.object(
            scan, "PRUNE_BYTES", 0
        ):
            return scan.run(args)

    def view(self, result):
        return views.scan_view(result, Path(self.path("scan-file.json")))


@unittest.skipUnless(POSIX, "fake dua is a POSIX executable")
class R1PartialIsVisible(FakeDuaCase):
    def test_a_partial_scan_says_so_in_the_result_and_in_the_agent_view(self):
        os.environ["FAKE_DUA_MODE"] = "partial"
        result = self.run_scan()
        self.assertIs(result["complete"], False)
        self.assertRegex(result["label"], r"^partial scan \(lower bound")
        view = self.view(result)
        self.assertIs(view["complete"], False)
        self.assertGreaterEqual(view["warnings"]["count"], 1)
        self.assertRegex(view["warnings"]["first"][0], r"partial: \d+ unreadable entries")
        self.assertGreaterEqual(view["unreadable_entries"], 1)
        self.assertRegex(view["label"], r"^partial scan")

    def test_a_clean_scan_is_complete(self):
        result = self.run_scan()
        self.assertIs(result["complete"], True)
        self.assertNotIn("partial", result["label"])
        self.assertEqual(self.view(result)["warnings"], {"count": 0, "first": []})

    def test_rows_from_a_dua_that_crashed_are_not_a_total(self):
        os.environ["FAKE_DUA_MODE"] = "cut"
        # First call: a dua that dies half way is unusable, so the scan restarts in basic mode.
        result = self.run_scan()
        self.assertEqual(result["tool"], "basic")
        self.assertIn("exited 101", result["fallback"])
        # Later call: the cut rows are dropped, the folder is listed as not measured.
        dua = scan._make_dua(self.info)
        dua.good_calls = 1
        ctx = scan._Ctx(dua)
        self.assertIsNone(dua.listing(self.root, [], ctx))
        self.assertIn("exited 101", ctx.errors[0]["error"])

    def test_the_view_shows_holds_the_gap_split_and_errors_as_text(self):
        result = self.run_scan()
        result["system_holds"] = [
            {"kind": "swap", "label": "Swap", "bytes": 4096, "measured": True, "in_gap": True, "note": "n", "action": "a"}
        ]
        result["gap"]["explained_by"] = [{"kind": "swap", "bytes": 4096, "volume": self.root}]
        result["errors"] = [{"path": "/x", "error": "Permission denied"}]
        view = self.view(result)
        self.assertEqual(view["system_holds"][0]["kind"], "swap")
        self.assertEqual(view["system_holds"][0]["bytes"], 4096)
        self.assertEqual(view["gap"]["explained_by"][0]["bytes"], 4096)
        self.assertIn("raw_unexplained_bytes", view["gap"])
        self.assertEqual(view["errors"]["first"], ["/x: Permission denied"])


@unittest.skipUnless(POSIX, "fake dua is a POSIX executable")
class R2UnmeasuredRoots(FakeDuaCase):
    def test_a_timed_out_root_is_unmeasured_not_zero_bytes_in_a_complete_scan(self):
        other = self.path("root2")
        write(os.path.join(other, "x", "x.bin"), 500)

        def slow(argv, timeout=0):
            return None, "", "timed out after %ds" % timeout

        with mock.patch.object(scan, "_run_cmd", side_effect=slow):
            result = self.run_scan(roots=[self.root, other], timeout=5)
        self.assertEqual(sorted(result["unmeasured_roots"]), sorted([self.root, other]))
        self.assertIs(result["complete"], False)
        self.assertRegex(result["label"], r"^partial scan \(lower bound: 2 root\(s\) not measured")
        self.assertEqual(sorted(self.view(result)["unmeasured_roots"]), sorted([self.root, other]))
        self.assertIn("--timeout", result["errors"][0]["error"])

    def test_permission_denied_root_is_unmeasured_too(self):
        os.environ["FAKE_DUA_MODE"] = "eperm"
        result = self.run_scan()
        self.assertEqual(result["unmeasured_roots"], [self.root])
        self.assertIs(result["complete"], False)

    def test_timeout_flag_is_registered_in_the_cli(self):
        args = corecleaner.build_parser().parse_args(["scan", "--roots", "/x", "--timeout", "5", "--max-seconds", "60"])
        self.assertEqual((args.timeout, args.max_seconds), (5, 60))
        self.assertFalse(corecleaner.build_parser().parse_args(["scan"]).ask_finder)
        self.assertTrue(corecleaner.build_parser().parse_args(["scan", "--ask-finder"]).ask_finder)


class R3Budget(FakeDuaCase):
    def test_the_default_per_call_timeout_fits_under_an_agent_foreground_shell(self):
        self.assertLess(scan.DUA_TIMEOUT_S, 600)

    def test_a_wall_clock_budget_caps_each_call_and_stops_the_scan_labelled(self):
        roots = [self.path("r%d" % i) for i in range(3)]
        for r in roots:
            write(os.path.join(r, "d", "f.bin"), 100)
        clock = [0.0]
        seen = []

        def fake_run(argv, timeout=0):
            seen.append(timeout)
            clock[0] += 100.0
            return 0, "         0 b d\n", ""

        dua = scan._Dua("dua", "2.46.0", True, True, timeout=900)
        ctx = scan._Ctx(dua)
        ctx.clock = lambda: clock[0]
        ctx.deadline = 150.0
        with mock.patch.object(scan, "_run_cmd", side_effect=fake_run), mock.patch.object(scan, "_list_dirs", return_value=([], [])):
            scan._scan_all(roots, ctx)
        self.assertEqual(seen, [150.0, 50.0])  # capped by what is left; the third root never started
        self.assertEqual(ctx.unmeasured, [roots[2]])
        self.assertIn("--max-seconds", ctx.errors[-1]["error"])

    def test_run_reads_the_budget_from_the_flag_then_the_environment(self):
        self.assertEqual(scan._resolve_max_seconds(argparse.Namespace(max_seconds=60)), 60)
        with mock.patch.dict(os.environ, {scan.MAX_SECONDS_ENV: "90"}):
            self.assertEqual(scan._resolve_max_seconds(argparse.Namespace()), 90)
            self.assertEqual(scan._resolve_max_seconds(argparse.Namespace(max_seconds=5)), 5)
        self.assertIsNone(scan._resolve_max_seconds(argparse.Namespace()))
        self.assertEqual(self.run_scan(max_seconds=120)["max_seconds"], 120)

    def test_a_slow_command_prints_a_heartbeat_on_stderr_and_a_timeout_kills_it(self):
        lines = []
        with mock.patch.object(scan, "HEARTBEAT_S", 0.2), mock.patch.object(scan, "log", side_effect=lines.append):
            rc, _, _ = scan._run_cmd([sys.executable, "-c", "import time; time.sleep(1.0)"], 20)
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(len(lines), 2)
        self.assertRegex(lines[0], r"still running")
        self.assertNotIn("time.sleep", lines[0])  # never the argv: it can hold a user path
        with mock.patch.object(scan, "HEARTBEAT_S", 0.2), mock.patch.object(scan, "log"):
            rc, out, err = scan._run_cmd([sys.executable, "-c", "import time; time.sleep(30)"], 1)
        self.assertEqual((rc, out), (None, ""))
        self.assertEqual(err, "timed out after 1s")

    def test_skill_tells_the_agent_to_run_the_slow_steps_in_the_background(self):
        text = (SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")
        steps = {line.split(".")[0]: line for line in text.splitlines() if line[:2] in ("4.", "6.")}
        for number in ("4", "6"):
            self.assertIn("background", steps[number])
        self.assertIn("--max-seconds", steps["4"])
        self.assertIn("complete", steps["4"])


class R4GapPerVolume(Base):
    def setUp(self):
        super().setUp()
        os.makedirs(self.path("a"))
        os.makedirs(self.path("b"))
        self.fake_dev = {self.path("a"): 11, self.path("b"): 22}
        real_stat = os.stat

        def stat(path, *a, **k):
            if path in self.fake_dev:
                return types.SimpleNamespace(st_dev=self.fake_dev[path])
            return real_stat(path, *a, **k)

        self.usage = {}
        patches = [
            mock.patch.object(scan.os, "stat", side_effect=stat),
            mock.patch.object(scan.shutil, "disk_usage", side_effect=lambda p: self.usage[p]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def gap(self, holds, read=400):
        return scan._gap([{"path": self.path("a"), "bytes": read}], scan._Ctx(None), holds)

    def test_a_hold_on_another_volume_is_not_subtracted_and_is_listed(self):
        self.usage = {
            self.path("a"): types.SimpleNamespace(total=1000, used=700, free=300),
            self.path("b"): types.SimpleNamespace(total=5000, used=100, free=4900),
        }
        swap = {"kind": "swap", "bytes": 120, "in_gap": True, "path": self.path("b")}
        gap = self.gap([swap])
        self.assertEqual((gap["explained_bytes"], gap["unexplained_bytes"], gap["raw_unexplained_bytes"]), (0, 300, 300))
        self.assertEqual(gap["explained_by"], [])
        self.assertEqual(gap["held_elsewhere"], [{"kind": "swap", "bytes": 120, "path": self.path("b")}])

    def test_a_hold_in_the_same_container_is_subtracted_from_that_volume_only(self):
        # Two APFS volumes of one container: different st_dev, same total and free.
        self.usage = {
            self.path("a"): types.SimpleNamespace(total=1000, used=700, free=300),
            self.path("b"): types.SimpleNamespace(total=1000, used=50, free=300),
        }
        gap = self.gap([{"kind": "swap", "bytes": 120, "in_gap": True, "path": self.path("b")}])
        self.assertEqual(gap["explained_by"], [{"kind": "swap", "bytes": 120, "volume": self.path("a")}])
        self.assertEqual((gap["explained_bytes"], gap["unexplained_bytes"]), (120, 180))
        self.assertEqual(gap["volumes"][0]["unexplained_bytes"], 300)  # volumes[] stay before the subtraction

    def test_a_hold_never_pushes_a_volume_below_zero(self):
        self.usage = {self.path("a"): types.SimpleNamespace(total=1000, used=500, free=500)}
        self.fake_dev[self.path("b")] = 11  # same device as a
        gap = self.gap([{"kind": "swap", "bytes": 900, "in_gap": True, "path": self.path("b")}], read=400)
        self.assertEqual(gap["raw_unexplained_bytes"], 100)
        self.assertEqual(gap["unexplained_bytes"], 0)
        self.assertEqual(gap["explained_by"], [{"kind": "swap", "bytes": 100, "volume": self.path("a")}])

    def test_a_negative_volume_stays_as_it_was_and_a_hold_without_a_path_is_not_attributed(self):
        self.usage = {self.path("a"): types.SimpleNamespace(total=1000, used=700, free=300)}
        gap = self.gap([{"kind": "swap", "bytes": 50, "in_gap": True}], read=900)
        self.assertEqual(gap["unexplained_bytes"], -200)
        self.assertEqual(gap["held_elsewhere"], [{"kind": "swap", "bytes": 50, "path": None}])

    def test_system_holds_carry_the_path_they_were_measured_on(self):
        self.os_kind = "macos"
        with mock.patch.object(scan, "_run_cmd", return_value=(0, "total = 1.00M  used = 0.00M  free = 1.00M\n", "")), mock.patch.object(
            scan, "_files_allocated", return_value=4096
        ):
            item = scan._swap_macos(["/Users/u"])[0]
        self.assertEqual(item["path"], scan.VM_VOLUME)


@unittest.skipUnless(POSIX, "fake dua is a POSIX executable")
class R5Names(FakeDuaCase):
    def test_parser_keeps_leading_and_trailing_spaces_of_a_name(self):
        self.assertEqual(scan.parse_dua_output("      4096 b foo \n"), [(4096, "foo ")])
        self.assertEqual(scan.parse_dua_output("        10 b  lead\n"), [(10, " lead")])
        self.assertEqual(scan.parse_dua_rows("         0 b foo   <1 IO Error>\n"), [(0, "foo ", 1)])
        self.assertEqual(scan.parse_dua_rows("       7 b a  <b> c\n"), [(7, "a  <b> c", 0)])

    def test_two_children_with_the_same_name_key_are_both_unknown_not_the_last_one(self):
        total, kids = scan.split_listing([(1, "x"), (2, "x"), (4, "y"), (7, "total")])
        self.assertEqual((total, kids), (7, {"x": None, "y": 4}))

    def test_folders_that_differ_only_by_a_space_or_a_newline_get_their_own_size(self):
        write(self.path("odd", "foo", "f.bin"), 100)
        write(self.path("odd", "foo ", "f.bin"), 300)
        write(self.path("odd", " lead", "f.bin"), 50)
        write(self.path("odd", "a\nb", "f.bin"), 70)
        write(self.path("odd", "a", "f.bin"), 111)  # bigger than "a\nb": its bogus "a" row sorts first
        result = self.run_scan(roots=[self.path("odd")])
        root = result["tree"]["children"][0]
        kids = {os.path.basename(c["path"]): c for c in root["children"]}
        self.assertEqual(
            {k: v["bytes"] for k, v in kids.items()},
            {"foo": 100, "foo ": 300, " lead": 50, "a\nb": 70, "a": 111},
        )
        self.assertFalse([c for c in kids.values() if c.get("note")])
        self.assertEqual(root["bytes"], 100 + 300 + 50 + 70 + 111)


class R6FinderIsOptIn(Base):
    mock_holds = False

    def setUp(self):
        super().setUp()
        self.home = self.path("home")
        self.trash = os.path.join(self.home, ".Trash")
        os.makedirs(self.trash)
        for patcher in (
            mock.patch.object(scan, "_home", return_value=self.home),
            mock.patch.object(scan.os, "scandir", side_effect=self._scandir(os.scandir)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _scandir(self, real):
        def scandir(path):
            if os.fspath(path) == self.trash:
                raise PermissionError(1, "Operation not permitted")
            return real(path)

        return scandir

    def test_by_default_a_scan_does_not_ask_finder_and_says_how_to(self):
        with mock.patch.object(scan, "_run_cmd") as cmd:
            hold = scan._trash_hold([self.home])[0]
        cmd.assert_not_called()
        self.assertEqual((hold["bytes"], hold["in_gap"]), (None, False))
        self.assertIn("Full Disk Access", hold["note"])
        self.assertIn("--ask-finder", hold["action"])

    def test_opt_in_asks_finder_with_a_short_timeout(self):
        with mock.patch.object(scan, "_run_cmd", return_value=(0, "4096\n", "")) as cmd:
            hold = scan._trash_hold([self.home], ask_finder=True)[0]
        self.assertEqual(cmd.call_args[0][1], scan.FINDER_TIMEOUT_S)
        self.assertLess(scan.FINDER_TIMEOUT_S, scan.CMD_TIMEOUT_S)
        self.assertEqual((hold["bytes"], hold["in_gap"]), (4096, True))

    def test_the_flag_reaches_system_holds_from_run(self):
        write(self.path("root", "a", "x.bin"), 100)
        with mock.patch.object(scan, "system_holds", return_value=[]) as holds:
            scan.run(argparse.Namespace(roots=[self.path("root")], no_dua=True))
            scan.run(argparse.Namespace(roots=[self.path("root")], no_dua=True, ask_finder=True))
        self.assertEqual([c.kwargs.get("ask_finder") for c in holds.call_args_list], [False, True])


if __name__ == "__main__":
    unittest.main()
