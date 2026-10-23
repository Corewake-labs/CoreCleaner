"""scan module: dua text parser, dua mode through a fake dua, basic mode on fixtures, gap, snapshots.

Everything runs inside tempfile.mkdtemp(). safety and platform_info are mocked (other modules own
them); dua is a fake executable that prints the "<bytes> b <name>" format and logs its argv.
"""

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import common, scan  # noqa: E402

POSIX = os.name == "posix"
NO_DUA = {"found": False, "path": None, "version": None, "managed": False}

FAKE_DUA = """#!%(python)s
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_DUA_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\\n")
if args[:1] == ["--version"]:
    print("dua-cli 2.46.0")
    sys.exit(0)
mode = os.environ.get("FAKE_DUA_MODE", "ok")
if mode == "dead":
    sys.stderr.write("boom\\n")
    sys.exit(2)
if mode == "eperm":
    sys.stderr.write("Error: Operation not permitted (os error 1)\\n")
    sys.exit(1)
paths = args[args.index("--") + 1:]
ignore = [a[2:] for a in args if a.startswith("-i")]
def size(p):
    if not os.path.isdir(p):
        return os.lstat(p).st_size
    total = 0
    for d, dirs, files in os.walk(p):
        dirs[:] = [x for x in dirs if os.path.join(d, x) not in ignore]
        for f in files:
            total += os.lstat(os.path.join(d, f)).st_size
    return total
# Real dua 2.46.0: ONE directory input prints its children and then `total` (no `total` for a
# single child, nothing for an empty folder); several inputs print one row per input plus `total`.
if len(paths) == 1 and os.path.isdir(paths[0]):
    kids = [os.path.join(paths[0], n) for n in os.listdir(paths[0])]
    rows = sorted((size(k), os.path.basename(k)) for k in kids if k not in ignore)
    with_total = len(rows) >= 2
else:
    rows = sorted((size(p), os.path.basename(p) if mode == "basename" else p) for p in paths)
    with_total = len(paths) > 1
if mode == "cut":  # killed half way: one row, no total, a crash exit code
    rows, with_total = rows[:1], False
flag = "  <1 IO Error>" if mode == "partial" else ""
for i, (n, name) in enumerate(rows):
    print("%%12d b %%s%%s" %% (n, name, flag if i == 0 else ""))
if with_total:
    print("%%12d b total%%s" %% (sum(n for n, _ in rows), flag))
sys.exit(1 if mode == "partial" else 101 if mode == "cut" else 0)
"""


def write(path, size):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(os.urandom(size))


def allocated_oracle(root):
    """Independent allocated-bytes sum (os.walk + lstat): inode once, symlinks not followed."""
    seen = set()
    total = 0

    def add(st):
        nonlocal total
        if not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1:
            key = (st.st_dev, st.st_ino)
            if key in seen:
                return
            seen.add(key)
        total += st.st_blocks * 512

    add(os.lstat(root))
    for d, dirs, files in os.walk(root):
        for name in dirs + files:
            add(os.lstat(os.path.join(d, name)))
    return total


class Base(unittest.TestCase):
    cloud = ()
    mock_snapshots = True
    mock_holds = True

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-scan-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.os_kind = "macos"
        patches = [
            mock.patch.object(scan.safety, "is_cloud_or_placeholder", side_effect=self._is_cloud),
            mock.patch.object(scan.safety, "sanitize_name", side_effect=lambda s, maxlen=80: s[:maxlen]),
            mock.patch.object(scan.platform_info, "os_kind", side_effect=lambda: self.os_kind),
            mock.patch.object(scan.platform_info, "check", return_value={"dua": NO_DUA}),
        ]
        if self.mock_snapshots:
            patches.append(
                mock.patch.object(
                    scan, "read_snapshots", return_value={"tool": "none", "available": False, "items": [], "count": 0}
                )
            )
        if self.mock_holds:  # swap, Trash and Finder are real-machine probes
            patches.append(mock.patch.object(scan, "system_holds", create=True, return_value=[]))
        # what the roots miss is the real volume of a temp folder: never walk it from a unit test
        patches.append(mock.patch.dict(os.environ, {scan.OUTSIDE_ENV: "0"}))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _is_cloud(self, path):
        for part in self.cloud:
            if part in path:
                return True, "fake " + part
        return False, ""

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


class DuaParser(unittest.TestCase):
    SAMPLE = (
        "   1048576 b /Users/u/proj/node_modules\n"
        "  52428800 b /Users/u/proj/.git\n"
        " 262144000 b /Users/u/proj/big dir\n"
        "       123 b 2024 notes\n"
        "\n"
        "Enumerating 12 entries\n"
        "error: permission denied\n"
        " 315621051 b total\n"
    )

    def test_literal_sample_in_text_format(self):
        rows = scan.parse_dua_output(self.SAMPLE)
        self.assertEqual(
            rows,
            [
                (1048576, "/Users/u/proj/node_modules"),
                (52428800, "/Users/u/proj/.git"),
                (262144000, "/Users/u/proj/big dir"),
                (123, "2024 notes"),
                (315621051, "total"),
            ],
        )

    def test_tolerates_ansi_colour_crlf_and_human_units(self):
        text = "\x1b[32m  4096 b\x1b[0m \x1b[1m/x/y\x1b[0m\r\n  1.50 GiB /a\n  2 KB /b\n"
        self.assertEqual(scan.parse_dua_output(text), [(4096, "/x/y"), (1610612736, "/a"), (2000, "/b")])

    def test_big_integers_stay_exact(self):
        self.assertEqual(scan.parse_dua_output("9007199254740993 b /big\n"), [(9007199254740993, "/big")])

    def test_garbage_yields_nothing(self):
        self.assertEqual(scan.parse_dua_output(""), [])
        self.assertEqual(scan.parse_dua_output("dua: command not found\n12 items\n"), [])


class VersionGate(unittest.TestCase):
    def test_dedup_flag_threshold(self):
        for text, expected in (
            ("2.46.0", True),
            ("dua-cli 2.46.0", True),
            ("dua 2.43.0", True),
            ("2.42.9", False),
            ("2.9.0", False),
            ("3.0.0", True),
            ("", False),
            (None, False),
        ):
            self.assertEqual(scan.dedup_supported(text), expected, text)


class Roots(Base):
    def test_default_roots_per_os_never_slash(self):
        with mock.patch.object(scan, "_home", return_value="/home/x"), mock.patch.object(
            scan, "_real", side_effect=lambda p: p
        ), mock.patch.object(scan.os.path, "isdir", return_value=True):
            self.os_kind = "macos"
            self.assertEqual(
                scan.default_roots(), ["/home/x", "/Applications", "/Library", "/opt", "/usr/local"]
            )
            self.os_kind = "linux"
            roots = scan.default_roots()
            self.assertEqual(roots, ["/home/x", "/var", "/opt", "/usr", "/srv", "/tmp"])
            self.assertNotIn("/", roots)

    def test_missing_roots_are_dropped(self):
        with mock.patch.object(scan, "_home", return_value="/home/x"), mock.patch.object(
            scan, "_real", side_effect=lambda p: p
        ), mock.patch.object(scan.os.path, "isdir", side_effect=lambda p: p != "/srv"):
            self.os_kind = "linux"
            self.assertNotIn("/srv", scan.default_roots())

    def test_windows_roots_env_other_fixed_drives_and_nested_temp(self):
        env = {
            "ProgramData": "/progdata",
            "ProgramFiles": "/progfiles",
            "TEMP": "/u/me/AppData/Local/Temp",
            "SystemDrive": "C:",
        }
        with mock.patch.object(scan, "_home", return_value="/u/me"), mock.patch.object(
            scan, "_real", side_effect=lambda p: p
        ), mock.patch.object(scan.os.path, "isdir", return_value=True), mock.patch.dict(
            os.environ, env, clear=False
        ), mock.patch.object(
            scan, "_windows_fixed_drives", return_value=["C:\\", "D:\\"]
        ):
            self.os_kind = "windows"
            os.environ.pop("ProgramFiles(x86)", None)
            self.assertEqual(scan.default_roots(), ["/u/me", "/progdata", "/progfiles", "D:\\"])

    def test_nested_and_duplicate_roots_count_once(self):
        os.makedirs(self.path("sub"))
        kept, dropped = scan._prepare_roots([self.tmp, self.path("sub"), self.path("missing"), self.tmp])
        self.assertEqual(kept, [self.tmp])
        reasons = sorted(d["reason"].split(" ")[0] for d in dropped)
        self.assertEqual(reasons, ["inside", "inside", "not"])
        kept, _ = scan._prepare_roots([self.path("sub"), self.tmp])
        self.assertEqual(kept, [self.tmp])

    def test_cloud_root_is_dropped(self):
        self.cloud = ("Dropbox",)
        os.makedirs(self.path("Dropbox"))
        kept, dropped = scan._prepare_roots([self.path("Dropbox")])
        self.assertEqual(kept, [])
        self.assertIn("cloud", dropped[0]["reason"])


class BasicMode(Base):
    def build(self):
        write(self.path("root", "a.bin"), 100000)
        os.link(self.path("root", "a.bin"), self.path("root", "hard.bin"))
        write(self.path("root", "sub", "b.bin"), 50000)
        write(self.path("root", "sub", "deep1", "deep2", "deep3", "c.bin"), 20000)
        write(self.path("outside", "huge.bin"), 400000)
        if POSIX:
            os.symlink(self.path("outside"), self.path("root", "link"))
        return self.path("root")

    def scan_root(self, root):
        ctx = scan._Ctx(None)
        node = scan._scan_root_basic(root, ctx)
        return node, ctx

    @unittest.skipUnless(POSIX, "st_blocks")
    def test_allocated_total_matches_independent_oracle_hardlink_once_symlink_not_followed(self):
        root = self.build()
        with mock.patch.object(scan, "PRUNE_BYTES", 0):
            node, ctx = self.scan_root(root)
            scan._prune(node)
        self.assertEqual(node["bytes"], allocated_oracle(root))
        self.assertTrue(node["apparent"])
        a_alloc = os.lstat(self.path("root", "a.bin")).st_blocks * 512
        counted_twice = allocated_oracle(root) + a_alloc
        self.assertLess(node["bytes"], counted_twice)
        self.assertNotIn(self.path("root", "link"), [c["path"] for c in node["children"]])
        self.assertLess(node["bytes"], 400000)  # the symlink target (400 KB file) is outside
        self.assertEqual(ctx.errors, [])

    @unittest.skipUnless(POSIX, "st_blocks")
    def test_depth_two_nodes_and_deeper_bytes_roll_up(self):
        root = self.build()
        with mock.patch.object(scan, "PRUNE_BYTES", 0):
            node, _ = self.scan_root(root)
            scan._prune(node)
        by_path = {c["path"]: c for c in node["children"]}
        sub = by_path[self.path("root", "sub")]
        deep1 = {c["path"]: c for c in sub["children"]}[self.path("root", "sub", "deep1")]
        self.assertEqual(deep1["children"], [])  # depth 3 is not materialized
        deep_alloc = allocated_oracle(self.path("root", "sub", "deep1"))
        self.assertEqual(deep1["bytes"], deep_alloc)
        self.assertGreaterEqual(sub["bytes"], deep1["bytes"])
        self.assertEqual(sub["children"][0]["apparent"], True)

    @unittest.skipUnless(POSIX, "st_blocks")
    def test_small_folders_are_folded_into_pruned(self):
        root = self.build()
        node, _ = self.scan_root(root)
        total = node["bytes"]
        scan._prune(node)
        self.assertEqual(node["bytes"], total)
        self.assertEqual(node["children"], [])
        self.assertEqual(node["pruned"]["count"], 1)
        self.assertGreater(node["pruned"]["bytes"], 0)

    def test_cloud_folder_is_listed_never_entered(self):
        self.cloud = ("Dropbox",)
        write(self.path("root", "keep.bin"), 1000)
        write(self.path("root", "Dropbox", "big.bin"), 300000)
        real_scandir = os.scandir
        entered = []

        def recording(path="."):
            entered.append(os.fspath(path))
            return real_scandir(path)

        with mock.patch.object(scan.os, "scandir", side_effect=recording):
            ctx = scan._Ctx(None)
            node = scan._scan_root_basic(self.path("root"), ctx)
        self.assertEqual([p for p in entered if "Dropbox" in p], [])
        cloud = [c for c in node["children"] if c["path"].endswith("Dropbox")][0]
        self.assertEqual(cloud["bytes"], 0)
        self.assertTrue(cloud["note"].startswith("cloud"))
        self.assertEqual(ctx.cloud, [self.path("root", "Dropbox")])
        self.assertEqual(ctx.ignore, [self.path("root", "Dropbox")])
        self.assertLess(node["bytes"], 100000)

    @unittest.skipUnless(POSIX, "chmod semantics")
    @unittest.skipIf(POSIX and os.geteuid() == 0, "root reads everything")
    def test_unreadable_folder_is_kept_with_a_note_and_an_error(self):
        write(self.path("root", "ok", "x.bin"), 5000)
        os.makedirs(self.path("root", "locked"))
        os.chmod(self.path("root", "locked"), 0)
        self.addCleanup(os.chmod, self.path("root", "locked"), 0o700)
        node, ctx = self.scan_root(self.path("root"))
        locked = [c for c in node["children"] if c["path"].endswith("locked")][0]
        self.assertTrue(locked["note"].startswith("unreadable"))
        self.assertEqual(ctx.errors_total, 1)
        self.assertEqual(ctx.errors[0]["path"], self.path("root", "locked"))
        scan._prune(node)
        self.assertIn(self.path("root", "locked"), [c["path"] for c in node["children"]])  # never pruned

    def test_unreadable_root_does_not_raise(self):
        node, ctx = self.scan_root(self.path("missing"))
        self.assertEqual(node["bytes"], 0)
        self.assertTrue(node["note"].startswith("unreadable"))
        self.assertEqual(ctx.errors_total, 1)

    @unittest.skipUnless(POSIX, "st_blocks")
    def test_other_filesystem_and_dataless_files_are_not_counted(self):
        write(self.path("root", "plain.bin"), 20000)
        write(self.path("root", "mnt", "inside.bin"), 300000)
        write(self.path("root", "gone.bin"), 90000)
        real_scandir = os.scandir

        class Entry:
            def __init__(self, real):
                self._real = real
                self.name, self.path = real.name, real.path

            def is_dir(self, follow_symlinks=True):
                return self._real.is_dir(follow_symlinks=follow_symlinks)

            def stat(self, follow_symlinks=True):
                st = self._real.stat(follow_symlinks=follow_symlinks)
                if self.name not in ("mnt", "gone.bin"):
                    return st
                return types.SimpleNamespace(
                    st_mode=st.st_mode,
                    st_dev=st.st_dev + (1 if self.name == "mnt" else 0),
                    st_ino=st.st_ino,
                    st_nlink=st.st_nlink,
                    st_size=st.st_size,
                    st_blocks=st.st_blocks,  # a placeholder must be skipped by its flag, not by luck
                    st_flags=scan.SF_DATALESS if self.name == "gone.bin" else 0,
                )

        class Handle:
            def __init__(self, real):
                self._real = real

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._real.close()

            def __iter__(self):
                return (Entry(e) for e in self._real)

        with mock.patch.object(scan.os, "scandir", side_effect=lambda p=".": Handle(real_scandir(p))), mock.patch.object(
            scan, "_DARWIN", True
        ):
            ctx = scan._Ctx(None)
            node = scan._scan_root_basic(self.path("root"), ctx)
        mnt = [c for c in node["children"] if c["path"].endswith("mnt")][0]
        self.assertEqual((mnt["bytes"], mnt["note"].startswith("other filesystem")), (0, True))
        self.assertEqual(ctx.other_fs, [self.path("root", "mnt")])
        self.assertEqual(ctx.placeholder_files, 1)
        plain_alloc = os.lstat(self.path("root", "plain.bin")).st_blocks * 512
        own = os.lstat(self.path("root")).st_blocks * 512
        self.assertEqual(node["bytes"], own + plain_alloc)  # mnt and gone.bin add nothing

    def test_placeholder_flags(self):
        flagged = types.SimpleNamespace(st_flags=scan.SF_DATALESS)
        plain = types.SimpleNamespace(st_flags=0)
        win = types.SimpleNamespace(st_file_attributes=0x40000)
        self.assertTrue(scan._is_placeholder_stat(flagged, True))
        self.assertFalse(scan._is_placeholder_stat(flagged, False))  # flag value means something else off macOS
        self.assertFalse(scan._is_placeholder_stat(plain, True))
        self.assertTrue(scan._is_placeholder_stat(win, False))
        self.assertFalse(scan._is_placeholder_stat(types.SimpleNamespace(), True))

    @unittest.skipUnless(sys.platform == "darwin", "APFS clones")
    def test_apfs_clones_are_counted_in_full_in_basic_mode(self):
        write(self.path("root", "one", "big.bin"), 1 << 20)
        for name in ("two", "three"):
            os.makedirs(self.path("root", name))
            done = subprocess.run(
                ["cp", "-c", self.path("root", "one", "big.bin"), self.path("root", name, "big.bin")],
                capture_output=True,
            )
            if done.returncode != 0:
                self.skipTest("cp -c not supported on this volume")
        node, _ = self.scan_root(self.path("root"))
        one_file = os.lstat(self.path("root", "one", "big.bin")).st_blocks * 512
        self.assertGreaterEqual(node["bytes"], 3 * one_file)
        self.assertTrue(node["apparent"])


@unittest.skipUnless(POSIX, "fake dua is a POSIX executable")
class DuaMode(Base):
    def setUp(self):
        super().setUp()
        self.fake = self.path("bin", "dua")
        os.makedirs(os.path.dirname(self.fake))
        with open(self.fake, "w") as fh:
            fh.write(FAKE_DUA % {"python": sys.executable})
        os.chmod(self.fake, 0o755)
        self.log = self.path("calls.jsonl")
        self.mode = "ok"
        env = mock.patch.dict(os.environ, {"FAKE_DUA_LOG": self.log})
        env.start()
        self.addCleanup(env.stop)
        write(self.path("root", "loose.bin"), 1000)
        write(self.path("root", "sub", "s.bin"), 30000)
        write(self.path("root", "sub", "inner", "i.bin"), 5000)
        write(self.path("root", "other", "o.bin"), 7000)
        write(self.path("root", "Dropbox", "d.bin"), 9000)
        self.root = self.path("root")

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def dua(self, version="2.46.0"):
        os.environ["FAKE_DUA_MODE"] = self.mode
        return scan._make_dua({"found": True, "path": self.fake, "version": version, "managed": False})

    def test_macos_flags_ignore_dirs_batching_and_sizes(self):
        self.cloud = ("Dropbox",)
        dua = self.dua()
        self.assertTrue(dua.dedup and dua.exact)
        with mock.patch.object(scan, "DRILL_MIN_BYTES", 0), mock.patch.object(scan, "PRUNE_BYTES", 0):
            ctx = scan._Ctx(dua)
            tree = scan._scan_all([self.root], ctx)
        head = ["aggregate", "-f", "bytes", "-x", "--deduplicate-apfs-clones"]  # argv without the program
        calls = self.calls()
        self.assertEqual(len(calls), 2)  # pass 1: the root alone; pass 2: ONE batch of depth-2 folders
        self.assertEqual(calls[0], head + ["-i" + self.path("root", "Dropbox"), "--", self.root])
        self.assertEqual(calls[1], head + ["--", self.path("root", "sub", "inner")])
        root = tree["children"][0]
        self.assertEqual(root["bytes"], 1000 + 30000 + 5000 + 7000)  # Dropbox ignored
        self.assertEqual(tree["bytes"], root["bytes"])
        self.assertFalse(root["apparent"])
        kids = {os.path.basename(c["path"]): c for c in root["children"]}
        self.assertEqual((kids["sub"]["bytes"], kids["other"]["bytes"]), (35000, 7000))
        self.assertEqual(kids["Dropbox"]["bytes"], 0)
        self.assertTrue(kids["Dropbox"]["note"].startswith("cloud"))
        self.assertEqual(kids["sub"]["children"][0]["bytes"], 5000)

    def test_flag_only_on_macos_and_only_from_2_43(self):
        self.os_kind = "linux"
        dua = self.dua()
        self.assertFalse(dua.dedup)
        self.assertTrue(dua.exact)
        scan._scan_all([self.root], scan._Ctx(dua))
        self.assertTrue(all("--deduplicate-apfs-clones" not in c for c in self.calls()))
        os.remove(self.log)  # the test's own log file in its own temp dir
        self.os_kind = "macos"
        old = self.dua("2.42.0")
        self.assertFalse(old.dedup)
        self.assertFalse(old.exact)
        ctx = scan._Ctx(old)
        scan._scan_all([self.root], ctx)
        self.assertTrue(all("--deduplicate-apfs-clones" not in c for c in self.calls()))
        self.assertTrue(ctx.apparent)
        self.assertIn("older than 2.43.0", scan._label(ctx))

    def test_version_is_probed_when_platform_info_has_none(self):
        dua = self.dua(version=None)
        self.assertTrue(dua.dedup)
        self.assertEqual(self.calls()[0], ["--version"])

    def test_names_that_do_not_match_fall_back_to_one_call_per_path(self):
        self.mode = "basename"
        dua = self.dua()
        ctx = scan._Ctx(dua)
        sizes = dua.sizes([self.path("root", "other"), self.path("root", "sub")], [], ctx)
        self.assertEqual(sizes, {self.path("root", "other"): 7000, self.path("root", "sub"): 35000})
        self.assertEqual(len(self.calls()), 3)  # one batch plus one retry per unmatched path

    def test_nonzero_exit_with_output_is_accepted_and_recorded(self):
        self.mode = "partial"
        dua = self.dua()
        ctx = scan._Ctx(dua)
        self.assertEqual(dua.sizes([self.path("root", "other")], [], ctx), {self.path("root", "other"): 7000})
        self.assertEqual(ctx.errors_total, 0)  # exit 1 with sizes is a warning, not a failure
        self.assertEqual(ctx.warnings[0]["warning"], "partial: 1 unreadable entries")
        self.assertEqual(ctx.unreadable_total, 1)

    def test_dead_dua_falls_back_to_basic_in_run(self):
        self.mode = "dead"
        info = {"found": True, "path": self.fake, "version": "2.46.0", "managed": False}
        os.environ["FAKE_DUA_MODE"] = self.mode
        with mock.patch.object(scan.platform_info, "check", return_value={"dua": info}):
            result = scan.run(argparse.Namespace(roots=[self.root], no_dua=False))
        self.assertEqual(result["tool"], "basic")
        self.assertFalse(result["exact"])
        self.assertIn("first call", result["fallback"])
        self.assertIsNone(result["dua"])

    def test_run_with_dua_reports_tool_and_label(self):
        info = {"found": True, "path": self.fake, "version": "2.46.0", "managed": False}
        os.environ["FAKE_DUA_MODE"] = "ok"
        with mock.patch.object(scan.platform_info, "check", return_value={"dua": info}):
            result = scan.run(argparse.Namespace(roots=[self.root], no_dua=False))
        self.assertEqual((result["tool"], result["exact"], result["fallback"]), ("dua", True, None))
        self.assertTrue(result["label"].startswith("dua:"))
        self.assertTrue(result["dua"]["dedup_apfs_clones"])
        json.dumps(result)

    def test_no_dua_flag_never_runs_dua(self):
        info = {"found": True, "path": self.fake, "version": "2.46.0", "managed": False}
        with mock.patch.object(scan.platform_info, "check", return_value={"dua": info}):
            result = scan.run(argparse.Namespace(roots=[self.root], no_dua=True))
        self.assertEqual(result["tool"], "basic")
        self.assertEqual(self.calls(), [])


class Summaries(Base):
    def test_gap_is_used_minus_read_per_volume_and_keeps_the_sign(self):
        usage = types.SimpleNamespace(total=1000, used=700, free=300)
        os.makedirs(self.path("a"))
        os.makedirs(self.path("b"))
        with mock.patch.object(scan.shutil, "disk_usage", return_value=usage):
            ctx = scan._Ctx(None)
            gap = scan._gap([{"path": self.path("a"), "bytes": 400}, {"path": self.path("b"), "bytes": 100}], ctx)
            self.assertEqual((gap["used_bytes"], gap["read_bytes"], gap["unexplained_bytes"]), (700, 500, 200))
            self.assertEqual(len(gap["volumes"]), 1)
            self.assertEqual(gap["label"], "unexplained")
            over = scan._gap([{"path": self.path("a"), "bytes": 900}], ctx)
            self.assertEqual(over["unexplained_bytes"], -200)

    def test_gap_groups_roots_by_device(self):
        usage = types.SimpleNamespace(total=1000, used=600, free=400)
        real_stat = os.stat
        os.makedirs(self.path("a"))
        os.makedirs(self.path("b"))

        def fake_stat(path, *args, **kwargs):
            st = real_stat(path, *args, **kwargs)
            dev = st.st_dev + (1 if str(path).endswith("b") else 0)
            return types.SimpleNamespace(st_dev=dev)

        with mock.patch.object(scan.shutil, "disk_usage", return_value=usage), mock.patch.object(
            scan.os, "stat", side_effect=fake_stat
        ):
            gap = scan._gap(
                [{"path": self.path("a"), "bytes": 100}, {"path": self.path("b"), "bytes": 50}], scan._Ctx(None)
            )
        self.assertEqual(len(gap["volumes"]), 2)
        self.assertEqual(gap["unexplained_bytes"], (600 - 100) + (600 - 50))

    def test_top_lists_leaves_and_loose_file_rest_without_double_counting(self):
        mb = 1 << 20
        tree = {
            "children": [
                {
                    "path": "/r",
                    "bytes": 1000 * mb,
                    "apparent": False,
                    "children": [
                        {"path": "/r/a", "bytes": 600 * mb, "apparent": False, "children": []},
                        {"path": "/r/b", "bytes": 100 * mb, "apparent": False, "children": []},
                        {"path": "/r/cloud", "bytes": 0, "apparent": False, "children": [], "note": "cloud"},
                    ],
                }
            ]
        }
        rows = scan._top(tree)
        self.assertEqual(
            [(r["path"], r["kind"], r["bytes"] // mb) for r in rows],
            [("/r/a", "folder", 600), ("/r", "rest", 300), ("/r/b", "folder", 100)],
        )
        self.assertEqual(len(scan._top(tree, 2)), 2)


class Snapshots(Base):
    mock_snapshots = False

    def cmd(self, table):
        def fake(argv, timeout=30):
            return table.get(argv[0], (None, "", "not found: " + argv[0]))

        return mock.patch.object(scan, "_run_cmd", side_effect=fake)

    def test_tmutil_real_sample(self):
        out = "Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-20-224646.local (dataless)\n"
        with self.cmd({"tmutil": (0, out, "")}):
            snap = scan.read_snapshots()
        self.assertTrue(snap["available"])
        self.assertEqual(snap["items"], [{"name": "com.apple.TimeMachine.2026-10-20-224646.local", "date": "2026-10-20-224646"}])
        self.assertEqual(snap["count"], 1)

    def test_tmutil_failure_is_recorded_not_raised(self):
        with self.cmd({}):
            snap = scan.read_snapshots()
        self.assertFalse(snap["available"])
        self.assertIn("not found", snap["error"])

    def test_btrfs_lists_snapshots_and_records_permission_errors(self):
        self.os_kind = "linux"
        mounts = "/dev/sda1 /mnt/data\\040x btrfs rw 0 0\n/dev/sdb1 / ext4 rw 0 0\n/dev/sdc1 /home btrfs rw 0 0\n"
        listing = "ID 258 gen 9 cgen 9 top level 5 otime 2026-10-20 12:00:00 uuid abc path .snapshots/1/snapshot\n"
        table = {"btrfs": (0, listing, "")}

        def fake(argv, timeout=30):
            if argv[-1] == "/home":
                return 1, "", "ERROR: can't perform the search: Operation not permitted\n"
            return table["btrfs"]

        with mock.patch.object(scan, "_read_proc_mounts", return_value=mounts), mock.patch.object(
            scan.shutil, "which", return_value="/usr/bin/btrfs"
        ), mock.patch.object(scan, "_run_cmd", side_effect=fake):
            snap = scan.read_snapshots()
        self.assertTrue(snap["available"])
        self.assertEqual(
            snap["items"],
            [{"mount": "/mnt/data x", "id": 258, "path": ".snapshots/1/snapshot", "created": "2026-10-20 12:00:00"}],
        )
        self.assertIn("/home", snap["error"])

    def test_btrfs_absent_is_quiet(self):
        self.os_kind = "linux"
        with mock.patch.object(scan, "_read_proc_mounts", return_value="/dev/sdb1 / ext4 rw 0 0\n"), mock.patch.object(
            scan.shutil, "which", return_value=None
        ):
            snap = scan.read_snapshots()
        self.assertEqual((snap["available"], snap["items"], snap["error"]), (False, [], None))

    def test_vssadmin_parse_and_access_denied(self):
        self.os_kind = "windows"
        out = (
            "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n\n"
            "Shadow Copy Storage association\n"
            "   For volume: (C:)\\\\?\\Volume{abc}\\\n"
            "   Shadow Copy Storage volume: (C:)\\\\?\\Volume{abc}\\\n"
            "   Used Shadow Copy Storage space: 1.5 GB (0%)\n"
            "   Allocated Shadow Copy Storage space: 2 GB (0%)\n"
            "   Maximum Shadow Copy Storage space: 30,5 GB (3%)\n"
        )
        with self.cmd({"vssadmin": (0, out, "")}):
            snap = scan.read_snapshots()
        item = snap["items"][0]
        self.assertEqual((item["used_bytes"], item["allocated_bytes"]), (int(1.5 * 1024 ** 3), 2 * 1024 ** 3))
        self.assertEqual(item["maximum_bytes"], int(30.5 * 1024 ** 3))
        with self.cmd({"vssadmin": (1, "Error: Access is denied.\n", "")}):
            snap = scan.read_snapshots()
        self.assertFalse(snap["available"])
        self.assertIn("elevated", snap["error"])


class Run(Base):
    def test_basic_run_shape_and_json(self):
        write(self.path("root", "a", "x.bin"), 3 << 20)
        write(self.path("root", "b", "y.bin"), 2 << 20)
        result = scan.run(argparse.Namespace(roots=[self.path("root")], no_dua=False))
        json.dumps(result)
        self.assertEqual((result["tool"], result["exact"]), ("basic", False))
        self.assertTrue(result["label"].startswith("apparent (upper bound)"))
        self.assertEqual(result["roots"], [self.path("root")])
        self.assertEqual(result["tree"]["path"], "(roots)")
        self.assertEqual(result["read_bytes"], result["tree"]["bytes"])
        self.assertEqual(result["gap"]["read_bytes"], result["read_bytes"])
        # a temp folder is not a whole volume: the gap is what the roots do not cover, not "unexplained"
        self.assertEqual(result["gap"]["label"], "outside the scanned roots")
        self.assertTrue(result["gap"]["partial"])
        sizes = [t["bytes"] for t in result["top"]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertLessEqual(len(sizes), scan.TOP_N)
        self.assertEqual(result["top"][0]["path"], self.path("root", "a"))
        self.assertEqual(result["errors_total"], 0)

    def test_no_usable_root_is_a_controlled_error(self):
        with self.assertRaises(common.CorecleanerError) as cm:
            scan.run(argparse.Namespace(roots=[self.path("nope")], no_dua=False))
        self.assertEqual(cm.exception.code, common.EXIT_ERROR)
        self.assertEqual(cm.exception.details["dropped_roots"][0]["reason"], "not a directory")

    def test_scan_function_returns_the_tree_only(self):
        write(self.path("root", "a", "x.bin"), 2 << 20)
        tree = scan.scan([self.path("root")], use_dua=False)
        self.assertEqual(set(tree), {"path", "bytes", "apparent", "children"})
        self.assertEqual(tree["children"][0]["path"], self.path("root"))


class NoDeleteGuard(unittest.TestCase):
    def test_module_never_deletes(self):
        source = (SCRIPTS / "corecleaner_lib" / "scan.py").read_text(encoding="utf-8")
        for token in ("os.remove", "os.unlink", "unlink(", "rmtree", "os.rmdir", "os.rename", "shutil.move"):
            self.assertNotIn(token, source, token)


if __name__ == "__main__":
    unittest.main()
