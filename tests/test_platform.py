"""platform_info: check/free, case-sensitivity probe, Trash availability per OS.

Everything that writes does so inside tempfile.mkdtemp(); the real home, ~/.claude and ~/.codex are
never touched. Windows and Linux branches run through injected helpers (this suite runs on macOS).
"""

import ntpath
import os
import re
import shutil
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import common  # noqa: E402
from corecleaner_lib import platform_info as pi  # noqa: E402

POSIX = os.name == "posix"
IS_ROOT = POSIX and os.geteuid() == 0


class TempCase(unittest.TestCase):
    def tmp(self) -> str:
        path = tempfile.mkdtemp(prefix="corecleaner-test-")
        self.addCleanup(self._cleanup, path)
        return os.path.realpath(path)

    @staticmethod
    def _cleanup(path):  # tests may chmod dirs read-only; restore so removal works
        import shutil

        for root, dirs, _files in os.walk(path):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o700)
                except OSError:
                    pass
        shutil.rmtree(path, ignore_errors=True)


def ns(**kw):
    return types.SimpleNamespace(**kw)


# --------------------------------------------------------------------------- fake filesystem


class FakeFS:
    """Just enough of lstat/scandir to run the case probes against a chosen filesystem.

    entries: {path: (st_dev, st_ino, is_dir)}. insensitive=True resolves names case-folded.
    """

    def __init__(self, entries, insensitive):
        self.insensitive = insensitive
        self.entries = {self._key(p): v for p, v in entries.items()}

    def _key(self, p):
        return p.casefold() if self.insensitive else p

    def lstat(self, p):
        v = self.entries.get(self._key(p))
        if v is None:
            raise FileNotFoundError(p)
        return ns(st_dev=v[0], st_ino=v[1], st_mode=stat.S_IFDIR if v[2] else stat.S_IFREG)

    def scandir(self, d):
        kids = [p for p in self.entries if os.path.dirname(p) == self._key(d.rstrip("/") or "/") and p != self._key(d)]
        items = [
            ns(name=os.path.basename(p), stat=lambda follow_symlinks=True, p=p: self.lstat(p)) for p in kids
        ]
        cm = mock.MagicMock()
        cm.__enter__.return_value = iter(items)
        return cm

    def patch(self):
        return mock.patch.multiple(pi, _lstat=self.lstat, _scandir=self.scandir)


# --------------------------------------------------------------------------- basics


class OsKind(unittest.TestCase):
    def test_mapping(self):
        for plat, expected in [("darwin", "macos"), ("linux", "linux"), ("linux2", "linux"), ("win32", "windows"), ("freebsd14", "freebsd14")]:
            with self.subTest(plat), mock.patch.object(sys, "platform", plat):
                self.assertEqual(pi.os_kind(), expected)


class Arch(unittest.TestCase):
    def test_aliases(self):
        for machine, expected in [("arm64", "arm64"), ("aarch64", "arm64"), ("AMD64", "x86_64"), ("x86_64", "x86_64"), ("riscv64", "riscv64")]:
            with self.subTest(machine), mock.patch.object(pi.platform, "machine", return_value=machine), mock.patch.object(
                pi, "os_kind", return_value="linux"
            ):
                self.assertEqual(pi._arch()[0], expected)

    def test_rosetta_reports_native_arch(self):
        with mock.patch.object(pi.platform, "machine", return_value="x86_64"), mock.patch.object(
            pi, "os_kind", return_value="macos"
        ), mock.patch.object(pi, "_run", return_value="1\n"):
            arch, warnings = pi._arch()
        self.assertEqual(arch, "arm64")
        self.assertTrue(any("Rosetta" in w for w in warnings))

    def test_real_intel_mac_stays_x86(self):
        with mock.patch.object(pi.platform, "machine", return_value="x86_64"), mock.patch.object(
            pi, "os_kind", return_value="macos"
        ), mock.patch.object(pi, "_run", return_value=None):  # sysctl: unknown oid
            self.assertEqual(pi._arch(), ("x86_64", []))


class DuaTarget(TempCase):
    def test_targets(self):
        self.assertEqual(pi.dua_target("macos", "arm64"), "aarch64-apple-darwin")
        self.assertEqual(pi.dua_target("linux", "x86_64"), "x86_64-unknown-linux-musl")
        self.assertEqual(pi.dua_target("windows", "arm64"), "aarch64-pc-windows-msvc")
        self.assertIsNone(pi.dua_target("linux", "riscv64"))
        self.assertIsNone(pi.dua_target("freebsd14", "x86_64"))

    def test_supported_without_pins_file_uses_builtin_table(self):
        with mock.patch.object(pi, "_PINS", Path(self.tmp()) / "missing.tsv"):
            self.assertTrue(pi._arch_supported("macos", "arm64"))
            self.assertFalse(pi._arch_supported("linux", "riscv64"))

    def test_supported_only_when_target_is_pinned(self):
        pins = Path(self.tmp()) / "pins.tsv"
        pins.write_text("# target\turl\tsha256\tversion\naarch64-apple-darwin\thttps://x/a.tgz\tab12\t2.46.0\n\n")
        with mock.patch.object(pi, "_PINS", pins):
            self.assertTrue(pi._arch_supported("macos", "arm64"))
            self.assertFalse(pi._arch_supported("macos", "x86_64"))  # known target but not pinned
            self.assertFalse(pi._arch_supported("linux", "riscv64"))


class ToolVersions(unittest.TestCase):
    def test_version_parse(self):
        for out, expected in [
            ("git version 2.54.0 (Apple Git-157)\n", "2.54.0"),
            ("ripgrep 15.2.0\nfeatures:+pcre2\n", "15.2.0"),
            ("dua-cli 2.46.0", "2.46.0"),
            ("no digits here", None),
            ("", None),
        ]:
            with self.subTest(out), mock.patch.object(pi, "_run", return_value=out):
                self.assertEqual(pi._version_of("/x/tool"), expected)

    def test_run_failure_is_none(self):
        with mock.patch.object(pi, "_run", return_value=None):
            self.assertIsNone(pi._version_of("/x/tool"))

    def test_missing_tool(self):
        with mock.patch.object(pi.shutil, "which", return_value=None):
            self.assertEqual(pi._tool("git"), {"found": False, "version": None})

    def test_found_tool(self):
        with mock.patch.object(pi.shutil, "which", return_value="/opt/bin/rg"), mock.patch.object(
            pi, "os_kind", return_value="linux"
        ), mock.patch.object(pi, "_version_of", return_value="15.2.0"):
            self.assertEqual(pi._tool("rg"), {"found": True, "version": "15.2.0"})

    def test_found_but_not_runnable_is_not_found(self):
        with mock.patch.object(pi.shutil, "which", return_value="/opt/bin/rg"), mock.patch.object(
            pi, "os_kind", return_value="linux"
        ), mock.patch.object(pi, "_version_of", return_value=None):
            self.assertEqual(pi._tool("rg"), {"found": False, "version": None})

    def test_apple_git_shim_without_clt_is_never_executed(self):
        with mock.patch.object(pi.shutil, "which", return_value="/usr/bin/git"), mock.patch.object(
            pi, "os_kind", return_value="macos"
        ), mock.patch.object(pi, "_run", return_value=None) as run, mock.patch.object(pi, "_version_of") as version:
            self.assertEqual(pi._tool("git"), {"found": False, "version": None})
        run.assert_called_once_with(["/usr/bin/xcode-select", "-p"])
        version.assert_not_called()

    def test_apple_git_with_clt_runs(self):
        with mock.patch.object(pi.shutil, "which", return_value="/usr/bin/git"), mock.patch.object(
            pi, "os_kind", return_value="macos"
        ), mock.patch.object(pi, "_run", return_value="/Library/Developer/CommandLineTools\n"), mock.patch.object(
            pi, "_version_of", return_value="2.54.0"
        ):
            self.assertEqual(pi._tool("git"), {"found": True, "version": "2.54.0"})


class FindDua(TempCase):
    def _exe(self, directory, name="dua"):
        path = os.path.join(directory, name)
        Path(path).write_text("#!/bin/sh\n")
        os.chmod(path, 0o755)
        return path

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_managed_copy_wins_over_path(self):
        state, other, home = self.tmp(), self.tmp(), self.tmp()
        os.makedirs(os.path.join(home, ".local", "bin"))
        managed = self._exe(os.path.join(home, ".local", "bin"))
        on_path = self._exe(other)
        with mock.patch.dict(os.environ, {common.STATE_ENV: state, "HOME": home}), mock.patch.object(
            pi.shutil, "which", return_value=on_path
        ), mock.patch.object(pi, "_version_of", return_value="2.46.0"):
            self.assertEqual(
                pi._find_dua("macos"), {"found": True, "path": managed, "version": "2.46.0", "managed": True}
            )

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_path_copy_is_not_managed(self):
        state, other = self.tmp(), self.tmp()
        on_path = self._exe(other)
        # HOME pinned: a dua already installed in the real ~/.local/bin must not be found as the managed copy.
        with mock.patch.dict(os.environ, {common.STATE_ENV: state, "HOME": self.tmp()}), mock.patch.object(
            pi.shutil, "which", return_value=on_path
        ), mock.patch.object(pi, "_version_of", return_value="2.46.0"):
            got = pi._find_dua("linux")
        self.assertEqual((got["found"], got["path"], got["managed"]), (True, on_path, False))

    def test_absent(self):
        state = self.tmp()
        with mock.patch.dict(os.environ, {common.STATE_ENV: state, "HOME": self.tmp()}), mock.patch.object(
            pi.shutil, "which", return_value=None
        ):
            self.assertEqual(pi._find_dua("linux"), {"found": False, "path": None, "version": None, "managed": False})
        self.assertEqual(os.listdir(state), [], "looking for dua must not write into the state dir")

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_binary_that_does_not_run_is_not_found_but_reported(self):
        other = self.tmp()
        on_path = self._exe(other)
        with mock.patch.dict(os.environ, {common.STATE_ENV: self.tmp(), "HOME": self.tmp()}), mock.patch.object(
            pi.shutil, "which", return_value=on_path
        ), mock.patch.object(pi, "_version_of", return_value=None):
            got = pi._find_dua("linux")
        self.assertEqual((got["found"], got["path"]), (False, on_path))

    def test_windows_looks_for_exe(self):
        state = self.tmp()
        with mock.patch.dict(os.environ, {common.STATE_ENV: state}), mock.patch.object(
            pi.shutil, "which", return_value=None
        ), mock.patch.object(pi.os.path, "isfile") as isfile:
            isfile.return_value = False
            pi._find_dua("windows")
        self.assertEqual(isfile.call_args_list[0][0][0], os.path.join(state, "bin", "dua.exe"))


class StateDirMirror(TempCase):
    """_state_dir_path is a non-creating copy of common.state_dir; they must not drift."""

    def test_env_override(self):
        base = self.tmp()
        target = os.path.join(base, "st")
        with mock.patch.dict(os.environ, {common.STATE_ENV: target}):
            self.assertEqual(pi._state_dir_path(), str(common.state_dir()))

    @unittest.skipUnless(POSIX, "HOME based")
    def test_default_posix(self):
        home = self.tmp()
        env = {"HOME": home}
        with mock.patch.dict(os.environ, env), mock.patch.dict(os.environ, clear=False):
            os.environ.pop(common.STATE_ENV, None)
            self.assertEqual(pi._state_dir_path(), str(common.state_dir()))
        self.assertEqual(pi._state_dir_path.__name__, "_state_dir_path")

    def test_windows_branch(self):
        base = self.tmp()
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": base}), mock.patch.object(sys, "platform", "win32"):
            os.environ.pop(common.STATE_ENV, None)
            self.assertEqual(pi._state_dir_path(), str(common.state_dir()))


# --------------------------------------------------------------------------- mount parsing


class MountParsing(unittest.TestCase):
    MAC = (
        "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"
        "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n"
        "/dev/disk4s3 on /Volumes/MARKS FAT32 (msdos, local, nodev, nosuid, noowners, noatime, fskit)\n"
        "/dev/disk9s1 on /Volumes/Photos (1) (apfs, local, journaled)\n"
        "//user@nas._smb._tcp.local/share on /Volumes/share (smbfs, nodev, nosuid, mounted by user)\n"
    )

    def test_mac(self):
        rows = {r["mount"]: r for r in pi._parse_mac_mounts(self.MAC)}
        self.assertEqual(rows["/"]["fs"], "apfs")
        self.assertIn("read-only", rows["/"]["opts"])
        self.assertEqual(rows["/System/Volumes/Data/home"]["device"], "map auto_home")
        self.assertEqual(rows["/Volumes/MARKS FAT32"]["fs"], "msdos")
        self.assertIn("/Volumes/Photos (1)", rows)  # parentheses inside the mount point
        self.assertEqual(rows["/Volumes/Photos (1)"]["fs"], "apfs")
        self.assertEqual(rows["/Volumes/share"]["fs"], "smbfs")
        self.assertNotIn("local", rows["/Volumes/share"]["opts"])

    def test_linux_with_octal_escapes(self):
        text = (
            "/dev/sda2 / ext4 rw,relatime 0 0\n"
            "/dev/sdb1 /media/me/USB\\040DRIVE vfat rw,nosuid 0 0\n"
            "server:/export /mnt/nas nfs4 ro,vers=4.2 0 0\n"
            "tmpfs /run tmpfs rw 0 0\n"
            "garbage\n"
        )
        rows = {r["mount"]: r for r in pi._parse_linux_mounts(text)}
        self.assertEqual(set(rows), {"/", "/media/me/USB DRIVE", "/mnt/nas", "/run"})
        self.assertEqual(rows["/media/me/USB DRIVE"]["fs"], "vfat")
        self.assertIn("ro", rows["/mnt/nas"]["opts"])

    def test_df_mount(self):
        out = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "map auto_home 1000 10 990 2% /System/Volumes/Data/some dir\n"
        )
        with mock.patch.object(pi.shutil, "which", return_value="/bin/df"), mock.patch.object(pi, "_run", return_value=out):
            self.assertEqual(pi._df_mount("/x"), "/System/Volumes/Data/some dir")

    def test_df_mount_failure(self):
        with mock.patch.object(pi.shutil, "which", return_value="/bin/df"), mock.patch.object(pi, "_run", return_value=None):
            self.assertIsNone(pi._df_mount("/x"))
        with mock.patch.object(pi.shutil, "which", return_value=None):
            self.assertIsNone(pi._df_mount("/x"))


class VolumeLookup(TempCase):
    MOUNTS = [
        {"device": "/dev/a", "mount": "/", "fs": "ext4", "opts": {"rw"}},
        {"device": "/dev/b", "mount": "/data", "fs": "ext4", "opts": {"rw"}},
        {"device": "/dev/c", "mount": "/data/deep", "fs": "xfs", "opts": {"ro"}},
    ]

    def test_df_decides_when_available(self):
        real = self.tmp()
        with mock.patch.object(pi, "_mounts", return_value=self.MOUNTS), mock.patch.object(
            pi, "_df_mount", return_value="/data"
        ):
            vol = pi._volume(real)
        self.assertEqual((vol["mount"], vol["fs"]), ("/data", "ext4"))

    def test_longest_prefix_fallback(self):
        real = self.tmp()
        mounts = [dict(m) for m in self.MOUNTS]
        mounts[2]["mount"] = real  # the temp dir itself is a mount point
        with mock.patch.object(pi, "_mounts", return_value=mounts), mock.patch.object(pi, "_df_mount", return_value=None):
            vol = pi._volume(os.path.join(real, "child", "missing"))
        self.assertEqual((vol["mount"], vol["fs"]), (real, "xfs"))

    def test_unknown_is_none(self):
        with mock.patch.object(pi, "_mounts", return_value=[]), mock.patch.object(pi, "_df_mount", return_value=None):
            self.assertIsNone(pi._volume(self.tmp()))
        self.assertIsNone(pi._volume("/definitely/not/here") if not os.path.exists("/") else None)

    def test_is_under(self):
        self.assertTrue(pi._is_under("/a/b", "/"))
        self.assertTrue(pi._is_under("/a/b", "/a"))
        self.assertTrue(pi._is_under("/a", "/a"))
        self.assertFalse(pi._is_under("/ab", "/a"))

    def test_network_and_read_only(self):
        self.assertTrue(pi._is_network("linux", "nfs4", set()))
        self.assertTrue(pi._is_network("linux", "fuse.sshfs", set()))
        self.assertFalse(pi._is_network("linux", "ext4", set()))
        self.assertTrue(pi._is_network("macos", "smbfs", {"nodev"}))
        self.assertTrue(pi._is_network("macos", "apfs", {"journaled"}))  # no "local" flag
        self.assertFalse(pi._is_network("macos", "apfs", {"local"}))
        self.assertFalse(pi._is_network("macos", None, set()))
        self.assertTrue(pi._is_read_only("macos", {"read-only"}))
        self.assertTrue(pi._is_read_only("linux", {"ro"}))
        self.assertFalse(pi._is_read_only("linux", {"rw"}))


# --------------------------------------------------------------------------- case sensitivity


class CaseProbeFakeFS(unittest.TestCase):
    """Behavior of the probes against simulated filesystems."""

    TREE = {
        "/": (1, 1, True),
        "/Users": (1, 2, True),
        "/Users/Marks": (1, 3, True),
        "/Users/Marks/Code": (1, 4, True),
        "/Users/Marks/123": (1, 5, True),
        "/Volumes": (1, 6, True),
        "/Volumes/USB": (2, 1, True),  # mount point: the entry is resolved by volume 1, content is volume 2
        "/Volumes/USB/Photos": (2, 2, True),
    }

    def _check(self, insensitive, path, expected):
        fs = FakeFS(self.TREE, insensitive)
        with fs.patch(), mock.patch.object(pi, "_existing_ancestor", return_value=path), mock.patch.object(
            pi, "_metadata_probe", return_value=None
        ), mock.patch.object(pi, "_state_dir_probe", return_value=None):
            self.assertEqual(pi.is_case_insensitive(path), expected, path)

    def test_insensitive_fs(self):
        self._check(True, "/Users/Marks/Code", True)

    def test_sensitive_fs(self):
        self._check(False, "/Users/Marks/Code", False)

    def test_digits_only_leaf_falls_back_to_a_lettered_parent(self):
        self._check(True, "/Users/Marks/123", True)
        self._check(False, "/Users/Marks/123", False)

    def test_two_distinct_entries_differing_by_case_mean_sensitive(self):
        tree = dict(self.TREE)
        tree["/Users/Marks/code"] = (1, 99, True)  # a sibling "code" next to "Code"
        fs = FakeFS(tree, insensitive=False)
        with fs.patch():
            self.assertFalse(pi._case_pair("/Users/Marks", "Code") is True)

    def test_mount_point_name_is_not_evidence_about_the_mounted_volume(self):
        # /Volumes is volume 1 (insensitive); /Volumes/USB/Photos lives in volume 2 (sensitive).
        # Looking up "usb" in /Volumes says nothing about volume 2, so the probe must use "Photos".
        entries = dict(self.TREE)
        fs = FakeFS(entries, insensitive=True)
        real = "/Volumes/USB"  # target is the mount point itself: no component qualifies
        with fs.patch():
            self.assertIsNone(pi._components_probe(real, 2))
        # An entry inside the volume does qualify.
        with fs.patch():
            self.assertTrue(pi._entries_probe(real, 2))

    def test_entries_probe_skips_other_volumes_and_symbols(self):
        tree = {
            "/m": (7, 1, True),
            "/m/123": (7, 2, True),
            "/m/foreign": (8, 3, True),  # other device: ignored
            "/m/Docs": (7, 4, True),
        }
        fs = FakeFS(tree, insensitive=False)
        with fs.patch():
            self.assertFalse(pi._entries_probe("/m", 7))

    def test_nothing_to_compare_fails_closed(self):
        tree = {"/": (1, 1, True), "/123": (1, 2, True)}
        fs = FakeFS(tree, insensitive=False)
        with fs.patch(), mock.patch.object(pi, "_existing_ancestor", return_value="/123"), mock.patch.object(
            pi, "_metadata_probe", return_value=None
        ), mock.patch.object(pi, "_state_dir_probe", return_value=None):
            self.assertTrue(pi.is_case_insensitive("/123"))

    def test_path_that_does_not_exist_anywhere_fails_closed(self):
        with mock.patch.object(pi, "_existing_ancestor", return_value=None):
            self.assertTrue(pi.is_case_insensitive("/nope"))

    def test_names_without_ascii_letters_are_skipped(self):
        fs = FakeFS({"/p": (1, 1, True), "/p/日本": (1, 2, True), "/p/123": (1, 3, True)}, insensitive=False)
        with fs.patch():
            self.assertIsNone(pi._case_pair("/p", "日本"))
            self.assertIsNone(pi._case_pair("/p", "123"))

    def test_lookup_error_is_none_not_a_verdict(self):
        def boom(p):
            raise PermissionError(p)

        with mock.patch.object(pi, "_lstat", boom):
            self.assertIsNone(pi._case_pair("/p", "Abc"))


class CaseProbeRealFS(TempCase):
    """Compare against what the host filesystem actually does."""

    def _truth(self, directory):
        probe = os.path.join(directory, "CaseTruth.txt")
        Path(probe).write_text("x")
        swapped = os.path.join(directory, "cASEtRUTH.TXT")
        return os.path.exists(swapped) and os.path.samefile(probe, swapped)

    def test_matches_host_behavior(self):
        d = self.tmp()
        self.assertEqual(pi.is_case_insensitive(d), self._truth(d))

    def test_path_below_a_missing_tail(self):
        d = self.tmp()
        self.assertEqual(pi.is_case_insensitive(os.path.join(d, "no", "such", "tail")), self._truth(d))

    def test_file_path(self):
        d = self.tmp()
        f = os.path.join(d, "Some.File")
        Path(f).write_text("x")
        self.assertEqual(pi.is_case_insensitive(f), self._truth(d))

    @unittest.skipUnless(sys.platform == "darwin", "pathconf case flag is macOS only")
    def test_macos_pathconf_agrees_with_behavior(self):
        d = self.tmp()
        self.assertEqual(pi._metadata_probe(d), self._truth(d))

    def test_state_dir_probe_matches_and_leaves_nothing_behind(self):
        state = self.tmp()
        with mock.patch.dict(os.environ, {common.STATE_ENV: os.path.join(state, "st")}):
            dev = os.lstat(state).st_dev
            self.assertEqual(pi._state_dir_probe(dev), self._truth(state))
            self.assertEqual(os.listdir(os.path.join(state, "st")), [])

    def test_state_dir_probe_refuses_other_volume(self):
        state = self.tmp()
        with mock.patch.dict(os.environ, {common.STATE_ENV: os.path.join(state, "st")}):
            self.assertIsNone(pi._state_dir_probe(os.lstat(state).st_dev + 12345))

    def test_state_dir_probe_survives_unusable_state_dir(self):
        with mock.patch.object(common, "state_dir", side_effect=common.CorecleanerError(1, "nope")):
            self.assertIsNone(pi._state_dir_probe(1))


# --------------------------------------------------------------------------- Trash: macOS


class TrashMacOS(TempCase):
    def _tools(self, with_trash=True, with_osascript=True):
        base = self.tmp()
        trash, osa = os.path.join(base, "trash"), os.path.join(base, "osascript")
        for path, wanted in ((trash, with_trash), (osa, with_osascript)):
            if wanted:
                Path(path).write_text("#!/bin/sh\n")
                os.chmod(path, 0o755)
        return mock.patch.multiple(pi, _MAC_TRASH=trash, _MAC_OSASCRIPT=osa), trash

    def _vol(self, mount, fs="apfs", opts=("local", "journaled")):
        return {"mount": mount, "fs": fs, "opts": set(opts)}

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_prefers_usr_bin_trash_on_home_volume(self):
        patch, trash = self._tools()
        mount = self.tmp()
        with patch, mock.patch.object(pi, "_home_mount", return_value=mount):
            self.assertEqual(pi._trash_macos(self._vol(mount)), (True, trash))

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_falls_back_to_osascript(self):
        patch, _ = self._tools(with_trash=False)
        mount = self.tmp()
        with patch, mock.patch.object(pi, "_home_mount", return_value=mount):
            self.assertEqual(pi._trash_macos(self._vol(mount)), (True, "osascript"))

    def test_no_tool_means_no(self):
        patch, _ = self._tools(False, False)
        with patch:
            ok, why = pi._trash_macos(self._vol(self.tmp()))
        self.assertFalse(ok)
        self.assertIn("no Trash tool", why)

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_network_and_read_only_volumes_are_refused(self):
        patch, _ = self._tools()
        mount = self.tmp()
        with patch, mock.patch.object(pi, "_home_mount", return_value=mount):
            ok, why = pi._trash_macos(self._vol(mount, "smbfs", ("nodev",)))
            self.assertFalse(ok)
            self.assertIn("network", why)
            ok, why = pi._trash_macos(self._vol(mount, "apfs", ("local", "read-only")))
            self.assertFalse(ok)
            self.assertIn("read-only", why)

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_other_volume_needs_dot_trashes(self):
        patch, trash = self._tools()
        mount = self.tmp()
        with patch, mock.patch.object(pi, "_home_mount", return_value="/somewhere/else"):
            ok, why = pi._trash_macos(self._vol(mount))
            self.assertFalse(ok)
            self.assertIn(".Trashes", why)
            os.mkdir(os.path.join(mount, ".Trashes"))
            self.assertEqual(pi._trash_macos(self._vol(mount)), (True, trash))

    @unittest.skipUnless(POSIX, "needs POSIX exec bits")
    def test_dot_trashes_symlink_does_not_count(self):
        patch, _ = self._tools()
        mount, elsewhere = self.tmp(), self.tmp()
        os.symlink(elsewhere, os.path.join(mount, ".Trashes"))
        with patch, mock.patch.object(pi, "_home_mount", return_value="/somewhere/else"):
            self.assertFalse(pi._trash_macos(self._vol(mount))[0])


# --------------------------------------------------------------------------- Trash: Linux


@unittest.skipUnless(POSIX, "Linux logic uses uid and mode bits")
class TrashLinux(TempCase):
    UID = 4242

    def _which(self, *present):
        return mock.patch.object(pi.shutil, "which", side_effect=lambda n: "/usr/bin/" + n if n in present else None)

    def _vol(self, mount, fs="ext4", opts=("rw",)):
        return {"mount": mount, "fs": fs, "opts": set(opts)}

    def test_topdir_spec_shared_trash_with_user_dir(self):
        top = self.tmp()
        shared = os.path.join(top, ".Trash")
        os.mkdir(shared)
        os.chmod(shared, 0o1777)
        os.mkdir(os.path.join(shared, str(self.UID)))
        ok, why = pi._linux_topdir_trash(top, self.UID)
        self.assertTrue(ok)
        self.assertIn(".Trash/%d" % self.UID, why)

    def test_topdir_shared_trash_without_sticky_bit_is_ignored(self):
        top = self.tmp()
        shared = os.path.join(top, ".Trash")
        os.mkdir(shared)
        os.chmod(shared, 0o777)
        os.mkdir(os.path.join(shared, str(self.UID)))
        ok, why = pi._linux_topdir_trash(top, self.UID)
        self.assertTrue(ok)  # falls through to .Trash-uid, creatable in the writable topdir
        self.assertNotIn(".Trash/%d" % self.UID, why.replace(".Trash/%d can" % self.UID, ""))
        self.assertIn(".Trash-%d" % self.UID, why)

    def test_topdir_shared_trash_symlink_is_ignored(self):
        top, other = self.tmp(), self.tmp()
        os.chmod(other, 0o1777)
        os.symlink(other, os.path.join(top, ".Trash"))
        ok, why = pi._linux_topdir_trash(top, self.UID)
        self.assertTrue(ok)
        self.assertIn(".Trash-%d" % self.UID, why)

    def test_topdir_existing_user_trash(self):
        top = self.tmp()
        os.mkdir(os.path.join(top, ".Trash-%d" % self.UID))
        self.assertEqual(pi._linux_topdir_trash(top, self.UID), (True, ".Trash-%d" % self.UID))

    @unittest.skipIf(IS_ROOT, "root can write anywhere")
    def test_topdir_unwritable_without_trash_dirs_means_no(self):
        top = self.tmp()
        os.chmod(top, 0o555)
        ok, why = pi._linux_topdir_trash(top, self.UID)
        self.assertFalse(ok)
        self.assertIn("no usable Trash", why)

    def test_no_tool(self):
        with self._which():
            ok, why = pi._trash_linux(self._vol(self.tmp()))
        self.assertFalse(ok)
        self.assertIn("trash-put", why)

    def test_home_volume_uses_gio_then_trash_put(self):
        data = self.tmp()
        mount = "/mnt/home"
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": data}), mock.patch.object(pi, "_df_mount", return_value=mount):
            with self._which("gio", "trash-put"):
                self.assertEqual(pi._trash_linux(self._vol(mount)), (True, "gio"))
            with self._which("trash-put"):
                self.assertEqual(pi._trash_linux(self._vol(mount)), (True, "trash-put"))

    def test_relative_xdg_data_home_is_ignored(self):
        home = self.tmp()
        seen = []

        def fake_ancestor(p):
            seen.append(p)
            return home

        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "relative/dir", "HOME": home}), mock.patch.object(
            pi, "_existing_ancestor", side_effect=fake_ancestor
        ), mock.patch.object(pi, "_df_mount", return_value="/mnt/home"), self._which("gio"):
            pi._trash_linux(self._vol("/mnt/home"))
        self.assertEqual(seen[0], os.path.join(home, ".local", "share"))

    def test_other_volume_uses_topdir_rules(self):
        data, top = self.tmp(), self.tmp()
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": data}), mock.patch.object(
            pi, "_df_mount", return_value="/mnt/home"
        ), self._which("gio"):
            self.assertEqual(pi._trash_linux(self._vol(top)), (True, "gio"))  # writable topdir: .Trash-uid creatable

    @unittest.skipIf(IS_ROOT, "root can write anywhere")
    def test_other_volume_read_only_directory_is_refused(self):
        data, top = self.tmp(), self.tmp()
        os.chmod(top, 0o555)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": data}), mock.patch.object(
            pi, "_df_mount", return_value="/mnt/home"
        ), self._which("gio"):
            ok, why = pi._trash_linux(self._vol(top))
        self.assertFalse(ok)
        self.assertIn("no usable Trash", why)

    def test_network_and_read_only_mounts_are_refused(self):
        top = self.tmp()
        with self._which("gio"):
            ok, why = pi._trash_linux(self._vol(top, "nfs4"))
            self.assertFalse(ok)
            self.assertIn("network", why)
            ok, why = pi._trash_linux(self._vol(top, "ext4", ("ro",)))
            self.assertFalse(ok)
            self.assertIn("read-only", why)

    @unittest.skipIf(IS_ROOT, "root can write anywhere")
    def test_home_trash_not_writable(self):
        data = self.tmp()
        os.chmod(data, 0o555)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": data}), mock.patch.object(
            pi, "_df_mount", return_value="/mnt/home"
        ), self._which("gio"):
            ok, why = pi._trash_linux(self._vol("/mnt/home"))
        self.assertFalse(ok)
        self.assertIn("cannot write", why)


# --------------------------------------------------------------------------- Trash: Windows (beta, injected)


class TrashWindows(unittest.TestCase):
    GUID = "{1b2c3d4e-0000-4abc-9def-0123456789ab}"

    def _patched(self, root="C:\\", dtype=3, guid=GUID, subkeys=(), dwords=None, powershell=True):
        dwords = dwords or {}

        def reg_dword(hive, key, name):
            return dwords.get((hive, key, name))

        return mock.patch.multiple(
            pi,
            _win_drive_root=mock.Mock(return_value=root),
            _win_drive_type=mock.Mock(return_value=dtype),
            _win_volume_guid=mock.Mock(return_value=guid),
            _reg_subkeys=mock.Mock(return_value=list(subkeys)),
            _reg_dword=mock.Mock(side_effect=reg_dword),
        ), mock.patch.object(pi.shutil, "which", side_effect=lambda n: "C:\\ps.exe" if powershell and n == "powershell" else None)

    def _run(self, **kw):
        a, b = self._patched(**kw)
        with a, b:
            return pi._trash_windows("C:\\Users\\x")

    def test_fixed_drive_with_default_settings_is_ok(self):
        self.assertEqual(self._run(), (True, "recycle-bin"))

    def test_removable_and_network_drives_are_refused(self):
        for dtype in (2, 4, 5, 6):
            with self.subTest(dtype):
                ok, why = self._run(dtype=dtype)
                self.assertFalse(ok)
                self.assertIn("not a fixed", why)

    def test_unc_path_is_refused(self):
        ok, why = self._run(root=None)
        self.assertFalse(ok)
        self.assertIn("drive letter", why)

    def test_unknown_volume_is_refused(self):
        self.assertFalse(self._run(guid=None)[0])

    def test_no_powershell_is_refused(self):
        ok, why = self._run(powershell=False)
        self.assertFalse(ok)
        self.assertIn("PowerShell", why)

    def test_nuke_on_delete_for_this_volume(self):
        key = pi._BITBUCKET_VOLUME + "\\" + self.GUID.upper()
        ok, why = self._run(subkeys=[self.GUID.upper()], dwords={("HKCU", key, "NukeOnDelete"): 1})
        self.assertFalse(ok)
        self.assertIn("NukeOnDelete", why)

    def test_nuke_on_delete_zero_or_other_volume_is_fine(self):
        key = pi._BITBUCKET_VOLUME + "\\" + self.GUID
        self.assertTrue(self._run(subkeys=[self.GUID], dwords={("HKCU", key, "NukeOnDelete"): 0})[0])
        other = "{ffffffff-0000-4abc-9def-0123456789ab}"
        okey = pi._BITBUCKET_VOLUME + "\\" + other
        self.assertTrue(self._run(subkeys=[other], dwords={("HKCU", okey, "NukeOnDelete"): 1})[0])

    def test_group_policy_no_recycle_files(self):
        for hive in ("HKCU", "HKLM"):
            with self.subTest(hive):
                ok, why = self._run(dwords={(hive, pi._EXPLORER_POLICY, "NoRecycleFiles"): 1})
                self.assertFalse(ok)
                self.assertIn("NoRecycleFiles", why)

    def test_drive_root_parsing(self):
        with mock.patch.object(pi.os, "path", ntpath):
            self.assertEqual(pi._win_drive_root("C:\\Users\\x"), "C:\\")
            self.assertEqual(pi._win_drive_root("\\\\?\\D:\\data"), "D:\\")
            self.assertIsNone(pi._win_drive_root("\\\\?\\UNC\\srv\\share\\x"))
            self.assertIsNone(pi._win_drive_root("\\\\srv\\share\\x"))

    def test_registry_helpers_with_a_fake_winreg(self):
        class Key:
            def __init__(self, name):
                self.name = name

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        tree = {
            "HKCU\\k": {"sub": ["{A}", "{B}"], "values": {"NukeOnDelete": 1}},
            "HKCU\\empty": {"sub": [], "values": {"S": "text"}},
        }

        def open_key(root, sub):
            name = "%s\\%s" % (root, sub)
            if name not in tree:
                raise FileNotFoundError(name)
            return Key(name)

        def enum_key(key, i):
            subs = tree[key.name]["sub"]
            if i >= len(subs):
                raise OSError(259, "no more items")
            return subs[i]

        def query(key, name):
            vals = tree[key.name]["values"]
            if name not in vals:
                raise FileNotFoundError(name)
            return vals[name], 4

        fake = types.SimpleNamespace(
            HKEY_CURRENT_USER="HKCU", HKEY_LOCAL_MACHINE="HKLM", OpenKey=open_key, EnumKey=enum_key, QueryValueEx=query
        )
        with mock.patch.dict(sys.modules, {"winreg": fake}):
            self.assertEqual(pi._reg_subkeys("HKCU", "k"), ["{A}", "{B}"])
            self.assertEqual(pi._reg_subkeys("HKCU", "missing"), [])
            self.assertEqual(pi._reg_dword("HKCU", "k", "NukeOnDelete"), 1)
            self.assertIsNone(pi._reg_dword("HKCU", "k", "Absent"))
            self.assertIsNone(pi._reg_dword("HKCU", "missing", "NukeOnDelete"))
            self.assertIsNone(pi._reg_dword("HKCU", "empty", "S"))  # not a DWORD

    def test_registry_error_other_than_missing_means_unknown_means_no(self):
        with mock.patch.object(pi, "os_kind", return_value="windows"), mock.patch.object(
            pi, "_trash_windows", side_effect=PermissionError(13, "denied")
        ):
            ok, why = pi.trash_available("C:\\x")
        self.assertFalse(ok)
        self.assertIn("cannot determine", why)

    def test_windows_volumes_list(self):
        with mock.patch.multiple(
            pi,
            _win_drives=mock.Mock(return_value=["A:\\", "C:\\", "D:\\", "Z:\\"]),
            _win_drive_type=mock.Mock(side_effect=lambda r: {"A:\\": 5, "C:\\": 3, "D:\\": 2, "Z:\\": 4}[r]),
            _win_fs_name=mock.Mock(return_value="NTFS"),
            _trash_windows=mock.Mock(side_effect=lambda r: (r == "C:\\", "recycle-bin" if r == "C:\\" else "no")),
            is_case_insensitive=mock.Mock(return_value=True),
        ), mock.patch.object(pi.shutil, "disk_usage", return_value=(100, 40, 60)):
            rows = pi._windows_volumes()
        self.assertEqual([r["mount"] for r in rows], ["C:\\", "D:\\", "Z:\\"])  # CD-ROM skipped
        self.assertEqual([r["trash"] for r in rows], [True, False, False])
        self.assertEqual(rows[0]["fs"], "NTFS")


# --------------------------------------------------------------------------- trash_available dispatch


class TrashDispatch(unittest.TestCase):
    def test_unknown_os_is_no(self):
        with mock.patch.object(pi, "os_kind", return_value="freebsd14"):
            ok, why = pi.trash_available("/x")
        self.assertFalse(ok)
        self.assertIn("unsupported", why)

    def test_unidentifiable_volume_is_no(self):
        with mock.patch.object(pi, "os_kind", return_value="linux"), mock.patch.object(pi, "_volume", return_value=None):
            ok, why = pi.trash_available("/x")
        self.assertFalse(ok)
        self.assertIn("cannot identify", why)

    def test_oserror_means_no(self):
        with mock.patch.object(pi, "os_kind", return_value="macos"), mock.patch.object(
            pi, "_volume", side_effect=PermissionError(13, "Permission denied")
        ):
            ok, why = pi.trash_available("/x")
        self.assertFalse(ok)
        self.assertIn("Permission denied", why)

    @unittest.skipUnless(sys.platform == "darwin" and os.path.exists(pi._MAC_TRASH), "macOS 15+ host")
    def test_real_mac_home_volume(self):
        d = tempfile.mkdtemp(prefix="corecleaner-test-")
        self.addCleanup(shutil.rmtree, d, True)
        home_vol = pi._home_mount()
        if pi._volume(d)["mount"] != home_vol:
            self.skipTest("TMPDIR is not on the home volume")
        self.assertEqual(pi.trash_available(d), (True, pi._MAC_TRASH))

    @unittest.skipUnless(sys.platform == "darwin", "macOS host")
    def test_real_mac_sealed_system_volume_is_no(self):
        ok, why = pi.trash_available("/System/Library")
        self.assertFalse(ok)


# --------------------------------------------------------------------------- check / free / run


class PosixVolumes(unittest.TestCase):
    MOUNTS = [
        {"device": "/dev/disk3s1s1", "mount": "/", "fs": "apfs", "opts": {"sealed", "local", "read-only"}},
        {"device": "/dev/disk3s5", "mount": "/System/Volumes/Data", "fs": "apfs", "opts": {"local", "nobrowse"}},
        {"device": "devfs", "mount": "/dev", "fs": "devfs", "opts": {"local"}},
        {"device": "/dev/disk4s3", "mount": "/Volumes/USB", "fs": "msdos", "opts": {"local"}},
        {"device": "/dev/disk5s3", "mount": "/Volumes/Rec", "fs": "apfs", "opts": {"local", "nobrowse"}},
        {"device": "//nas/share", "mount": "/Volumes/share", "fs": "smbfs", "opts": {"nodev"}},
        {"device": "/dev/disk4s3", "mount": "/Volumes/USB", "fs": "msdos", "opts": {"local"}},  # duplicate
    ]

    def _run(self, kind, mounts, home_mount, **extra):
        usage = mock.Mock(return_value=(1000, 400, 600))
        patched = {"_volume": mock.Mock(return_value=None), **extra}
        trash = mock.Mock(side_effect=lambda k, p, vol: (vol["fs"] != "smbfs", "tool" if vol["fs"] != "smbfs" else "network"))
        with mock.patch.object(pi, "_mounts", return_value=mounts), mock.patch.object(
            pi, "_home_mount", return_value=home_mount
        ), mock.patch.object(pi.shutil, "disk_usage", usage), mock.patch.object(
            pi, "is_case_insensitive", return_value=True
        ), mock.patch.object(pi, "_trash_for", trash), mock.patch.multiple(pi, **patched):
            return pi._posix_volumes(kind)

    def test_macos_filtering_and_home_exception(self):
        rows = self._run("macos", self.MOUNTS, "/System/Volumes/Data")
        self.assertEqual([r["mount"] for r in rows], ["/System/Volumes/Data", "/Volumes/USB", "/Volumes/share"])
        by = {r["mount"]: r for r in rows}
        self.assertTrue(by["/Volumes/USB"]["trash"])
        self.assertFalse(by["/Volumes/share"]["trash"])
        self.assertEqual(by["/Volumes/share"]["trash_detail"], "network")
        self.assertEqual(set(rows[0]), {"mount", "fs", "total_bytes", "free_bytes", "case_insensitive", "trash", "trash_detail"})

    def test_linux_pseudo_and_read_only_dropped(self):
        mounts = [
            {"device": "/dev/sda1", "mount": "/", "fs": "ext4", "opts": {"rw"}},
            {"device": "proc", "mount": "/proc", "fs": "proc", "opts": {"rw"}},
            {"device": "tmpfs", "mount": "/run", "fs": "tmpfs", "opts": {"rw"}},
            {"device": "/dev/loop1", "mount": "/snap/x", "fs": "squashfs", "opts": {"ro"}},
            {"device": "/dev/sdb1", "mount": "/media/u/ro", "fs": "ext4", "opts": {"ro"}},
            {"device": "/dev/sdb2", "mount": "/media/u/rw", "fs": "vfat", "opts": {"rw"}},
        ]
        rows = self._run("linux", mounts, "/")
        self.assertEqual([r["mount"] for r in rows], ["/", "/media/u/rw"])

    def test_home_volume_missing_from_the_table_is_added(self):  # e.g. overlay root in a container
        mounts = [{"device": "overlay", "mount": "/", "fs": "overlay", "opts": {"rw"}}]
        rows = self._run("linux", mounts, "/", _volume=mock.Mock(return_value={"mount": "/", "fs": "overlay", "opts": {"rw"}}))
        self.assertEqual([r["mount"] for r in rows], ["/"])

    def test_unreadable_volume_is_skipped(self):
        mounts = [{"device": "/dev/a", "mount": "/a", "fs": "ext4", "opts": {"rw"}}, {"device": "/dev/b", "mount": "/b", "fs": "ext4", "opts": {"rw"}}]

        def usage(mount):
            if mount == "/a":
                raise PermissionError(13, "denied")
            return (10, 4, 6)

        with mock.patch.object(pi, "_mounts", return_value=mounts), mock.patch.object(
            pi, "_home_mount", return_value="/b"
        ), mock.patch.object(pi.shutil, "disk_usage", side_effect=usage), mock.patch.object(
            pi, "is_case_insensitive", return_value=False
        ), mock.patch.object(pi, "_trash_for", return_value=(True, "gio")):
            rows = pi._posix_volumes("linux")
        self.assertEqual([r["mount"] for r in rows], ["/b"])


class CheckAndFree(TempCase):
    def test_check_contract_on_this_host(self):
        state = os.path.join(self.tmp(), "never-created")
        with mock.patch.dict(os.environ, {common.STATE_ENV: state}):
            got = pi.check()
        self.assertFalse(os.path.exists(state), "check is read-only: it must not create the state dir")
        for key, typ in [
            ("os", str), ("os_version", str), ("arch", str), ("arch_supported", bool), ("python", str),
            ("is_admin", bool), ("trash", dict), ("dua", dict), ("git", dict), ("rg", dict),
            ("volumes", list), ("warnings", list),
        ]:
            self.assertIsInstance(got[key], typ, key)
        self.assertEqual(set(got["trash"]), {"available", "tool", "reason"})
        self.assertEqual(set(got["dua"]), {"found", "path", "version", "managed"})
        self.assertEqual(set(got["git"]), {"found", "version"})
        self.assertRegex(got["python"], r"^3\.\d+\.\d+")
        self.assertEqual(got["trash"]["available"], got["trash"]["tool"] is not None)
        for vol in got["volumes"]:
            self.assertEqual(
                set(vol), {"mount", "fs", "total_bytes", "free_bytes", "case_insensitive", "trash", "trash_detail"}
            )

    def test_check_with_everything_mocked(self):
        with mock.patch.multiple(
            pi,
            os_kind=mock.Mock(return_value="linux"),
            _arch=mock.Mock(return_value=("riscv64", [])),
            _os_version=mock.Mock(return_value="Test OS"),
            _find_dua=mock.Mock(return_value={"found": False, "path": "/x/dua", "version": None, "managed": False}),
            trash_available=mock.Mock(return_value=(False, "no Trash tool")),
            _tool=mock.Mock(return_value={"found": False, "version": None}),
            _posix_volumes=mock.Mock(return_value=[]),
        ), mock.patch.object(common, "is_admin", return_value=True):
            got = pi.check()
        self.assertFalse(got["arch_supported"])
        self.assertTrue(got["is_admin"])
        self.assertEqual(got["trash"], {"available": False, "tool": None, "reason": "no Trash tool"})
        self.assertTrue(any("no pinned dua build" in w for w in got["warnings"]))
        self.assertTrue(any("did not report a version" in w for w in got["warnings"]))

    def test_check_unknown_os_warns_and_stays_json_safe(self):
        with mock.patch.multiple(
            pi,
            os_kind=mock.Mock(return_value="freebsd14"),
            _arch=mock.Mock(return_value=("x86_64", [])),
            _find_dua=mock.Mock(return_value={"found": False, "path": None, "version": None, "managed": False}),
            _tool=mock.Mock(return_value={"found": False, "version": None}),
        ):
            got = pi.check()
        self.assertEqual(got["os"], "freebsd14")
        self.assertEqual(got["volumes"], [])
        self.assertFalse(got["trash"]["available"])
        self.assertTrue(any("unsupported OS" in w for w in got["warnings"]))

    def test_free_on_a_temp_dir(self):
        d = self.tmp()
        got = pi.free(d)
        self.assertEqual(got["path"], d)
        for key in ("total_bytes", "used_bytes", "free_bytes"):
            self.assertIsInstance(got[key], int)
        self.assertGreater(got["free_bytes"], 0)
        self.assertGreaterEqual(got["total_bytes"], got["free_bytes"])
        self.assertRegex(got["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_free_default_is_home(self):
        home = self.tmp()
        with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
            self.assertEqual(pi.free()["path"], os.path.abspath(os.path.expanduser("~")))

    def test_free_uses_disk_usage_numbers_verbatim(self):
        with mock.patch.object(pi.shutil, "disk_usage", return_value=(1000, 700, 300)):
            got = pi.free(self.tmp())
        self.assertEqual((got["total_bytes"], got["used_bytes"], got["free_bytes"]), (1000, 700, 300))

    def test_free_missing_path_is_a_corecleaner_error(self):
        with self.assertRaises(common.CorecleanerError) as cm:
            pi.free(os.path.join(self.tmp(), "nope"))
        self.assertEqual(cm.exception.code, common.EXIT_ERROR)

    def test_run_dispatch(self):
        d = self.tmp()
        self.assertIn("free_bytes", pi.run(ns(cmd="free", path=d)))
        with mock.patch.object(pi, "check", return_value={"os": "x"}):
            self.assertEqual(pi.run(ns(cmd="check")), {"os": "x"})
        with self.assertRaises(common.CorecleanerError) as cm:
            pi.run(ns(cmd="trash"))
        self.assertEqual(cm.exception.code, common.EXIT_USAGE)


class NoDeleteGuard(unittest.TestCase):
    """SPEC trava 4: this module never removes a user path."""

    def test_source_has_no_destructive_calls_except_own_probe_file(self):
        source = Path(pi.__file__).read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        for banned in ("rmtree", "os.remove", "os.rmdir", "shutil.move", "os.rename", "send2trash"):
            self.assertNotIn(banned, code, banned)
        self.assertEqual(len(re.findall(r"\bos\.unlink\(", code)), 1)
        self.assertIn("os.unlink(tmp)", code)  # the CaseProbe temp file in the state dir


if __name__ == "__main__":
    unittest.main()
