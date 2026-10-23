"""bootstrap.py: pins, platform pick, consent dry-run, sha256 gate, safe extraction, self-test, install.

No test touches the real network, the real HOME or the real state dir: a loopback http.server serves
fake archives whose `dua` is a tiny shell script, state and install dirs live in mkdtemp() folders.
"""

import hashlib
import http.server
import io
import json
import os
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import threading
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import corecleaner  # noqa: E402
from corecleaner_lib import bootstrap, common  # noqa: E402
from corecleaner_lib.common import CorecleanerError  # noqa: E402

POSIX = os.name == "posix"
DARWIN = sys.platform == "darwin"
FIXTURE_TOTAL = 20 * 1024 * 1024
REAL_PINS = Path(bootstrap.PINS_FILE)
GITHUB_PREFIX = "https://github.com/Byron/dua-cli/releases/download/v2.46.0/"


def fake_dua(version="2.46.0", total=FIXTURE_TOTAL, marker=None):
    """A `dua` stand-in; every execution appends to `marker`, so tests can prove it never ran."""
    touch = 'echo run >> "%s"\n' % marker if marker else ""
    return (
        "#!/bin/sh\n" + touch + 'case "$1" in\n'
        '  --version) echo "dua %s";;\n'
        '  aggregate) echo "         0 b clone1.bin"; echo "  %d b total";;\n'
        "  *) exit 2;;\n"
        "esac\n" % (version, total)
    ).encode()


def tar_gz(members):
    """members: [(name, bytes | ("symlink", target))] -> .tar.gz bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, data[1]
                tf.addfile(info)
            else:
                info.size, info.mode = len(data), 0o755
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(members, symlinks=()):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name)
            if name in symlinks:
                info.external_attr = 0o120777 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def pin_line(target, url, sha, version="2.46.0", size=100):
    return "\t".join((target, url, sha, version, str(size)))


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # clients abort oversized downloads on purpose
        pass


class Server:
    """Loopback file server over `directory`; `hits` counts requests, `redirect` maps path -> Location."""

    def __init__(self, directory):
        self.hits = []
        self.redirect = {}
        outer = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=str(directory), **kw)

            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.hits.append(self.path)
                if self.path in outer.redirect:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect[self.path])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                super().do_GET()

        self.httpd = QuietHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, args=(0.01,), daemon=True).start()

    def url(self, name):
        return "http://127.0.0.1:%d/%s" % (self.port, name)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="corecleaner-test-")).resolve()
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.state = self.tmp / "state"  # deliberately not created: describe must not need it
        self.bin = self.tmp / "bin"
        self.www = self.tmp / "www"
        self.www.mkdir()
        self.marker = self.tmp / "ran.marker"
        self.server = Server(self.www)
        self.addCleanup(self.server.close)
        self.on_path = None
        for patcher in (
            mock.patch.dict(os.environ, {common.STATE_ENV: str(self.state)}),
            mock.patch.object(bootstrap, "install_dir", lambda os_name: self.bin),
            mock.patch.object(bootstrap, "_URL_SCHEMES", ("https", "http")),
            mock.patch.object(bootstrap.shutil, "which", lambda name: self.on_path),
            mock.patch.object(common, "log"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def stage(self, os_name="linux", machine="x86_64", payload=None, version="2.46.0", pin_sha=None,
              pin_size=None, raw=None):
        """Serve a fake release asset and point PINS_FILE at it. Returns the Pin."""
        arch = bootstrap._ARCH_TAG[machine.lower()]
        target = "%s-%s" % (arch, bootstrap._OS_TAG[os_name])
        folder = "dua-v%s-%s" % (version, target)
        if os_name == "windows":
            name, member = folder + ".zip", "dua.exe"
            blob = raw or zip_bytes([(folder + "/", b""), (folder + "/" + member, payload or fake_dua())])
        else:
            name, member = folder + ".tar.gz", "dua"
            blob = raw or tar_gz([(folder + "/" + member, payload or fake_dua(marker=self.marker))])
        (self.www / name).write_bytes(blob)
        sha = pin_sha or hashlib.sha256(blob).hexdigest()
        pins = self.tmp / "pins.tsv"
        pins.write_text(pin_line(target, self.server.url(name), sha, version, pin_size or len(blob)) + "\n")
        patcher = mock.patch.object(bootstrap, "PINS_FILE", pins)
        patcher.start()
        self.addCleanup(patcher.stop)
        return bootstrap.load_pins()[target]

    def state_tmp_entries(self):
        tmp = self.state / "tmp"
        return sorted(p.name for p in tmp.iterdir()) if tmp.exists() else []

    def run_install(self, os_name="linux", machine="x86_64", yes=True):
        return bootstrap._bootstrap(yes, os_name, machine)


class RealPins(unittest.TestCase):
    def test_six_targets_pinned_for_v2_46_0(self):
        pins = bootstrap.parse_pins(REAL_PINS.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(pins),
            sorted(
                "%s-%s" % (a, o)
                for a in ("aarch64", "x86_64")
                for o in ("apple-darwin", "unknown-linux-musl", "pc-windows-msvc")
            ),
        )
        for pin in pins.values():
            self.assertEqual(pin.version, "2.46.0")
            self.assertTrue(pin.url.startswith(GITHUB_PREFIX), pin.url)
            self.assertRegex(pin.sha256, r"^[0-9a-f]{64}$")
            self.assertGreater(pin.size, 1_000_000)
            self.assertEqual(pin.kind, "zip" if "windows" in pin.target else "tar.gz")
        self.assertEqual(
            pins["aarch64-apple-darwin"].sha256,
            "857af70a6be7fe3d22611a3aa082f17789435ad0b89808845ef13f85789e8e1b",
        )

    def test_every_supported_platform_resolves_to_a_pin(self):
        pins = bootstrap.load_pins()
        cases = {
            ("macos", "arm64"): "aarch64-apple-darwin",
            ("macos", "x86_64"): "x86_64-apple-darwin",
            ("linux", "x86_64"): "x86_64-unknown-linux-musl",
            ("linux", "aarch64"): "aarch64-unknown-linux-musl",
            ("windows", "AMD64"): "x86_64-pc-windows-msvc",
            ("windows", "ARM64"): "aarch64-pc-windows-msvc",
        }
        for (os_name, machine), target in cases.items():
            self.assertEqual(bootstrap.select_pin(pins, os_name, machine).target, target)

    def test_unsupported_platform_exits_10_with_supported_list(self):
        pins = bootstrap.load_pins()
        for os_name, machine in (("linux", "riscv64"), ("linux", "armv7l"), ("freebsd", "x86_64"), ("macos", "ppc")):
            with self.assertRaises(CorecleanerError) as ctx:
                bootstrap.select_pin(pins, os_name, machine)
            self.assertEqual(ctx.exception.code, common.EXIT_UNSUPPORTED_ARCH)
            self.assertEqual(len(ctx.exception.details["supported"]), 6)


class ParsePins(unittest.TestCase):
    SHA = "a" * 64
    URL = GITHUB_PREFIX + "dua-v2.46.0-x86_64-unknown-linux-musl.tar.gz"
    GOOD = pin_line("x86_64-unknown-linux-musl", URL, SHA)

    def bad(self, text):
        with self.assertRaises(CorecleanerError) as ctx:
            bootstrap.parse_pins(text)
        self.assertEqual(ctx.exception.code, common.EXIT_ERROR)
        return ctx.exception.message

    def test_good_row_with_comments_and_blanks(self):
        pins = bootstrap.parse_pins("# c\n\n" + self.GOOD + "\n")
        self.assertEqual(pins["x86_64-unknown-linux-musl"].sha256, self.SHA)

    def test_malformed_rows_are_errors_not_skipped(self):
        g = self.GOOD
        self.bad(g.replace("\t2.46.0\t100", "\t2.46.0"))  # 4 columns
        self.bad(g.replace(self.SHA, "A" * 64))  # uppercase hex
        self.bad(g.replace(self.SHA, "a" * 63))
        self.bad(g.replace("\t2.46.0\t", "\t2.46\t"))
        self.bad(g.replace("\t100", "\t0"))
        self.bad(g.replace("x86_64-unknown-linux-musl\t", "x86_64-unknown-linux-gnu\t", 1))
        self.bad(g.replace("https://", "http://"))  # production schemes are https only
        self.bad(g.replace("dua-v2.46.0-x86_64", "dua-v2.45.0-x86_64"))  # asset name vs version
        self.bad(g + "\n" + g)  # duplicate target
        self.bad("# only comments\n")

    def test_error_names_the_line(self):
        self.assertIn("line 3", self.bad("# a\n# b\n" + self.GOOD.replace(self.SHA, "zz")))


class Versions(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(bootstrap.parse_version("dua 2.46.0\n"), (2, 46, 0))
        self.assertEqual(bootstrap.parse_version("dua v2.43.1-rc1"), (2, 43, 1))
        self.assertIsNone(bootstrap.parse_version("du (GNU coreutils) 9.4"))
        self.assertIsNone(bootstrap.parse_version(""))
        self.assertGreaterEqual((2, 43, 0), bootstrap.MIN_DUA)
        self.assertLess(bootstrap.parse_version("dua 2.42.9"), bootstrap.MIN_DUA)
        self.assertLess(bootstrap.parse_version("dua 1.99.0"), bootstrap.MIN_DUA)
        self.assertGreater(bootstrap.parse_version("dua 10.0.0"), bootstrap.MIN_DUA)  # numeric, not lexical


@unittest.skipUnless(POSIX, "uses shell-script stand-ins for dua")
class ConsentAndSkip(Base):
    def test_without_yes_only_describes_and_touches_nothing(self):
        pin = self.stage()
        out = self.run_install(yes=False)
        self.assertEqual(out["action"], "needs_consent")
        self.assertTrue(out["needs_consent"])
        self.assertFalse(out["installed"])
        self.assertEqual(
            (out["source"], out["version"], out["sha256"], out["bytes"], out["destination"]),
            (pin.url, "2.46.0", pin.sha256, pin.size, str(self.bin / "dua")),
        )
        self.assertFalse(out["replaces_existing"])
        for needle in (pin.url, pin.sha256, str(self.bin / "dua")):
            self.assertIn(needle, out["prompt"])
        self.assertEqual(self.server.hits, [])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.bin.exists())
        json.dumps(out)

    def test_older_dua_at_destination_is_disclosed_as_replaced(self):
        self.stage()
        self.bin.mkdir()
        (self.bin / "dua").write_bytes(fake_dua(version="2.40.0"))
        os.chmod(self.bin / "dua", 0o755)
        out = self.run_install(yes=False)
        self.assertTrue(out["replaces_existing"])
        self.assertEqual(out["existing_version"], "2.40.0")
        self.assertIn("replaces the existing dua 2.40.0", out["prompt"])

    def test_destination_symlink_directory_or_foreign_file_is_refused(self):
        self.stage()
        self.bin.mkdir()
        dest = self.bin / "dua"
        target = self.tmp / "elsewhere"
        target.write_bytes(b"x")
        os.symlink(str(target), str(dest))
        for setup in ("symlink", "dir", "foreign"):
            if setup == "dir":
                dest.unlink()
                dest.mkdir()
            elif setup == "foreign":
                dest.rmdir()
                dest.write_bytes(b"#!/bin/sh\necho not-the-tool\n")
                os.chmod(dest, 0o755)
            with self.assertRaises(CorecleanerError) as ctx:
                self.run_install(yes=True)
            self.assertEqual(ctx.exception.code, common.EXIT_ERROR, setup)
        self.assertEqual(dest.read_bytes(), b"#!/bin/sh\necho not-the-tool\n")  # untouched
        self.assertEqual(self.server.hits, [])

    def test_dua_on_path_new_enough_skips_everything(self):
        script = self.tmp / "dua-on-path"
        script.write_bytes(fake_dua(version="2.43.0", marker=self.marker))
        os.chmod(script, 0o755)
        self.on_path = str(script)
        for yes in (False, True):
            out = self.run_install(yes=yes)  # no pins staged: must not even read them
            self.assertEqual(out["action"], "skip")
            self.assertTrue(out["present"])
            self.assertFalse(out["installed"] or out["needs_consent"])
            self.assertEqual((out["path"], out["version"]), (str(script), "2.43.0"))
        self.assertEqual(self.server.hits, [])
        self.assertFalse(self.state.exists())

    def test_dua_at_destination_but_not_on_path_also_skips(self):
        self.bin.mkdir()
        (self.bin / "dua").write_bytes(fake_dua(version="2.46.0"))
        os.chmod(self.bin / "dua", 0o755)
        self.assertEqual(self.run_install(yes=True)["action"], "skip")

    def test_dua_on_path_too_old_does_not_skip(self):
        self.stage()
        script = self.tmp / "old-dua"
        script.write_bytes(fake_dua(version="2.42.9"))
        os.chmod(script, 0o755)
        self.on_path = str(script)
        self.assertEqual(self.run_install(yes=False)["action"], "needs_consent")

    def test_non_dua_on_path_does_not_skip(self):
        self.stage()
        script = self.tmp / "du-lookalike"
        script.write_bytes(b"#!/bin/sh\necho du 9.9.9\n")
        os.chmod(script, 0o755)
        self.on_path = str(script)
        self.assertEqual(self.run_install(yes=False)["action"], "needs_consent")

    def test_unsupported_arch_is_exit_10_in_both_modes(self):
        self.stage()
        for yes in (False, True):
            with self.assertRaises(CorecleanerError) as ctx:
                bootstrap._bootstrap(yes, "linux", "riscv64")
            self.assertEqual(ctx.exception.code, common.EXIT_UNSUPPORTED_ARCH)
        self.assertEqual(self.server.hits, [])


@unittest.skipUnless(POSIX, "uses shell-script stand-ins for dua")
class Install(Base):
    def test_good_hash_installs_executable_and_cleans_temp(self):
        pin = self.stage()
        out = self.run_install()
        dest = self.bin / "dua"
        self.assertEqual(out["action"], "installed")
        self.assertTrue(out["installed"])
        self.assertEqual((out["path"], out["version"], out["sha256"], out["source"]), (str(dest), "2.46.0", pin.sha256, pin.url))
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o755)
        self.assertEqual(dest.read_bytes(), fake_dua(marker=self.marker))
        self.assertEqual(out["selftest"]["version"], "2.46.0")
        self.assertEqual(out["selftest"]["clone_check"]["status"], "not_applicable")
        self.assertFalse(out["on_path"])
        self.assertIn("absolute path", out["note"])
        self.assertEqual(self.state_tmp_entries(), [])
        self.assertEqual(sorted(p.name for p in self.bin.iterdir()), ["dua"])  # no sibling temp files
        self.assertEqual(len(self.server.hits), 1)
        json.dumps(out)

    def test_on_path_flag_when_install_dir_is_on_path(self):
        self.stage()
        self.bin.mkdir()
        with mock.patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}):
            out = self.run_install()
        self.assertTrue(out["on_path"])
        self.assertIsNone(out["note"])

    def test_replaces_an_older_dua(self):
        self.stage()
        self.bin.mkdir()
        (self.bin / "dua").write_bytes(fake_dua(version="2.40.0"))
        os.chmod(self.bin / "dua", 0o755)
        out = self.run_install()
        self.assertEqual(out["replaced_version"], "2.40.0")
        self.assertEqual(bootstrap.probe_version(str(self.bin / "dua")), "2.46.0")

    def test_wrong_hash_exits_20_runs_nothing_and_deletes_the_temp(self):
        self.stage(pin_sha=hashlib.sha256(b"some other build").hexdigest())
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        err = ctx.exception
        self.assertEqual(err.code, common.EXIT_HASH_MISMATCH)
        self.assertEqual(err.details["expected"], hashlib.sha256(b"some other build").hexdigest())
        self.assertRegex(err.details["actual"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(err.details["actual"], err.details["expected"])
        self.assertFalse(self.marker.exists(), "nothing from the download may execute")
        self.assertFalse(self.bin.exists())
        self.assertEqual(self.state_tmp_entries(), [])
        self.assertEqual(len(self.server.hits), 1)

    def test_wrong_hash_through_the_cli_prints_code_20(self):
        self.stage(pin_sha="0" * 64)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(bootstrap, "_os_name", return_value="linux"), mock.patch(
            "platform.machine", return_value="x86_64"
        ), mock.patch.object(common, "is_admin", return_value=False), mock.patch("sys.stdout", out), mock.patch(
            "sys.stderr", err
        ):
            code = corecleaner.main(["bootstrap", "--yes"])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, 20)
        self.assertFalse(doc["ok"])
        self.assertEqual((doc["error"]["code"], doc["error"]["name"]), (20, "hash_mismatch"))
        self.assertFalse(self.marker.exists())

    def test_tampered_bytes_with_the_right_pin_fail_the_same_way(self):
        pin = self.stage()
        blob = (self.www / pin.url.rsplit("/", 1)[1]).read_bytes()
        (self.www / pin.url.rsplit("/", 1)[1]).write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_HASH_MISMATCH)
        self.assertFalse(self.marker.exists())

    def test_download_bigger_than_pinned_size_is_cut_off_with_20(self):
        junk = tar_gz([("dua-v2.46.0-x86_64-unknown-linux-musl/dua", os.urandom(2 * 1024 * 1024))])
        self.stage(raw=junk, pin_size=100)
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_HASH_MISMATCH)
        self.assertIn("pinned size", ctx.exception.message)
        self.assertEqual(self.state_tmp_entries(), [])

    def test_unreachable_server_is_exit_11(self):
        self.stage()
        with socket.socket() as s:  # a port that was just free: connection refused
            s.bind(("127.0.0.1", 0))
            dead = s.getsockname()[1]
        pins = bootstrap.PINS_FILE
        pins.write_text(pins.read_text().replace(":%d/" % self.server.port, ":%d/" % dead))
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_NO_NETWORK)
        self.assertIn("hint", ctx.exception.details)
        self.assertFalse(self.bin.exists())
        self.assertEqual(self.state_tmp_entries(), [])

    def test_missing_asset_404_means_stale_pins_not_offline(self):
        self.stage()
        (self.www / bootstrap.load_pins()["x86_64-unknown-linux-musl"].url.rsplit("/", 1)[1]).unlink()
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_ERROR)
        self.assertIn("outdated", ctx.exception.message)

    def test_redirect_to_a_disallowed_scheme_is_refused(self):
        pin = self.stage()
        name = pin.url.rsplit("/", 1)[1]
        self.server.redirect["/" + name] = "ftp://127.0.0.1/dua.tar.gz"
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_NO_NETWORK)
        self.assertFalse(self.marker.exists())

    def test_redirect_to_the_same_scheme_is_followed(self):
        pin = self.stage()
        name = pin.url.rsplit("/", 1)[1]
        (self.www / "moved.bin").write_bytes((self.www / name).read_bytes())
        self.server.redirect["/" + name] = self.server.url("moved.bin")
        self.assertEqual(self.run_install()["action"], "installed")

    def test_selftest_version_mismatch_installs_nothing(self):
        self.stage(payload=fake_dua(version="2.45.0", marker=self.marker))
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_ERROR)
        self.assertIn("self-test", ctx.exception.message)
        self.assertTrue(self.marker.exists())  # it ran, in staging only
        self.assertFalse(self.bin.exists())
        self.assertEqual(self.state_tmp_entries(), [])

    def test_failing_install_dir_reports_and_leaves_the_user_dir_alone(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        self.stage()
        self.bin.mkdir()
        (self.bin / "keep.txt").write_text("mine")
        os.chmod(self.bin, 0o500)
        self.addCleanup(os.chmod, str(self.bin), 0o700)
        with self.assertRaises(CorecleanerError) as ctx:
            self.run_install()
        self.assertEqual(ctx.exception.code, common.EXIT_ERROR)
        self.assertEqual(sorted(p.name for p in self.bin.iterdir()), ["keep.txt"])
        self.assertEqual(self.state_tmp_entries(), [])

    def test_public_entry_point_and_run_wrapper(self):
        self.stage()
        with mock.patch.object(bootstrap, "_os_name", return_value="linux"), mock.patch(
            "platform.machine", return_value="x86_64"
        ):
            self.assertEqual(bootstrap.bootstrap(False)["action"], "needs_consent")
            self.assertEqual(bootstrap.run(types.SimpleNamespace(cmd="bootstrap", yes=False))["action"], "needs_consent")
            self.assertEqual(bootstrap.run(types.SimpleNamespace(cmd="bootstrap", yes=True))["action"], "installed")


class WindowsFlow(Base):
    """Windows is beta and cannot execute here: the zip path runs with `dua --version` faked."""

    def test_zip_install_places_dua_exe_in_the_state_bin_dir(self):
        pin = self.stage(os_name="windows", machine="AMD64")
        self.assertTrue(pin.url.endswith(".zip"))
        with mock.patch.object(bootstrap, "probe_version", return_value="2.46.0"):
            out = self.run_install("windows", "AMD64")
        self.assertEqual(out["path"], str(self.bin / "dua.exe"))
        self.assertEqual(out["selftest"]["clone_check"]["status"], "not_applicable")
        self.assertEqual((self.bin / "dua.exe").read_bytes(), fake_dua())
        self.assertEqual(self.state_tmp_entries(), [])


class Extraction(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="corecleaner-extract-")).resolve()
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.pin_tar = bootstrap.Pin("x86_64-unknown-linux-musl", "u", "0" * 64, "2.46.0", 1)
        self.pin_zip = bootstrap.Pin("x86_64-pc-windows-msvc", "u", "0" * 64, "2.46.0", 1)

    def extract(self, pin, blob):
        archive = self.tmp / ("a." + pin.kind)
        archive.write_bytes(blob)
        dest = self.tmp / "out" / pin.member
        dest.parent.mkdir(exist_ok=True)
        bootstrap._extract_binary(archive, pin, dest)
        return dest

    def refused(self, pin, blob):
        with self.assertRaises(CorecleanerError) as ctx:
            self.extract(pin, blob)
        self.assertEqual(ctx.exception.code, common.EXIT_ERROR)
        self.assertEqual(sorted(p.name for p in (self.tmp / "out").iterdir()) if (self.tmp / "out").exists() else [], [])

    def test_only_the_binary_is_written_and_traversal_names_are_inert(self):
        blob = tar_gz(
            [
                ("../escape.txt", b"nope"),
                ("/abs/escape2.txt", b"nope"),
                ("pkg/LICENSE", b"mit"),
                ("pkg/dua", b"BIN"),
            ]
        )
        dest = self.extract(self.pin_tar, blob)
        self.assertEqual(dest.read_bytes(), b"BIN")
        if POSIX:
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o755)
        self.assertEqual(sorted(p.name for p in (self.tmp / "out").iterdir()), ["dua"])
        self.assertFalse((self.tmp.parent / "escape.txt").exists())
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir() if p.is_file()), ["a.tar.gz"])

    def test_tar_refusals(self):
        self.refused(self.pin_tar, tar_gz([("pkg/dua", ("symlink", "/bin/sh"))]))
        self.refused(self.pin_tar, tar_gz([("a/dua", b"1"), ("b/dua", b"2")]))
        self.refused(self.pin_tar, tar_gz([("a/b/c/dua", b"1")]))
        self.refused(self.pin_tar, tar_gz([("pkg/../dua", b"1")]))
        self.refused(self.pin_tar, tar_gz([("pkg/LICENSE", b"1")]))
        self.refused(self.pin_tar, b"this is not a tarball")

    def test_zip_extracts_dua_exe_and_refuses_the_rest(self):
        dest = self.extract(self.pin_zip, zip_bytes([("pkg/", b""), ("pkg/dua.exe", b"EXE"), ("pkg/README.md", b"r")]))
        self.assertEqual(dest.read_bytes(), b"EXE")
        self.assertEqual(sorted(p.name for p in (self.tmp / "out").iterdir()), ["dua.exe"])

    def test_zip_refusals(self):
        self.refused(self.pin_zip, zip_bytes([("pkg/dua.exe", b"x")], symlinks=("pkg/dua.exe",)))
        self.refused(self.pin_zip, zip_bytes([("..\\dua.exe", b"x")]))
        self.refused(self.pin_zip, zip_bytes([("a/dua.exe", b"1"), ("b/dua.exe", b"2")]))
        self.refused(self.pin_zip, b"PK not really")

    def test_implausibly_large_member_is_refused(self):
        with mock.patch.object(bootstrap, "MAX_BINARY_BYTES", 10):
            self.refused(self.pin_tar, tar_gz([("pkg/dua", b"x" * 100)]))
            self.refused(self.pin_zip, zip_bytes([("pkg/dua.exe", b"x" * 100)]))

    def test_existing_destination_is_never_overwritten_by_extraction(self):
        (self.tmp / "out").mkdir()
        (self.tmp / "out" / "dua").write_bytes(b"OLD")
        with self.assertRaises(CorecleanerError):
            self.extract(self.pin_tar, tar_gz([("pkg/dua", b"NEW")]))
        self.assertEqual((self.tmp / "out" / "dua").read_bytes(), b"OLD")


class AggregateParsing(unittest.TestCase):
    def test_total_line(self):
        text = "         0 b clone1.bin\n  20971520 b base.bin\n  20971520 b total\n"
        self.assertEqual(bootstrap._aggregate_total(text), 20971520)
        self.assertIsNone(bootstrap._aggregate_total("  5 b base.bin\n"))
        self.assertIsNone(bootstrap._aggregate_total(""))
        self.assertEqual(bootstrap._aggregate_total("  5 b total\n  9 b total\n"), 9)


@unittest.skipUnless(DARWIN, "APFS clone self-test is macOS only")
class MacCloneSelfTest(Base):
    def test_exact_total_passes(self):
        self.stage(os_name="macos", machine="arm64")
        out = self.run_install("macos", "arm64")
        check = out["selftest"]["clone_check"]
        self.assertIn(check["status"], ("ok", "skipped"))  # skipped only if tmp is not APFS
        if check["status"] == "ok":
            self.assertEqual(check["total_bytes"], FIXTURE_TOTAL)
        self.assertEqual(self.state_tmp_entries(), [])  # fixture (20 MiB + clones) is gone

    def test_wrong_total_fails_and_installs_nothing(self):
        self.stage(os_name="macos", machine="arm64", payload=fake_dua(total=4 * FIXTURE_TOTAL, marker=self.marker))
        try:
            out = self.run_install("macos", "arm64")
        except CorecleanerError as exc:
            self.assertEqual(exc.code, common.EXIT_ERROR)
            self.assertIn("clone fixture", exc.message)
            self.assertFalse(self.bin.exists())
            self.assertEqual(self.state_tmp_entries(), [])
        else:  # volume without clone support: the check is skipped by design
            self.assertEqual(out["selftest"]["clone_check"]["status"], "skipped")


class ClonePreconditions(unittest.TestCase):
    def test_fixture_constants(self):
        self.assertEqual(bootstrap.FIXTURE_BYTES, FIXTURE_TOTAL)
        self.assertEqual(bootstrap.MIN_DUA, (2, 43, 0))


class DiscardWork(unittest.TestCase):
    def test_refuses_anything_that_is_not_a_dua_child_of_the_root(self):
        with tempfile.TemporaryDirectory(prefix="corecleaner-discard-") as tmp:
            root = Path(tmp) / "tmp"
            root.mkdir()
            outside = Path(tmp) / "dua-outside"
            outside.mkdir()
            (outside / "keep").write_text("x")
            nested = root / "dua-a" / "dua-b"
            nested.mkdir(parents=True)
            stray = root / "other"
            stray.mkdir()
            for victim in (outside, nested, stray, root):
                with mock.patch.object(common, "log") as log:
                    bootstrap._discard_work(victim, root)
                self.assertTrue(victim.exists(), victim)
                self.assertEqual(log.call_count, 1)
            mine = root / "dua-xyz"
            mine.mkdir()
            (mine / "f").write_text("x")
            bootstrap._discard_work(mine, root)
            self.assertFalse(mine.exists())


if __name__ == "__main__":
    unittest.main()
