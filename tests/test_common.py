"""common.py and the corecleaner.py dispatcher, in-process (no real module is called)."""

import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import corecleaner  # noqa: E402
from corecleaner_lib import common  # noqa: E402

POSIX = os.name == "posix"


def run_main(argv, modules=None, admin=False):
    """Run corecleaner.main(argv) with fake modules; return (exit code, parsed stdout, stderr)."""
    modules = modules or {}
    out, err = io.StringIO(), io.StringIO()

    def fake_load(short):
        if short not in modules:
            raise AssertionError("module %s should not be loaded" % short)
        return modules[short]

    with mock.patch.object(corecleaner, "load_module", side_effect=fake_load), mock.patch.object(
        common, "is_admin", return_value=admin
    ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = corecleaner.main(argv)
    return code, json.loads(out.getvalue()), err.getvalue()


def fake_module(fn):
    return types.SimpleNamespace(run=fn)


class ExitCodes(unittest.TestCase):
    def test_codes_match_spec(self):
        self.assertEqual(
            (
                common.EXIT_UNSUPPORTED_ARCH,
                common.EXIT_NO_NETWORK,
                common.EXIT_HASH_MISMATCH,
                common.EXIT_NO_TRASH,
                common.EXIT_DENYLISTED,
                common.EXIT_PLAN_TAMPERED,
                common.EXIT_STATE_CHANGED,
                common.EXIT_LIVE_PROCESS,
                common.EXIT_NO_SPACE_FOR_ARCHIVE,
            ),
            (10, 11, 20, 30, 40, 41, 42, 43, 44),
        )

    def test_every_code_has_a_name(self):
        for code in (10, 11, 20, 30, 40, 41, 42, 43, 44, 46, 50):
            self.assertNotEqual(common.error_name(code), "error", code)


class StateDir(unittest.TestCase):
    def test_created_private_and_subdir(self):
        with tempfile.TemporaryDirectory(prefix="corecleaner-common-") as tmp:
            target = Path(tmp) / "state"
            with mock.patch.dict(os.environ, {common.STATE_ENV: str(target)}):
                path = common.state_dir()
                self.assertEqual(path, target)
                sub = common.state_subdir("plans")
                self.assertEqual(sub, target / "plans")
                if POSIX:
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(sub.stat().st_mode & 0o777, 0o700)
                for bad in ("", "..", "a/b", "a\\b"):
                    with self.assertRaises(ValueError):
                        common.state_subdir(bad)

    @unittest.skipUnless(POSIX, "symlink + mode semantics are POSIX")
    def test_loose_existing_dir_is_tightened_and_symlink_refused(self):
        with tempfile.TemporaryDirectory(prefix="corecleaner-common-") as tmp:
            real = Path(tmp) / "real"
            real.mkdir(mode=0o755)
            os.chmod(real, 0o755)
            with mock.patch.dict(os.environ, {common.STATE_ENV: str(real)}):
                common.state_dir()
            self.assertEqual(real.stat().st_mode & 0o777, 0o700)
            link = Path(tmp) / "link"
            link.symlink_to(real)
            with mock.patch.dict(os.environ, {common.STATE_ENV: str(link)}):
                with self.assertRaises(common.CorecleanerError):
                    common.state_dir()


class Output(unittest.TestCase):
    def test_now_iso_is_utc_seconds(self):
        self.assertRegex(common.now_iso(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(common.file_stamp(), r"^\d{8}T\d{6}Z$")

    def test_emit_handles_path_set_and_lone_surrogate(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\n")  # strict, like a real tty
        with mock.patch.object(sys, "stdout", stream):
            common.emit({"p": Path("a/b"), "s": {"y", "x"}, "bad": "n\udcffame"})
        data = json.loads(stream.buffer.getvalue().decode("ascii"))
        self.assertEqual(data["p"], str(Path("a/b")))
        self.assertEqual(data["s"], ["x", "y"])
        self.assertEqual(data["bad"], "n\udcffame")

    def test_die_prints_json_and_exits_with_code(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                common.die(common.EXIT_DENYLISTED, "no")
        self.assertEqual(cm.exception.code, 40)
        data = json.loads(out.getvalue())
        self.assertEqual((data["ok"], data["error"]["code"], data["error"]["name"]), (False, 40, "denylisted"))
        self.assertIn("no", err.getvalue())


class LsofEscapes(unittest.TestCase):
    def test_bytes_lsof_could_not_print_come_back_as_the_real_name(self):
        escaped = "/Users/u/_Cria\\xc3\\xa7\\xc3\\xa3o/Motion"
        self.assertEqual(common.unescape_lsof(escaped), "/Users/u/_Cria\u00e7\u00e3o/Motion")
        nfd = "/Users/u/_Criac\\xcc\\xa7a\\xcc\\x83o"  # decomposed form, as macOS often stores it
        self.assertEqual(common.unescape_lsof(nfd), "/Users/u/_Criac\u0327a\u0303o")

    def test_plain_names_pass_through_untouched(self):
        for text in ("/plain/path", "/with space/and-dash", ""):
            self.assertEqual(common.unescape_lsof(text), text)

    def test_invalid_utf8_is_kept_not_raised(self):
        out = common.unescape_lsof("/x/\\xff\\xfe")
        self.assertTrue(out.startswith("/x/"))
        self.assertEqual(out.encode("utf-8", "surrogateescape")[3:], b"\xff\xfe")


class Dispatcher(unittest.TestCase):
    def test_success_envelope_and_dispatch(self):
        mod = fake_module(lambda args: {"os": "x", "cmd_seen": args.cmd})
        code, data, _ = run_main(["free", "--path", "/p"], {"platform_info": mod})
        self.assertEqual((code, data["ok"], data["cmd"], data["cmd_seen"]), (0, True, "free", "free"))

    def test_undo_is_served_by_trash_module(self):
        mod = fake_module(lambda args: {"run": args.run})
        code, data, _ = run_main(["undo", "--run", "r1"], {"trash": mod})
        self.assertEqual((code, data["run"]), (0, "r1"))

    def test_check_and_free_allowed_as_root_others_refused(self):
        ok = fake_module(lambda args: {})
        for cmd in (["check"], ["free"]):
            code, data, _ = run_main(cmd, {"platform_info": ok}, admin=True)
            self.assertEqual(code, 0, cmd)
        for cmd in (["scan"], ["inventory"], ["bootstrap"], ["undo", "--run", "r"]):
            code, data, _ = run_main(cmd, {}, admin=True)  # no module may be loaded
            self.assertEqual((code, data["error"]["name"]), (50, "root_refused"), cmd)

    def test_corecleaner_error_sets_exit_code_and_details(self):
        def boom(args):
            raise common.CorecleanerError(common.EXIT_PLAN_TAMPERED, "hash differs", plan="p.json")

        code, data, err = run_main(["ask", "--plan", "p.json"], {"ask": fake_module(boom)})
        self.assertEqual(code, 41)
        self.assertEqual(data["error"]["name"], "plan_tampered")
        self.assertEqual(data["error_details"], {"plan": "p.json"})
        self.assertEqual(data["cmd"], "ask")
        self.assertIn("hash differs", err)

    def test_stub_and_crash_still_print_json(self):
        def stub(args):
            raise NotImplementedError

        code, data, _ = run_main(["inventory"], {"inventory": fake_module(stub)})
        self.assertEqual((code, data["error"]["name"]), (1, "not_implemented"))

        def crash(args):
            raise RuntimeError("kaput")

        code, data, err = run_main(["inventory"], {"inventory": fake_module(crash)})
        self.assertEqual((code, data["error"]["name"]), (1, "internal"))
        self.assertIn("kaput", data["error"]["message"])
        self.assertIn("Traceback", err)

    def test_usage_errors_are_json(self):
        for argv in ([], ["nope"], ["trash", "--plan", "p"], ["ask", "--plan", "p", "--format", "xml"]):
            code, data, _ = run_main(argv)
            self.assertEqual((code, data["error"]["name"]), (2, "usage"), argv)

    def test_trash_ids_split_and_dry_run_default(self):
        seen = {}

        def capture(args):
            seen.update(ids=args.ids, apply=args.apply, plan=args.plan)
            return {}

        code, _, _ = run_main(
            ["trash", "--plan", "p.json", "--ids", "c001,c002", "c003"], {"trash": fake_module(capture)}
        )
        self.assertEqual(code, 0)
        self.assertEqual(seen, {"ids": ["c001", "c002", "c003"], "apply": False, "plan": "p.json"})

    def test_pretty_accepted_before_and_after_subcommand(self):
        mod = fake_module(lambda args: {})
        for argv in (["--pretty", "check"], ["check", "--pretty"]):
            out = io.StringIO()
            with mock.patch.object(corecleaner, "load_module", return_value=mod), mock.patch.object(
                common, "is_admin", return_value=False
            ), contextlib.redirect_stdout(out):
                self.assertEqual(corecleaner.main(argv), 0)
            self.assertIn("\n  ", out.getvalue(), argv)


if __name__ == "__main__":
    unittest.main()
