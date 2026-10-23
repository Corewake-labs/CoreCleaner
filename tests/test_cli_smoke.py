"""Subprocess smoke test: `check` and `free` run and print one JSON document on stdout."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts" / "corecleaner.py"


def run_cli(*args):
    # -I: the script must find corecleaner_lib from its own location, not from cwd/PYTHONPATH.
    # -B: -I ignores PYTHONDONTWRITEBYTECODE, so ask for no .pyc here to keep the repo clean.
    return subprocess.run(
        [sys.executable, "-I", "-B", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tempfile.gettempdir(),
    )


def parse(proc):
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise AssertionError("stdout is not one JSON document:\n%r\nstderr:\n%s" % (proc.stdout, proc.stderr))


class CliSmoke(unittest.TestCase):
    def _result(self, *args):
        proc = run_cli(*args)
        data = parse(proc)  # JSON on stdout even when the module is still a stub
        if not data.get("ok") and data.get("error", {}).get("name") == "not_implemented":
            self.skipTest("%s: platform_info is still a stub (T1)" % args[0])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIs(data["ok"], True)
        self.assertEqual(data["cmd"], args[0])
        return data

    def test_check(self):
        data = self._result("check")
        self.assertIn(data["os"], ("macos", "linux", "windows"))
        self.assertIsInstance(data["arch"], str)

    def test_free(self):
        with tempfile.TemporaryDirectory(prefix="corecleaner-smoke-") as tmp:
            data = self._result("free", "--path", tmp)
        self.assertIsInstance(data["free_bytes"], int)
        self.assertGreater(data["free_bytes"], 0)

    def test_unknown_command_is_json_usage_error(self):
        proc = run_cli("definitely-not-a-command")
        data = parse(proc)
        self.assertEqual(proc.returncode, 2)
        self.assertIs(data["ok"], False)
        self.assertEqual(data["error"]["name"], "usage")


if __name__ == "__main__":
    unittest.main()
