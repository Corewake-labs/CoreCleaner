"""The temp-dir guard in tests/__init__.py, and a lint that keeps every test's temp dir cleaned and prefixed.

The guard tests run against a scratch root (and child interpreters whose TMPDIR is that root), never the real
temp dir, so nothing here can remove a dir that is not made by this file.
"""
import ast
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests
from tests import LEDGER_PREFIX, PREFIX, ledger_path, reap_dead, remove_listed

REPO = Path(__file__).resolve().parent.parent
POSIX = os.name == "posix"


def write_ledger(path, entries):
    Path(path).write_text("".join(str(e) + "\n" for e in entries), encoding="utf-8")


class GuardCase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-hygiene-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def make(self, *parts):
        path = os.path.join(self.root, *parts)
        os.makedirs(path)
        Path(path, "f.txt").write_text("x")
        return path


class RemoveListed(GuardCase):
    def test_only_real_suite_dirs_directly_in_the_root_are_removed(self):
        mine = self.make("corecleaner-a")
        readonly = self.make("corecleaner-b", "locked")
        os.chmod(readonly, 0o500)
        foreign = self.make("not-ours")
        nested = self.make("sub", "corecleaner-nested")
        outside = self.make("elsewhere")
        link = os.path.join(self.root, "corecleaner-link")
        if POSIX:  # creating a symlink needs a privilege on Windows
            os.symlink(outside, link)
        ledger = os.path.join(self.root, "ledger.txt")
        write_ledger(ledger, [mine, os.path.join(self.root, "corecleaner-b"), foreign, nested, link,
                              os.path.join(self.root, "corecleaner-gone"), "relative/corecleaner-x", "", "/"])
        removed = remove_listed(ledger, self.root)
        self.assertEqual(sorted(removed), sorted([mine, os.path.join(self.root, "corecleaner-b")]))
        self.assertFalse(os.path.exists(mine))
        self.assertFalse(os.path.exists(os.path.join(self.root, "corecleaner-b")), "a read-only subdir does not stop it")
        for kept in (foreign, nested, outside) + ((link,) if POSIX else ()):
            self.assertTrue(os.path.lexists(kept), kept)
        self.assertTrue(os.path.exists(os.path.join(outside, "f.txt")), "a symlink is never followed")
        self.assertFalse(os.path.exists(ledger))

    def test_a_missing_ledger_removes_nothing(self):
        keep = self.make("corecleaner-a")
        self.assertEqual(remove_listed(os.path.join(self.root, "none.txt"), self.root), [])
        self.assertTrue(os.path.isdir(keep))


@unittest.skipUnless(POSIX, "dead pids are only probed on POSIX")
class ReapDead(GuardCase):
    def ledger(self, pid, *dirs):
        path = ledger_path(pid, self.root)
        write_ledger(path, dirs)
        return path

    def test_a_dead_pid_ledger_is_reaped_and_a_live_one_is_not(self):
        dead_dir, live_dir, own_dir = (self.make("corecleaner-" + n) for n in ("dead", "live", "own"))
        dead = self.ledger(111111, dead_dir)
        live = self.ledger(222222, live_dir)
        own = self.ledger(os.getpid(), own_dir)
        odd = os.path.join(self.root, LEDGER_PREFIX + "abc.txt")
        write_ledger(odd, [dead_dir])
        removed = reap_dead(self.root, alive=lambda pid: pid != 111111)
        self.assertEqual(removed, [dead_dir])
        self.assertFalse(os.path.exists(dead_dir) or os.path.exists(dead))
        for kept in (live_dir, live, own_dir, own, odd):
            self.assertTrue(os.path.exists(kept), kept)

    def test_pid_probe(self):
        self.assertTrue(tests._pid_alive(os.getpid()))
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        self.assertFalse(tests._pid_alive(proc.pid))


@unittest.skipUnless(POSIX, "signals and TMPDIR semantics are POSIX")
class KilledRuns(GuardCase):
    CHILD = (
        "import os, signal, sys\n"
        "signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
        "signal.signal(signal.SIGHUP, signal.SIG_DFL)\n"
        "import tests, tempfile\n"
        "d = tempfile.mkdtemp(prefix='corecleaner-hygiene-child-')\n"
        "open(os.path.join(d, 'f.txt'), 'w').write('x')\n"
        "print(d, flush=True)\n"
        "how = sys.argv[1]\n"
        "if how == 'kill':\n"
        "    os.kill(os.getpid(), signal.SIGKILL)\n"
        "elif how == 'term':\n"
        "    os.kill(os.getpid(), signal.SIGTERM)\n"
        "elif how == 'hup':\n"
        "    os.kill(os.getpid(), signal.SIGHUP)\n"
    )

    def child(self, how):
        env = dict(os.environ, TMPDIR=self.root)
        proc = subprocess.run([sys.executable, "-c", self.CHILD, how], cwd=str(REPO), env=env,
                              capture_output=True, text=True, timeout=60)
        made = proc.stdout.strip().splitlines()[0]
        self.assertEqual(os.path.dirname(os.path.realpath(made)), self.root, proc.stderr)
        return proc.returncode, made

    def test_a_normal_exit_removes_what_the_run_made(self):
        code, made = self.child("exit")
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(made))
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith(LEDGER_PREFIX)], [])

    def test_sigterm_and_sighup_clean_and_still_kill_the_run(self):
        for how, sig in (("term", signal.SIGTERM), ("hup", signal.SIGHUP)):
            code, made = self.child(how)
            self.assertEqual(code, -sig, how)
            self.assertFalse(os.path.exists(made), how)

    def test_sigkill_leaves_a_ledger_that_the_next_run_reaps(self):
        code, made = self.child("kill")
        self.assertEqual(code, -signal.SIGKILL)
        self.assertTrue(os.path.isdir(made), "SIGKILL cannot clean; that is what the ledger is for")
        self.assertEqual(reap_dead(self.root), [made])
        self.assertFalse(os.path.exists(made))
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith(LEDGER_PREFIX)], [])


class Recording(GuardCase):
    def ledger_lines(self):
        try:
            return Path(ledger_path(os.getpid())).read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

    def test_mkdtemp_and_temporarydirectory_are_recorded_when_they_carry_the_prefix(self):
        made = tempfile.mkdtemp(prefix="corecleaner-hygiene-rec-")
        self.addCleanup(shutil.rmtree, made, True)
        tmp = tempfile.TemporaryDirectory(prefix="corecleaner-hygiene-rec-")
        self.addCleanup(tmp.cleanup)
        lines = self.ledger_lines()
        self.assertIn(made, lines)
        self.assertIn(tmp.name, lines)

    def test_a_dir_made_somewhere_else_is_not_recorded(self):
        inside = tempfile.mkdtemp(prefix="corecleaner-hygiene-in-", dir=self.root)
        self.addCleanup(shutil.rmtree, inside, True)
        self.assertNotIn(inside, self.ledger_lines())


class Lint(unittest.TestCase):
    """Every temp dir a test creates is prefixed `corecleaner-` and cleaned even when the test fails."""

    def offenders(self):
        out = []
        for path in sorted((REPO / "tests").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "tempfile":
                    out.append("%s:%d imports from tempfile (use tempfile.mkdtemp so the guard sees it)" % (path.name, node.lineno))
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("mkdtemp", "TemporaryDirectory")
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile"):
                    continue
                where = "%s:%d" % (path.name, node.lineno)
                prefix = next((k.value for k in node.keywords if k.arg == "prefix"), None)
                if not (isinstance(prefix, ast.Constant) and isinstance(prefix.value, str) and prefix.value.startswith(PREFIX)):
                    out.append("%s: temp dir without a literal prefix starting with %r" % (where, PREFIX))
                if isinstance(parent.get(node), ast.withitem):
                    continue  # the context manager cleans on failure too
                func = node
                while func in parent and not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func = parent[func]
                cleaned = any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "addCleanup"
                              for c in ast.walk(func))
                if not cleaned:
                    out.append("%s: temp dir not cleaned by `with` or addCleanup in the same function" % where)
        return out

    def test_every_temp_dir_is_prefixed_and_cleaned(self):
        self.assertEqual(self.offenders(), [])


if __name__ == "__main__":
    unittest.main()
