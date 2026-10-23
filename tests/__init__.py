"""Test package setup: one clock override for the whole suite.

Fixtures are created now and aged with os.utime, so every fixture's birthtime and ctime say "arrived a
moment ago": the plan (plan._stat_times) would treat each one as a tree just restored from a backup and
keep it out for an hour. The suite reports "no arrival signal" instead, for every test, and tests of the
arrival rule patch plan._stat_times again with mock.patch.object. REAL_STAT_TIMES is the production
function, for a test that wants the real filesystem answer.


Hygiene guard for the temp dirs this suite creates. Importing the package (every run does) arms it.

Every temp dir the suite makes carries the prefix `corecleaner-`. A killed run used to leave them behind, and
`inventory` then offered them as cleanup candidates. The guard only ever removes a dir that
  - this suite recorded (tempfile.mkdtemp is wrapped; TemporaryDirectory goes through it too),
  - sits directly in the system temp dir, is a real directory (not a symlink) and starts with the prefix.
A run that exits (normally, KeyboardInterrupt, SIGTERM, SIGHUP) removes what it recorded. A run that dies for good
(SIGKILL) leaves a ledger `corecleaner-ledger-<pid>.txt`; the next run removes what a dead pid recorded. Nothing
else in the temp dir is looked at, and nothing is removed on Windows by pid (os.kill(pid, 0) kills there).
"""

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from corecleaner_lib import plan as _plan  # noqa: E402

REAL_STAT_TIMES = _plan._stat_times


def _no_arrival_signal(st):
    return None, 0.0


_plan._stat_times = _no_arrival_signal

# ---------------------------------------------------------------- temp dir hygiene guard
import atexit
import os
import shutil
import signal
import tempfile

PREFIX = "corecleaner-"
LEDGER_PREFIX = PREFIX + "ledger-"
_TMP = os.path.realpath(tempfile.gettempdir())
_POSIX = os.name == "posix"


def ledger_path(pid, root=None):
    return os.path.join(root or _TMP, "%s%d.txt" % (LEDGER_PREFIX, pid))


def _is_suite_dir(path, root):
    """True only for a real directory directly under `root` whose name starts with the suite prefix."""
    parent, name = os.path.split(os.path.abspath(path))
    return (name.startswith(PREFIX) and not name.startswith(LEDGER_PREFIX) and os.path.realpath(parent) == os.path.realpath(root)
            and os.path.isdir(path) and not os.path.islink(path))


def _rmtree(path):
    for dirpath, dirs, _files in os.walk(path):  # a test may have left a dir read-only; os.walk does not follow links
        for d in dirs:
            full = os.path.join(dirpath, d)
            if not os.path.islink(full):
                try:
                    os.chmod(full, 0o700)
                except OSError:
                    pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def remove_listed(ledger, root=None):
    """Remove every suite dir listed in `ledger`, then the ledger. Returns the dirs removed."""
    root = root or _TMP
    removed = []
    try:
        with open(ledger, encoding="utf-8") as fh:
            listed = [line.rstrip("\n") for line in fh if line.strip()]
    except OSError:
        return removed
    for path in listed:
        if _is_suite_dir(path, root):
            _rmtree(path)
            removed.append(path)
    try:
        os.unlink(ledger)
    except OSError:
        pass
    return removed


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # PermissionError: the pid exists and belongs to someone else
        return True
    return True


def reap_dead(root=None, alive=_pid_alive):
    """Remove what runs that died without cleaning (SIGKILL) recorded. Skips this process; POSIX only."""
    root = root or _TMP
    if not _POSIX:
        return []
    removed = []
    try:
        names = os.listdir(root)
    except OSError:
        return removed
    for name in names:
        if not (name.startswith(LEDGER_PREFIX) and name.endswith(".txt")):
            continue
        digits = name[len(LEDGER_PREFIX):-len(".txt")]
        full = os.path.join(root, name)
        if not digits.isdigit() or int(digits) == os.getpid() or alive(int(digits)):
            continue
        if os.path.isfile(full) and not os.path.islink(full):
            removed.extend(remove_listed(full, root))
    return removed


def _record(path):
    if os.path.dirname(os.path.realpath(path)) == _TMP and os.path.basename(path).startswith(PREFIX):
        try:
            with open(ledger_path(os.getpid()), "a", encoding="utf-8") as fh:
                fh.write(path + "\n")
        except OSError:
            pass


_real_mkdtemp = tempfile.mkdtemp


def _recording_mkdtemp(suffix=None, prefix=None, dir=None):
    path = _real_mkdtemp(suffix, prefix, dir)
    _record(path)
    return path


def _on_signal(signum, _frame):
    remove_listed(ledger_path(os.getpid()))
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)  # die the way the sender asked, after cleaning


def arm():
    if tempfile.mkdtemp is not _recording_mkdtemp:
        tempfile.mkdtemp = _recording_mkdtemp
        atexit.register(lambda: remove_listed(ledger_path(os.getpid())))
        if _POSIX:
            for name in ("SIGTERM", "SIGHUP"):
                sig = getattr(signal, name, None)
                try:
                    if sig is not None and signal.getsignal(sig) == signal.SIG_DFL:
                        signal.signal(sig, _on_signal)
                except (ValueError, OSError):  # not the main thread
                    pass
    reap_dead()


arm()
