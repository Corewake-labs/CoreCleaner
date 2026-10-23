"""Runs the real CLI in this process with plan._stat_times reporting no arrival signal.

For tests that drive `corecleaner.py` as a subprocess over fixtures made now and aged with os.utime (their
birthtime and ctime say "arrived a moment ago", which the plan would rightly keep out for an hour). The
subprocess cannot be patched from the test, so it starts here: `python -I -B tests/aged_cli.py <args>`.
Everything else is the CLI as shipped.
"""

import runpy
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
CLI = SCRIPTS / "corecleaner.py"

if __name__ == "__main__":
    sys.path.insert(0, str(SCRIPTS))
    from corecleaner_lib import plan

    plan._stat_times = lambda st: (None, 0.0)
    sys.argv[0] = str(CLI)
    runpy.run_path(str(CLI), run_name="__main__")
