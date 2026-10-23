"""Cleanup candidates, categories A-L, with evidence. (T5; subcommand `inventory`)

Read-only: lists, never decides. Categories and rules: faxina-dos-agentes.md and
references/categorias.md (per-OS paths, how each size is measured, the action hint).
  A agent history   B worktrees   C stray clones   D scratch/generated output   E idle node_modules
  F tool caches     G downloaded models   H raw already transformed (NOT detected: needs a per-item match)
  I duplicates      J what the OS holds (snapshots, code_sign_clone, Trash, journal)   K forgotten processes
  L heavy folders no other category sees (idle projects' .wrangler/.venv/dist..., Xcode, Gradle, Docker; list only)
Agent dirs: $CLAUDE_CONFIG_DIR or ~/.claude, $CODEX_HOME or ~/.codex, Claude tmp (/private/tmp/claude-<uid>,
$CLAUDE_CODE_TMPDIR, %TEMP%\\claude), worktrees in <repo>/.claude/worktrees and $CODEX_HOME/worktrees.

run(args): no arguments. Returns {"candidates": inventory(), "ts": now_iso(), + meta}; meta = tools,
  retention, live_agents, unverified, warnings. Nothing is written, moved or killed, git runs with
  --no-optional-locks (no index refresh), tool commands are only asked for their cache dir, `crontab -l` is read.

inventory(ctx=None) -> list[dict]
  Candidate = {
    "category": "A".."L", "kind": str (stable slug, see categorias.md),
    "path": str,                 # realpath; virtual items: "tmutil:<date>", "journal:disk-usage", "process:<pid>", "docker:system-df"
    "virtual": bool,             # True = not a filesystem path: list only, never realpath/stat/trash it
    "bytes": int,                # allocated: st_blocks*512 (st_size on Windows); upper bound on APFS clones
    "mtime": float,              # newest mtime inside, epoch seconds
    "owner": "claude"|"codex"|"tool"|"user"|"unknown",
    "action": "trash"|"tool_command"|"archive_then_trash"|"list_only",   # a HINT; plan.py decides
    "evidence": {                # script-measured, never agent-asserted
      "git": {"is_repo": bool, "dirty": bool, "unpushed": int, "stash": int, "origin": str|None,
              "last_commit": str|None, "remotes": int, "head_on_remote": bool,
              "ignored_large": {"count": files, "bytes": n},   # ignored data >= 10 MiB the archive does NOT carry
              "remote_checked": False,   # unpushed/head_on_remote come from local remote-tracking refs, never the server
              ...},
      "age_days": int, "live_process": bool, "live_reasons": [str],
      "referenced_by": [str], "referenced_by_total": int,   # rg -F of the path in agent files and project code
      "keep_note": bool,         # a referencing line says keep / manter / do not delete; a worktree: also a repo note
                                 # saying its branch is local-only / never push (then "local_only_note": True)
      "alias_paths": [str],      # only when a linked ancestor gives the path a second name (the one files cite)
      "referenced_maybe": [str], # only when files may build the path in code (`"ref", "lib"`, `cd parent && ./lib`)
      "cloud": bool, "protected": bool, "reason": str,
      "tool_command": str|None,  # cache categories: the tool's own clean command (never rm)
      "unverified": [str],       # checks that could not run (rg or lsof missing, repo too big): NOT "clean"
      ...kind specific: manual_command (sudo, printed only), hint, reinstall, keeper, ...
    }}
  Fail closed: a git check that fails or times out reports dirty=True. Deny-listed, cloud and
  placeholder paths come back with protected/cloud=True and action list_only. Output of git, rg,
  lsof and ps is parsed, never forwarded raw (SPEC trava 9); names that reach evidence strings go
  through safety.sanitize_name, and credentials in remote URLs are stripped.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote

from . import archive, gitguard
from .common import CorecleanerError, log, now_iso, unescape_lsof

DAY = 86400.0
LIVE_WINDOW_S = 3600.0          # SPEC trava 7: touched in the last hour = live state
AGE_HISTORY_DAYS = 45           # A: transcripts and per-session leftovers
AGE_SCRATCH_DAYS = 7            # D: scratch units under the Claude tmp dir
AGE_USER_WORKTREE_DAYS = 45     # B: worktrees that are not inside an agent dir
AGE_NODE_MODULES_DAYS = 30      # E: project idle (no edit outside node_modules, no commit)
MIN_DUP_BYTES = 1 << 20         # I: smaller files are not worth a hash
MAX_ENTRIES = 3_000_000         # per measured candidate
NOISE_NAMES = frozenset({".DS_Store", ".localized", "Thumbs.db", "desktop.ini", "Desktop.ini"})


def is_noise(name: str) -> bool:
    """Finder, Explorer and AppleDouble files: the OS rewrites them on a browse, so their mtime is never an edit."""
    return name in NOISE_NAMES or name.startswith("._")
MAX_DISCOVERY_DIRS = 400_000    # per discovery walk (C and E); reaching it is reported, not hidden
DISCOVERY_SECONDS = 120.0
GIT_TIMEOUT = 60.0
REF_SEARCH_SECONDS = 150.0      # one rg for every candidate path; past this the check is "unverified", never "clean"
REF_MAX_LINES = 300_000         # hit lines parsed; more than this is reported as partial
REF_LONG_LINES = 300            # lines rg omitted (too long) that are re-read from the file; more = partial
# Every visible folder of HOME is a project tree, searched whole (code, not only CLAUDE.md), except these: media,
# apps and package stores. A user's ~/workspace, ~/git or ~/Coding is found by being there, not by its name.
REF_TOP_SKIP = ("Library", "Applications", "Movies", "Music", "Pictures", "Public", "Downloads", "Templates", "Videos",
                "go", "snap")
REF_NEVER_READ = (".cache", ".corecleaner", ".Trash")  # under HOME: where the candidates live, the tool's own state, trash
REF_HOME_FILES = (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile",
                  ".gitconfig", ".tmux.conf", ".vimrc", ".envrc")  # shell and tool start-up files: user code outside any project
REF_HOME_DIRS = (".config", ".dotfiles", os.path.join(".local", "bin"), os.path.join(".local", "share", "chezmoi"),
                 "bin", os.path.join("Library", "LaunchAgents"))
REF_BINARY_EXT = ("png,jpg,jpeg,gif,webp,avif,heic,ico,icns,bmp,tif,tiff,psd,ai,raw,cr2,mp4,mov,m4v,avi,mkv,webm,"
                  "mp3,wav,aac,flac,m4a,ogg,zip,gz,tgz,bz2,xz,zst,7z,rar,tar,dmg,iso,pkg,woff,woff2,ttf,otf,eot,pdf,"
                  "docx,xlsx,pptx,key,numbers,pages,blend,glb,fbx,wasm,pyc,so,dylib,o,a,class,jar,db,exe,dll,"
                  "min.js,map")  # `bin` is not here: a file named tool.bin may be text, and rg skips real binaries itself
# Folders only (trailing slash): a FILE named build, dist or vendor is a script and is read. Inside .git only
# history is skipped: config (local remotes), hooks and FETCH_HEAD stay readable. The cache names keep an
# Electron profile under ~/.config from costing minutes.
REF_SKIP_DIRS = ("node_modules", ".next", "dist", "build", "target", "vendor", "worktrees", ".corecleaner", "Cache",
                 "Code Cache", "GPUCache", "IndexedDB", "Service Worker", "CacheStorage", "Local Storage")
REF_SKIP_GIT = ("objects", "logs", "lfs", "refs")
_SKILL_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
_CHECKOUT = os.path.dirname(os.path.dirname(_SKILL_DIR))
# this tool's own docs, code and tests name every cache it knows: never a citation (a checkout only when it is one)
OWN_ROOTS = (_SKILL_DIR,) + ((_CHECKOUT,) if os.path.isdir(os.path.join(_CHECKOUT, ".git")) else ())
REF_SKIP_GLOBS = (tuple(d + "/" for d in REF_SKIP_DIRS) + tuple("**/.git/**/%s/" % d for d in REF_SKIP_GIT)
                  + ("**/.git/index", "**/.git/packed-refs", "*.jsonl", "*.lock", "*.sqlite*", "*.{%s}" % REF_BINARY_EXT))
REF_NOT_SEARCHED = ("files outside HOME (/opt, other volumes unless HOME links to them), Downloads and Library, "
                    "~/.cache, node_modules/build/dist/vendor/target folders, *.lock, *.map, *.min.js, binaries, "
                    "files over 2 MB, and any path assembled at run time (only a possible citation is flagged)")
REF_ENV_BASES = (("XDG_CACHE_HOME", ".cache"), ("XDG_DATA_HOME", os.path.join(".local", "share")),
                 ("XDG_CONFIG_HOME", ".config"), ("XDG_STATE_HOME", os.path.join(".local", "state")),
                 ("CODEX_HOME", ".codex"), ("CLAUDE_CONFIG_DIR", ".claude"), ("TMPDIR", None),
                 ("CLAUDE_CODE_TMPDIR", None), ("TMP", None), ("TEMP", None), ("LOCALAPPDATA", None), ("APPDATA", None))
REF_TMP_VARS = ("TMPDIR", "CLAUDE_CODE_TMPDIR", "TMP", "TEMP")
REF_WEAK_CATEGORIES = ("B", "C", "D", "F", "G")  # the ones that can come out as "sure junk": worth the extra patterns
REF_WEAK_MAX_PATTERNS = 200_000
REF_WEAK_MIN_NAME = 6  # a shorter folder name says nothing when a file merely shares it
# Names every tool and test run creates (mktemp dirs `mine`/`theirs`, `repo`, `clone`): a text that names one is not
# citing THIS folder. They get no "possibly cited" patterns; the whole path is still searched.
REF_WEAK_STOP_NAMES = frozenset({
    "theirs", "mine", "ours", "repo", "repos", "clone", "cloned", "checkout", "origin", "upstream", "branch", "main",
    "master", "tmp", "temp", "tmpdir", "temporary", "scratch", "sandbox", "work", "workdir", "worktree", "worktrees",
    "workspace", "test", "tests", "testing", "build", "builds", "output", "outputs", "result", "results", "cache",
    "caches", "backup", "backups", "archive", "archives", "project", "projects", "source", "sources", "sample",
    "samples", "example", "examples", "default", "current", "release", "staging", "download", "downloads", "plugin",
    "plugins", "package", "packages", "module", "modules", "service", "services", "server", "client", "folder",
    "folders", "latest", "stable", "fixture", "fixtures", "target", "vendor", "mirror"})
_LOG_FILE_RE = re.compile(r"\.log(?:\.\d+)?$", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
LOCKFILES = {
    "bun.lock": "bun install", "bun.lockb": "bun install", "pnpm-lock.yaml": "pnpm install",
    "yarn.lock": "yarn install", "package-lock.json": "npm ci", "npm-shrinkwrap.json": "npm ci",
}
KEEP_RE = re.compile(
    r"\b(manter|mantenha|keep|do not (delete|remove)|don't (delete|remove)|n[aã]o (apagar|remover|deletar))\b", re.I
)

Runner = Callable[[Sequence[str], Optional[str], float, Optional[str]], Tuple[int, str]]

_GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                 "GIT_NAMESPACE", "GIT_ALTERNATE_OBJECT_DIRECTORIES")


def _default_run(argv: Sequence[str], cwd: Optional[str] = None, timeout: float = 60.0,
                 stdin: Optional[str] = None) -> Tuple[int, str]:
    """(returncode, stdout). Any failure to run = (127, ""). stderr is dropped, never forwarded."""
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, env=env, input=stdin.encode("utf-8", "surrogateescape") if stdin else None,
            stdin=None if stdin else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return 127, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _detect_os() -> str:
    return {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")


@dataclass
class Ctx:
    """Everything the detectors read from the outside world; tests swap each piece."""

    home: Path
    os_kind: str
    env: Dict[str, str]
    now: float
    uid: Optional[int]
    tmp_dir: Path
    run: Runner
    which: Callable[[str], Optional[str]]
    safety: Any
    tmp_bases: List[str] = field(default_factory=lambda: ["/private/tmp", "/tmp"])
    proc_dir: str = "/proc"
    progress: Callable[[str], None] = lambda message: None
    age_history_days: int = AGE_HISTORY_DAYS
    age_scratch_days: int = AGE_SCRATCH_DAYS
    age_node_modules_days: int = AGE_NODE_MODULES_DAYS
    min_dup_bytes: int = MIN_DUP_BYTES
    ref_seconds: float = REF_SEARCH_SECONDS
    unverified: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    _memo: Dict[str, Any] = field(default_factory=dict)

    @property
    def claude_dir(self) -> Path:
        return self._expand(self.env.get("CLAUDE_CONFIG_DIR")) or self.home / ".claude"

    @property
    def codex_dir(self) -> Path:
        return self._expand(self.env.get("CODEX_HOME")) or self.home / ".codex"

    def _expand(self, value: Optional[str]) -> Optional[Path]:
        if not value:
            return None
        return self.home / value[2:] if value.startswith("~/") else Path(value)

    def note_unverified(self, what: str) -> None:
        if what not in self.unverified:
            self.unverified.append(what)

    def memo(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]


def default_ctx() -> Ctx:
    from . import safety

    uid = os.getuid() if hasattr(os, "getuid") else None
    bases = ["/private/tmp", "/tmp", tempfile.gettempdir()] if os.name == "posix" else [tempfile.gettempdir()]
    return Ctx(home=Path.home(), os_kind=_detect_os(), env=dict(os.environ), now=time.time(), uid=uid,
               tmp_dir=Path(tempfile.gettempdir()), run=_default_run, which=shutil.which, safety=safety,
               tmp_bases=bases, progress=log)


# ---------------------------------------------------------------- filesystem helpers

@dataclass
class Measure:
    bytes: int = 0
    mtime: float = 0.0
    entries: int = 0
    truncated: bool = False
    unreadable: int = 0
    fresh: bool = False  # walk stopped early: an entry newer than `fresh_after` exists, so bytes/entries are partial


class _Cut:
    """Shared early-exit flag of one measure(): set by whichever walker thread meets an entry newer than `after`."""

    __slots__ = ("after", "hit")

    def __init__(self, after: float) -> None:
        self.after = after
        self.hit = False


def _alloc(st: os.stat_result) -> int:
    blocks = getattr(st, "st_blocks", None)
    return blocks * 512 if blocks is not None else st.st_size


def _lstat(path: str) -> Optional[os.stat_result]:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _entries(path: Any) -> List[os.DirEntry]:
    try:
        with os.scandir(str(path)) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def _mtime(e: os.DirEntry) -> float:
    try:
        return e.stat(follow_symlinks=False).st_mtime
    except OSError:
        return 0.0


def _is_real_dir(e: os.DirEntry) -> bool:
    try:
        return e.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _is_real_file(e: os.DirEntry) -> bool:
    try:
        return e.is_file(follow_symlinks=False)
    except OSError:
        return False


_WALKERS = max(2, min(8, os.cpu_count() or 4))
_walk_pool: List[ThreadPoolExecutor] = []
_pool_lock = threading.Lock()


def _pool() -> ThreadPoolExecutor:
    with _pool_lock:
        if not _walk_pool:
            _walk_pool.append(ThreadPoolExecutor(max_workers=_WALKERS, thread_name_prefix="corecleaner-size"))
        return _walk_pool[0]


def _scan_dir(d: str, acc: Measure, links: Dict[Tuple[int, int], int], subdirs: List[str], cap: int,
              cut: Optional[_Cut] = None) -> bool:
    """Account the entries of ONE directory into `acc`; subdirectories are queued, never followed as links.
    Hardlinked regular files go to `links` so they are counted once however many threads see them.
    Returns False when the walk must stop: entry cap reached, or `cut` hit (a newer entry was found)."""
    if cut is not None and cut.hit:
        return False
    try:
        it = os.scandir(d)
    except OSError:
        acc.unreadable += 1
        return True
    with it:
        for e in it:
            acc.entries += 1
            if acc.entries > cap:
                acc.truncated = True
                return False
            try:
                est = e.stat(follow_symlinks=False)
            except OSError:
                acc.unreadable += 1
                continue
            # A folder's mtime moves when Finder drops a .DS_Store in it: only files and links are edits
            if est.st_mtime > acc.mtime and not is_noise(e.name) and not stat.S_ISDIR(est.st_mode):
                acc.mtime = est.st_mtime
                if cut is not None and est.st_mtime > cut.after:
                    cut.hit = True
                    return False
            if stat.S_ISDIR(est.st_mode):
                acc.bytes += _alloc(est)
                subdirs.append(e.path)
            elif stat.S_ISREG(est.st_mode) and est.st_nlink > 1:
                links.setdefault((est.st_dev, est.st_ino), _alloc(est))
            else:
                acc.bytes += _alloc(est)
    return True


def _walk_subtree(root: str, cap: int, cut: Optional[_Cut] = None) -> Tuple[Measure, Dict[Tuple[int, int], int]]:
    acc, links, stack = Measure(), {}, [root]
    while stack:
        subdirs: List[str] = []
        if not _scan_dir(stack.pop(), acc, links, subdirs, cap, cut):
            break
        stack.extend(subdirs)
    return acc, links


def measure(path: str, max_entries: int = MAX_ENTRIES, fresh_after: Optional[float] = None) -> Measure:
    """Allocated bytes and newest mtime under `path`. lstat only: never follows or opens anything.
    A few levels are read serially, then the subtrees are sized by a thread pool (stat() is a syscall).

    `fresh_after`: stop at the first entry whose mtime is newer than this epoch and return fresh=True. The caller
    only wanted to know whether the tree is that recent (a candidate younger than its minimum age is dropped),
    so walking the other millions of entries would be pure cost; bytes/entries are partial in that case."""
    m = Measure()
    st = _lstat(path)
    if st is None:
        return m
    m.mtime, m.entries, m.bytes = (0.0 if stat.S_ISDIR(st.st_mode) else st.st_mtime), 1, _alloc(st)
    if not stat.S_ISDIR(st.st_mode):
        return m
    cut = _Cut(fresh_after) if fresh_after is not None else None
    if cut is not None and st.st_mtime > cut.after:
        m.fresh = True
        return m
    links: Dict[Tuple[int, int], int] = {}
    frontier, depth = [path], 0
    while frontier and len(frontier) < 16 and depth < 4 and not m.truncated and not (cut and cut.hit):
        nxt: List[str] = []
        for d in frontier:
            if not _scan_dir(d, m, links, nxt, max_entries, cut):
                break
        frontier, depth = nxt, depth + 1
    if cut is not None and cut.hit:
        m.fresh = True
        return m
    if frontier and not m.truncated:
        parts = list(_pool().map(lambda d: _walk_subtree(d, max_entries, cut), frontier)) if len(frontier) > 1 \
            else [_walk_subtree(frontier[0], max_entries, cut)]
        if cut is not None and cut.hit:
            m.fresh = True
            return m
        for sub, sub_links in parts:
            m.bytes += sub.bytes
            m.mtime = max(m.mtime, sub.mtime)
            m.entries += sub.entries
            m.unreadable += sub.unreadable
            m.truncated = m.truncated or sub.truncated
            for key, size in sub_links.items():
                links.setdefault(key, size)
        m.truncated = m.truncated or m.entries > max_entries
    m.bytes += sum(links.values())
    return m


def _pmap(fn: Callable[[Any], Any], items: Sequence[Any]) -> List[Any]:
    """fn over items on a thread pool, results in input order. The first exception is re-raised."""
    if len(items) < 2:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=_WALKERS, thread_name_prefix="corecleaner-cand") as ex:
        return list(ex.map(fn, items))


def newest_mtime(path: str, exclude: Iterable[str], max_entries: int = 200_000,
                 stop_after: Optional[float] = None) -> Tuple[float, bool]:
    """(newest mtime outside the `exclude` directory names, truncated).

    `stop_after`: return at the first entry newer than this epoch (the caller only needs "is it that recent?")."""
    skip = set(exclude)
    newest = 0.0
    seen = 0
    stack = [path]
    while stack:
        d = stack.pop()
        for e in _entries(d):
            seen += 1
            if seen > max_entries:
                return newest, True
            if e.name in skip and _is_real_dir(e):
                continue  # neither its entries nor its own mtime count as an edit of the project
            try:
                est = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if not is_noise(e.name) and not stat.S_ISDIR(est.st_mode):  # a folder's mtime is not an edit
                newest = max(newest, est.st_mtime)
            if stop_after is not None and newest > stop_after:
                return newest, False
            if stat.S_ISDIR(est.st_mode):
                stack.append(e.path)
    return newest, False


def _walk(root: str, max_depth: int, prune: Callable[[str, str], bool], deadline: float,
          budget: List[int], flag_depth: bool = False) -> Iterable[Tuple[str, List[str], List[str]]]:
    """os.walk(topdown) with depth, name pruning and a shared entry/time budget; budget[1]=1 when hit.

    The full `dirnames` list is yielded even at the depth limit (a `.git` at the boundary is still seen);
    pruning is applied after the yield unless the caller emptied the list. With `flag_depth`, a cut by depth
    also sets budget[1], so the caller knows the result is not complete."""
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        budget[0] -= 1
        if budget[0] <= 0 or time.time() > deadline:
            budget[1] = 1
            return
        depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
        if flag_depth and depth >= max_depth and dirnames:
            budget[1] = 1
        keep = {d for d in dirnames if depth < max_depth and not prune(d, os.path.join(dirpath, d))}
        yield dirpath, dirnames, filenames
        dirnames[:] = [d for d in dirnames if d in keep]


# ---------------------------------------------------------------- git

_GIT = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "log.showSignature=false"]
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+$")


def _git(ctx: Ctx, repo: str, *args: str) -> Tuple[int, str]:
    return ctx.run(_GIT + ["-C", repo] + list(args), None, GIT_TIMEOUT, None)


def _lines(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip())


def _redact_url(url: str) -> str:
    return re.sub(r"^([A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]*@", r"\1", url.strip())


def _no_git() -> dict:
    return {"is_repo": False, "dirty": False, "unpushed": 0, "stash": 0, "origin": None,
            "last_commit": None, "remotes": 0, "head_on_remote": False, "ignored_large": {"count": 0, "bytes": 0},
            "remote_checked": False}


def _ignored_tree(path: str, budget: List[int]) -> Tuple[int, int, bool]:
    """(apparent bytes, files, cut by the shared entry budget) of a tree. lstat only, links never followed."""
    total = files = 0
    stack = [path]
    while stack:
        try:
            it = os.scandir(stack.pop())
        except OSError:
            continue
        with it:
            for e in it:
                if budget[0] <= 0:
                    return total, files, True
                budget[0] -= 1
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(e.path)
                else:
                    total += st.st_size
                    files += 1
    return total, files, False


def _ignored_large(ctx: Ctx, repo: str) -> dict:
    """Ignored data (models, `.wrangler/state`) the archive does NOT carry: {"count": files, "bytes": n, "approx"?}.

    Every ignored path `git status --ignored` lists (a fully ignored folder is one entry) of at least
    archive.IGNORED_MIN_BYTES counts, sized the way archive.py sizes it (apparent bytes, one shared entry budget).
    A `node_modules` an install rebuilds (package.json beside it, a lockfile there or above) is not data. A status
    that fails is reported as unverified and counts nothing: the clone is then judged by the other evidence."""
    found = {"count": 0, "bytes": 0}
    rc, out = _git(ctx, repo, "status", "--porcelain", "-z", "--ignored", "--untracked-files=normal",
                   "--ignore-submodules=all")
    if rc != 0:
        ctx.note_unverified("git ignored files (status --ignored failed)")
        return found
    budget = [archive.SCAN_BUDGET]
    items = out.split("\0")
    i = 0
    while i < len(items):
        entry = items[i]
        i += 1
        if len(entry) < 4:
            continue
        if entry[:2] != "!!":
            if "R" in entry[:2] or "C" in entry[:2]:
                i += 1  # a rename or copy carries the original path as its own entry
            continue
        if budget[0] <= 0:
            found["approx"] = True  # the entries after this one were not sized
            break
        full = os.path.join(repo, entry[3:])
        st = _lstat(full)
        if st is None:
            continue
        if stat.S_ISDIR(st.st_mode):
            parent = os.path.dirname(full.rstrip("/"))
            if os.path.basename(full.rstrip("/")) == "node_modules" and os.path.isfile(os.path.join(parent, "package.json")) \
                    and _lockfile(parent, repo):
                continue
            size, files, cut = _ignored_tree(full, budget)
            if cut:
                found["approx"] = True
        else:
            size, files = st.st_size, 1
        if size >= archive.IGNORED_MIN_BYTES:
            found["count"] += files
            found["bytes"] += size
    return found


def git_info(ctx: Ctx, repo: str) -> dict:
    """Facts from `git status --porcelain`, `log --branches --not --remotes`, `stash list`. Fails closed.

    "Published" means every commit is reachable from a local remote-tracking ref. The network is never touched, so a
    branch deleted on the server (or a ref that is stale) still counts: `remote_checked` is always False."""
    info = _no_git()
    if not os.path.lexists(os.path.join(repo, ".git")):
        return info
    info["is_repo"] = True
    info["remote_checked"] = False  # "published" below is read from LOCAL remote-tracking refs; no server was contacted
    if not ctx.which("git"):
        info.update(dirty=True, error="git not found: cannot prove clean")
        ctx.note_unverified("git (not found)")
        return info
    # A repo whose own config names a filter, gpg or diff program would run it on status/log: read nothing.
    unsafe = gitguard.unsafe_config(lambda *a: _git(ctx, repo, *a), repo)
    if unsafe:
        info.update(dirty=True, error="repo config can run programs (%s): not inspected, cannot prove clean" % ", ".join(unsafe))
        ctx.note_unverified("git (repo config runs programs)")
        return info
    # Flags beat the repo's own config (status.showUntrackedFiles=no would hide files and fake a clean tree).
    rc, out = _git(ctx, repo, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none")
    if rc != 0:
        info.update(dirty=True, error="git status failed: cannot prove clean")
        return info
    info["dirty"] = bool(out.strip())
    info["ignored_large"] = _ignored_large(ctx, repo)
    rc, out = _git(ctx, repo, "log", "--branches", "--not", "--remotes", "--oneline", "--max-count=100000")
    unpushed = _lines(out) if rc == 0 else 0
    if rc != 0:
        info.update(dirty=True, error="git log failed: cannot prove published")
    rc, out = _git(ctx, repo, "log", "HEAD", "--not", "--remotes", "--oneline", "--max-count=100000")
    head_ok = rc == 0
    head_unpushed = _lines(out) if head_ok else 0  # detached HEAD commits are invisible to --branches
    info["unpushed"] = max(unpushed, head_unpushed)
    rc, out = _git(ctx, repo, "stash", "list")
    info["stash"] = _lines(out) if rc == 0 else 0
    rc, out = _git(ctx, repo, "remote")
    info["remotes"] = _lines(out) if rc == 0 else 0
    info["head_on_remote"] = bool(info["remotes"]) and head_ok and head_unpushed == 0
    rc, out = _git(ctx, repo, "config", "--get", "remote.origin.url")
    if rc == 0 and out.strip():
        info["origin"] = ctx.safety.sanitize_name(_redact_url(out.splitlines()[0]), 200)
    rc, out = _git(ctx, repo, "log", "-1", "--format=%cI")
    if rc == 0 and _ISO_RE.match(out.strip()):
        info["last_commit"] = out.strip()
    return info


def _last_commit_epoch(ctx: Ctx, repo: str) -> Optional[float]:
    if not ctx.which("git"):
        return None
    rc, out = _git(ctx, repo, "log", "-1", "--format=%ct")
    return float(out.strip()) if rc == 0 and out.strip().isdigit() else None


def _gitdir_of(path: str) -> Tuple[bool, Optional[str]]:
    """For a linked worktree (`.git` is a file): (gitdir missing, main repo path)."""
    gp = os.path.join(path, ".git")
    if os.path.islink(gp) or not os.path.isfile(gp):
        return False, None
    try:
        with open(gp, "rb") as fh:
            text = fh.read(1024).decode("utf-8", "replace")
    except OSError:
        return True, None
    m = re.match(r"gitdir:\s*(.+)", text)
    if not m:
        return True, None
    gd = m.group(1).strip()
    if not os.path.isabs(gd):
        gd = os.path.normpath(os.path.join(path, gd))
    main = re.match(r"(.*)[/\\]\.git[/\\]worktrees[/\\][^/\\]+$", gd)
    return (not os.path.isdir(gd)), (main.group(1) if main else None)


def _aggregate_git(infos: List[dict]) -> dict:
    agg = _no_git()
    agg["is_repo"] = bool(infos)
    agg["repos"] = len(infos)
    for g in infos:
        agg["dirty"] = agg["dirty"] or g["dirty"]
        agg["unpushed"] += g["unpushed"]
        agg["stash"] += g["stash"]
        agg["origin"] = agg["origin"] or g["origin"]
        agg["remotes"] += g["remotes"]
        big = g.get("ignored_large") if isinstance(g.get("ignored_large"), dict) else {}
        agg["ignored_large"]["count"] += big.get("count", 0)
        agg["ignored_large"]["bytes"] += big.get("bytes", 0)
        if big.get("approx"):
            agg["ignored_large"]["approx"] = True
        if g.get("last_commit") and (not agg["last_commit"] or g["last_commit"] > agg["last_commit"]):
            agg["last_commit"] = g["last_commit"]
        if g.get("error"):
            agg["error"] = g["error"]
    agg["head_on_remote"] = bool(infos) and all(g["head_on_remote"] for g in infos)
    return agg


# ---------------------------------------------------------------- live state

def _cwd_table(ctx: Ctx) -> List[Tuple[int, str]]:
    """(pid, cwd) of visible processes. lsof where available, /proc otherwise, else unverified."""

    def build() -> List[Tuple[int, str]]:
        rows: List[Tuple[int, str]] = []
        if ctx.os_kind != "windows" and ctx.which("lsof"):
            rc, out = ctx.run(["lsof", "-n", "-P", "-d", "cwd", "-Fpn"], None, 60.0, None)
            if rc in (0, 1):
                pid = -1
                for ln in out.splitlines():
                    if ln.startswith("p") and ln[1:].isdigit():
                        pid = int(ln[1:])
                    elif ln.startswith("n/") and pid >= 0:
                        rows.append((pid, unescape_lsof(ln[1:])))
                return rows
        if os.path.isdir(ctx.proc_dir):
            for e in _entries(ctx.proc_dir):
                if e.name.isdigit():
                    try:
                        rows.append((int(e.name), os.readlink(os.path.join(e.path, "cwd"))))
                    except OSError:
                        continue
            return rows
        ctx.note_unverified("process cwd check (no lsof, no /proc)")
        return rows

    return ctx.memo("cwd_table", build)


def _ps_rows(ctx: Ctx) -> List[dict]:
    """[{pid, etime_s|None, rss_bytes, command}] from `ps` (Unix) or `tasklist` (Windows)."""

    def build() -> List[dict]:
        rows: List[dict] = []
        if ctx.os_kind == "windows":
            rc, out = ctx.run(["tasklist", "/FO", "CSV", "/NH"], None, 30.0, None)
            for ln in out.splitlines():
                parts = [p.strip('"') for p in ln.split('","')]
                if len(parts) >= 2 and parts[1].isdigit():
                    rows.append({"pid": int(parts[1]), "etime_s": None, "rss_bytes": 0, "command": parts[0]})
            if rc != 0:
                ctx.note_unverified("process list (tasklist failed)")
            return rows
        rc, out = ctx.run(["ps", "-axww", "-o", "pid=,etime=,rss=,command="], None, 30.0, None)
        if rc != 0:
            ctx.note_unverified("process list (ps failed)")
            return rows
        for ln in out.splitlines():
            parts = ln.split(None, 3)
            if len(parts) == 4 and parts[0].isdigit():
                rows.append({"pid": int(parts[0]), "etime_s": _etime_seconds(parts[1]),
                             "rss_bytes": int(parts[2]) * 1024 if parts[2].isdigit() else 0, "command": parts[3]})
        return rows

    return ctx.memo("ps_rows", build)


def _etime_seconds(text: str) -> Optional[float]:
    m = re.match(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$", text)
    if not m:
        return None
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return float(d * 86400 + h * 3600 + mi * 60 + s)


_AGENT_RE = re.compile(r"^(?:\S*[/\\])?(claude|codex)(?:\.exe)?(?:\s|$)|(?:^|[\s/\\])(?:@anthropic-ai[/\\]claude-code|@openai[/\\]codex)")


def _agent_pids(ctx: Ctx) -> List[int]:
    return [r["pid"] for r in _ps_rows(ctx) if _AGENT_RE.search(r["command"]) and r["pid"] != os.getpid()]


def _encode_cwd(cwd: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", cwd)


def _live_encoded(ctx: Ctx) -> Set[str]:
    """Claude project-dir names (encoded cwd) of the folders where claude/codex are running now."""
    pids = set(_agent_pids(ctx))
    return {_encode_cwd(cwd) for pid, cwd in _cwd_table(ctx) if pid in pids}


Project = Tuple[str, str]  # ("dir", project folder) | ("enc", Claude project-dir name, the encoded cwd)


def _git_ancestor(start: str, home: str) -> Optional[str]:
    cur = start
    while cur and cur != home and os.path.dirname(cur) != cur:
        if os.path.lexists(os.path.join(cur, ".git")):
            return cur
        cur = os.path.dirname(cur)
    return None


def project_of(category: str, path: str, home: str) -> Optional[Project]:
    """The project a candidate belongs to, whose running processes make it live too. `path` and `home` are real paths.

    E: the project of the node_modules (git root below HOME, else the folder holding it). D: the Claude project of
    the scratch unit `<tmp>/-<encoded cwd>/<uuid>`. F, L: the git repo a cache or build folder sits in (a cache in
    ~/.cache or ~/.npm belongs to no project). None when there is none, or when it is HOME or above: a shell in ~
    does not mean that every folder under it is being worked on.
    """
    if category == "D":
        enc = os.path.basename(os.path.dirname(path))
        home_enc = _encode_cwd(home)
        if not (UUID_RE.match(os.path.basename(path)) and enc.startswith("-")) or enc == home_enc or home_enc.startswith(enc + "-"):
            return None
        return ("enc", enc)
    if category == "E" and os.path.basename(path) == "node_modules":
        root = project_root_of(home, os.path.dirname(path))
    elif category in ("F", "L"):
        root = _git_ancestor(os.path.dirname(path), home) or ""
    else:
        return None
    if not root or root == home or home.startswith(root.rstrip(os.sep) + os.sep):
        return None
    return ("dir", root)


def in_project(project: Project, cwd: str) -> bool:
    """True when a process with this cwd works in the project (its folder, or anything below it)."""
    kind, where = project
    if kind == "dir":
        return cwd == where or cwd.startswith(where.rstrip(os.sep) + os.sep)
    enc = _encode_cwd(cwd)  # lossy (every non-alphanumeric is "-"): a false match only keeps an item, never frees one
    return enc == where or enc.startswith(where + "-")


def _live_reasons(ctx: Ctx, real: str, mtime: float, project: Optional[Project] = None) -> List[str]:
    reasons: List[str] = []
    if ctx.now - mtime < LIVE_WINDOW_S:
        reasons.append("modified within the last hour")
    prefix = real.rstrip(os.sep) + os.sep
    table = _cwd_table(ctx)
    for pid, cwd in table:
        if (cwd + os.sep).startswith(prefix):
            reasons.append("cwd of pid %d" % pid)
    if project:
        pid = next((p for p, cwd in table if in_project(project, cwd)), None)
        if pid is not None:  # `bun run dev` sits in the folder that holds node_modules, not inside it
            reasons.append("a process works in the project (pid %d)" % pid)
    return reasons


# ---------------------------------------------------------------- candidate builder

def _age_days(ctx: Ctx, mtime: float) -> int:
    return int(max(0.0, ctx.now - mtime) // DAY)


def _cand(ctx: Ctx, category: str, kind: str, path: str, owner: str, *, min_age: Optional[int] = None,
          action: str = "trash", git: Any = None, tool_command: Optional[str] = None,
          reason: str = "", ev: Optional[dict] = None, live_hint: Optional[str] = None,
          list_only: bool = False) -> Optional[dict]:
    st = _lstat(path)
    if st is None or stat.S_ISLNK(st.st_mode):
        return None  # vanished, or a symlink: never a candidate (SPEC trava 3)
    real = os.path.realpath(path)
    protected, why_prot = ctx.safety.is_protected(real)
    cloud, why_cloud = ctx.safety.is_cloud_or_placeholder(real)
    if min_age is not None and _age_days(ctx, st.st_mtime) < min_age:
        return None  # the root alone is too young; the newest mtime of the tree can only be younger still
    # A candidate with a minimum age is dropped as soon as one entry is younger than it: stop the walk there
    # (the margin keeps the early exit strictly inside the exact age test below, never past it).
    fresh_after = ctx.now - min_age * DAY + 1.0 if min_age else None
    m = Measure(mtime=st.st_mtime) if cloud else measure(real, fresh_after=fresh_after)  # never walk a cloud tree
    if m.fresh:
        return None
    mtime = m.mtime or st.st_mtime
    age = _age_days(ctx, mtime)
    if min_age is not None and age < min_age:
        return None
    live = _live_reasons(ctx, real, mtime, project_of(category, real, os.path.realpath(str(ctx.home))))
    if live_hint:
        live.append(live_hint)
    if cloud:
        git = None  # never run git inside a synced tree
    git = (git() if callable(git) else git) or _no_git()
    why = [reason] if reason else []
    if protected:
        why.append("deny list: " + str(why_prot))
    if cloud:
        why.append("cloud or placeholder: " + str(why_cloud))
    if live:
        why.append("live state: " + live[0])
    if protected or cloud or live or list_only:
        action = "list_only"
    elif tool_command:
        action = "tool_command"
    elif git["is_repo"] and (git["dirty"] or git["unpushed"] or git["stash"]):
        action = "archive_then_trash"
    evidence = {
        "git": git, "age_days": age, "live_process": bool(live), "live_reasons": live,
        "referenced_by": [], "referenced_by_total": 0, "keep_note": False,
        "cloud": bool(cloud), "protected": bool(protected), "reason": "; ".join(why),
        "tool_command": tool_command, "unverified": [],
        "size": {"entries": m.entries, "truncated": m.truncated, "unreadable": m.unreadable,
                 "method": "st_size" if ctx.os_kind == "windows" else "st_blocks",
                 "upper_bound": ctx.os_kind == "macos"},  # APFS clones share blocks: the real gain is measured by free space
    }
    if cloud:
        evidence["size"]["skipped"] = "cloud or placeholder: not walked"
    lexical = os.path.abspath(path)
    if lexical != real:  # a linked ancestor (~/.cache -> a volume): files cite the path they typed, not the real one
        evidence["alias_paths"] = [lexical]
    evidence.update(ev or {})
    return {"category": category, "kind": kind, "path": real, "virtual": False, "bytes": m.bytes,
            "mtime": mtime, "owner": owner, "action": action, "evidence": evidence}


def _virtual(ctx: Ctx, category: str, kind: str, path: str, owner: str, *, size: int = 0, mtime: float = 0.0,
             reason: str = "", ev: Optional[dict] = None, live: bool = False) -> dict:
    evidence = {
        "git": _no_git(), "age_days": int(max(0.0, ctx.now - mtime) // DAY) if mtime else 0,
        "live_process": live, "live_reasons": ["running process"] if live else [],
        "referenced_by": [], "referenced_by_total": 0, "keep_note": False, "cloud": False, "protected": False,
        "reason": reason, "tool_command": None, "unverified": [],
    }
    evidence.update(ev or {})
    return {"category": category, "kind": kind, "path": path, "virtual": True, "bytes": size, "mtime": mtime,
            "owner": owner, "action": "list_only", "evidence": evidence}


def _add(out: List[dict], cand: Optional[dict]) -> None:
    if cand is not None:
        out.append(cand)


# ---------------------------------------------------------------- A: agent history

def _known_projects(ctx: Ctx) -> List[str]:
    """Working folders of past Claude sessions, read from the `cwd` field of recent transcripts."""

    def build() -> List[str]:
        found: List[str] = []
        pat = re.compile(rb'"cwd"\s*:\s*"((?:[^"\\]|\\.)*)"')
        for proj in _entries(ctx.claude_dir / "projects"):
            if not _is_real_dir(proj):
                continue
            files = [e for e in _entries(proj.path) if e.name.endswith(".jsonl") and _is_real_file(e)]
            files.sort(key=lambda e: -_mtime(e))
            for e in files[:3]:
                try:
                    with open(e.path, "rb") as fh:
                        head = fh.read(65536)
                except OSError:
                    continue
                m = pat.search(head)
                if not m:
                    continue
                try:
                    cwd = json.loads('"' + m.group(1).decode("utf-8", "replace") + '"')
                except ValueError:
                    continue
                if os.path.isdir(cwd):
                    found.append(os.path.realpath(cwd))
                    break
        return sorted(set(found))

    return ctx.memo("known_projects", build)


def _detect_A_claude(ctx: Ctx, out: List[dict]) -> None:
    cd, age = ctx.claude_dir, ctx.age_history_days
    live_enc = _live_encoded(ctx)
    for proj in _entries(cd / "projects"):
        if not _is_real_dir(proj):
            continue
        units = [e for e in _entries(proj.path)
                 if (_is_real_file(e) and e.name.endswith(".jsonl")) or (_is_real_dir(e) and UUID_RE.match(e.name))]
        newest = max(units, key=_mtime, default=None)
        for e in units:
            is_file = _is_real_file(e)
            hint = "agent session open in this folder" if (proj.name in live_enc and e is newest) else None
            _add(out, _cand(ctx, "A", "claude.transcript" if is_file else "claude.session_dir", e.path, "claude",
                            min_age=age, live_hint=hint,
                            reason="Claude %s idle (>= %dd)" % ("transcript" if is_file else "session data", age)))
    flat = (("file-history", "claude.file_history", "dir"), ("debug", "claude.debug", "file"),
            ("shell-snapshots", "claude.shell_snapshot", "file"), ("todos", "claude.todos", "file"),
            ("plans", "claude.plan", "file"))
    for sub, kind, want in flat:
        for e in _entries(cd / sub):
            if (want == "dir" and _is_real_dir(e)) or (want == "file" and _is_real_file(e)):
                _add(out, _cand(ctx, "A", kind, e.path, "claude", min_age=age, reason="Claude %s idle (>= %dd)" % (sub, age)))


def _detect_A_codex(ctx: Ctx, out: List[dict]) -> None:
    xd, age = ctx.codex_dir, ctx.age_history_days
    budget = [MAX_DISCOVERY_DIRS, 0]
    for sub, kind in (("sessions", "codex.session"), ("archived_sessions", "codex.archived_session")):
        root = str(xd / sub)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in _walk(root, 6, lambda n, p: False, time.time() + DISCOVERY_SECONDS, budget):
            for name in files:
                if name.endswith(".jsonl"):
                    _add(out, _cand(ctx, "A", kind, os.path.join(dirpath, name), "codex", min_age=age,
                                    reason="Codex %s idle (>= %dd)" % (sub, age)))
    hist = str(xd / "history.jsonl")
    _add(out, _cand(ctx, "A", "codex.history", hist, "codex", list_only=True,
                    reason="prompt history, trimmed by Codex itself: set [history] max_bytes instead of trashing"))
    for e in _entries(xd / "log"):
        if _is_real_file(e):
            _add(out, _cand(ctx, "A", "codex.log", e.path, "codex", min_age=age, reason="Codex log idle (>= %dd)" % age))
    for e in _entries(xd):
        if _is_real_file(e) and re.match(r"^logs_.*\.sqlite$", e.name):
            _add(out, _cand(ctx, "A", "codex.logs_db", e.path, "codex", list_only=True,
                            reason="SQLite state database: never moved while Codex may run"))
    if budget[1]:
        ctx.warnings.append("codex sessions walk hit its budget: list is partial")


def _detect_A(ctx: Ctx, out: List[dict]) -> None:
    _detect_A_claude(ctx, out)
    _detect_A_codex(ctx, out)


# ---------------------------------------------------------------- C and D: stray clones, scratch

_TOOL_CACHE_NAMES = {"uv", "pip", "npm", "_npx", "pnpm", "bun", "yarn", "go-build", "Homebrew", "ms-playwright",
                     "puppeteer", "huggingface", "torch", "whisper", "node_modules", ".venv", "venv",
                     "site-packages", "__pycache__"}


def _find_repos(ctx: Ctx, root: str, max_depth: int, skip_real: Iterable[str] = ()) -> Tuple[List[str], bool]:
    return find_repos(root, max_depth, skip_real)


def find_repos(root: str, max_depth: int, skip_real: Iterable[str] = ()) -> Tuple[List[str], bool]:
    """Directories under `root` holding a .git (dir or file). Never descends into a repo, node_modules, tool caches.

    Returns (repos, truncated); truncated means the walk hit its budget and may have missed some.
    """
    skip = {os.path.realpath(s) for s in skip_real}
    repos: List[str] = []
    budget = [MAX_DISCOVERY_DIRS, 0]

    def prune(name: str, path: str) -> bool:
        if name in _TOOL_CACHE_NAMES and name != "node_modules" and os.path.lexists(os.path.join(path, ".git")):
            return False  # a clone named like a tool (whisper, bun, uv, pip) is a repo, not a cache
        return name in _TOOL_CACHE_NAMES or bool(skip and os.path.realpath(path) in skip)

    if os.path.lexists(os.path.join(root, ".git")):
        return [root], False
    for dirpath, dirnames, filenames in _walk(root, max_depth, prune, time.time() + DISCOVERY_SECONDS, budget, True):
        if ".git" in dirnames or ".git" in filenames:
            repos.append(dirpath)
            dirnames[:] = []
    return repos, bool(budget[1])


def _shared_dirs(ctx: Ctx) -> Set[str]:
    """Real paths of folders that belong to nobody in particular (system temp bases, $TMPDIR/$TMP/$TEMP, HOME)."""
    shared = {os.path.realpath(b) for b in ctx.tmp_bases}
    shared.add(os.path.realpath(str(ctx.tmp_dir)))
    shared.add(os.path.realpath(str(ctx.home)))
    for var in ("TMPDIR", "TMP", "TEMP"):
        p = ctx._expand(ctx.env.get(var))
        if p is not None:
            shared.add(os.path.realpath(str(p)))
    return shared


def claude_tmp_roots(ctx: Ctx) -> List[str]:
    cands: List[Path] = []
    base = ctx.env.get("CLAUDE_CODE_TMPDIR")
    if base:
        b = ctx._expand(base)
        sub = b / ("claude-%s" % ctx.uid) if (b and ctx.uid is not None) else None
        if sub is not None and sub.is_dir():
            cands.append(sub)
        elif b is not None and os.path.realpath(str(b)) not in _shared_dirs(ctx):
            cands.append(b)  # a folder set apart for Claude; a shared temp dir or HOME is never one: it holds other tools' folders
    if ctx.os_kind == "windows":
        t = ctx.env.get("TEMP") or ctx.env.get("TMP")
        if t:
            cands.append(Path(t) / "claude")
    elif ctx.uid is not None:
        cands.extend(Path(b) / ("claude-%d" % ctx.uid) for b in ctx.tmp_bases)
    roots: List[str] = []
    for c in cands:
        if c.is_dir() and not c.is_symlink() and os.path.realpath(c) not in roots:  # a planted link would make its target scratch
            roots.append(os.path.realpath(c))
    return roots


def _scratch_units(root: str) -> List[Tuple[str, Optional[str]]]:
    """(unit path, project dir name or None). `<root>/-<proj>/<session-uuid>` is one unit; anything else directly
    under the root is its own unit."""
    units: List[Tuple[str, Optional[str]]] = []
    for e in _entries(root):
        if e.is_symlink():
            continue
        sessions = [s for s in _entries(e.path) if _is_real_dir(s) and UUID_RE.match(s.name)] if (
            e.name.startswith("-") and _is_real_dir(e)) else []
        if sessions:
            units.extend((s.path, e.name) for s in sessions)
        else:
            units.append((e.path, None))
    return units


def _detect_D(ctx: Ctx, out: List[dict]) -> Set[str]:
    """Claude scratch units older than AGE_SCRATCH_DAYS. Returns the real tmp roots (their repos belong to a unit)."""
    live_enc = _live_encoded(ctx)
    claimed: Set[str] = set()
    for root in claude_tmp_roots(ctx):
        claimed.add(root)
        units = _scratch_units(root)

        def unit_cand(unit: Tuple[str, Optional[str]]) -> Optional[dict]:
            path, proj = unit
            # every unit of the project, not only the newest: an older session may still be open (resumed, or a
            # second terminal), and the agent writes into its unit by path
            hint = "agent session open in this folder" if proj in live_enc else None
            ev: Dict[str, Any] = {}

            def repo_git() -> dict:
                repos, truncated = _find_repos(ctx, path, 6) if _is_real_dir_path(path) else ([], False)
                if repos:
                    ev["repos"] = [ctx.safety.sanitize_name(os.path.basename(r), 80) for r in repos]
                if truncated:
                    ev["unverified"] = ["repo search inside this unit hit its budget"]
                    ev["search_truncated"] = True
                return _aggregate_git([git_info(ctx, r) for r in repos]) if repos else _no_git()

            return _cand(ctx, "D", "claude.scratch", path, "claude", min_age=ctx.age_scratch_days, git=repo_git,
                         live_hint=hint, ev=ev, reason="Claude scratch idle (>= %dd)" % ctx.age_scratch_days)

        for cand in _pmap(unit_cand, units):
            _add(out, cand)
    return claimed


def _is_real_dir_path(path: str) -> bool:
    st = _lstat(path)
    return bool(st and stat.S_ISDIR(st.st_mode))


def _stray_roots(ctx: Ctx) -> List[Tuple[str, int, str]]:
    roots: List[Tuple[str, int, str]] = [(str(ctx.home / ".cache"), 6, "unknown"),
                                         (str(ctx.codex_dir / "cache"), 6, "codex"),
                                         (str(ctx.codex_dir / "tmp"), 6, "codex"),
                                         (str(ctx.codex_dir / ".tmp"), 6, "codex")]
    seen: Set[str] = set()
    for b in ctx.tmp_bases:
        rb = os.path.realpath(b)
        if rb not in seen:
            seen.add(rb)
            roots.append((rb, 3, "unknown"))
    return [r for r in roots if os.path.isdir(r[0])]


def _detect_C(ctx: Ctx, out: List[dict], claude_roots: Set[str]) -> List[str]:
    """Stray clones in caches and temp dirs. Returns the repo paths found (also used for worktree discovery)."""
    found: List[str] = []
    seen: Set[str] = set()
    for root, depth, owner in _stray_roots(ctx):
        repos, truncated = _find_repos(ctx, root, depth, skip_real=claude_roots)
        if truncated:
            ctx.warnings.append("stray clone search under %s stopped at %d levels or at its budget: deeper clones are not listed"
                                % (ctx.safety.sanitize_name(root, 120), depth))
        fresh: List[str] = []
        for r in repos:
            rr = os.path.realpath(r)
            if rr not in seen and rr not in claude_roots:
                seen.add(rr)
                fresh.append(rr)
        found.extend(fresh)
        for cand in _pmap(lambda rr, owner=owner: _cand(ctx, "C", "scratch.clone", rr, owner,
                                                      git=lambda: git_info(ctx, rr),
                                                      reason="git clone outside project folders"), fresh):
            _add(out, cand)
    return found


# ---------------------------------------------------------------- B: worktrees

def _parse_worktrees(text: str) -> List[dict]:
    blocks: List[dict] = []
    cur: Dict[str, Any] = {}
    for ln in text.splitlines() + [""]:
        if not ln.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        key, _, val = ln.partition(" ")
        cur[key] = val or True
    return blocks


def _local_only_note(ctx: Ctx, real: str, main: Optional[str]) -> bool:
    """True when a note says the branch checked out in this worktree is local on purpose (never push, local-only).

    repos.never_push does the reading: note-like files of the work tree, the same files committed at the tip of
    HEAD, and `branch.<b>.description`; a line that names no branch of the repo covers every branch, and notes it
    could not read to the end do too (fail closed: the worktree is kept). It runs on the worktree and on its main
    repo, because the note may live only there. A detached HEAD is covered only by a note that names no branch."""
    from . import repos  # lazy: repos imports this module

    def run_in(repo: str) -> Callable[..., Tuple[int, str]]:
        return lambda *args: _git(ctx, repo, *args)

    def tip_of(repo: str) -> List[str]:
        rc, sha = run_in(repo)("rev-parse", "-q", "--verify", "HEAD")
        return [sha.strip()] if rc == 0 and sha.strip() else []

    run = run_in(real)
    rc, refs = run("for-each-ref", "--format=%(refname)", "refs/heads")
    names = [ln[len("refs/heads/"):] for ln in refs.splitlines() if ln.startswith("refs/heads/")] if rc == 0 else []
    rc, sym = run("symbolic-ref", "-q", "HEAD")
    branch = sym.strip()[len("refs/heads/"):] if rc == 0 and sym.strip().startswith("refs/heads/") else None

    def covers(found: Dict[str, Any]) -> bool:
        return bool(found["all"]) or (branch is not None and branch in found["branches"])

    if covers(repos.never_push(real, names, run, tip_of(real))):
        return True
    if main and os.path.isdir(main) and os.path.realpath(main) != real:
        found = ctx.memo("never_push:" + main, lambda: repos.never_push(main, names, run_in(main), tip_of(main)))
        return covers(found)
    return False


def _worktree_cand(ctx: Ctx, path: str, owner: str, main: Optional[str], prunable: bool,
                   out: List[dict], seen: Set[str]) -> None:
    real = os.path.realpath(path)
    if real in seen or not os.path.isdir(real):
        return
    seen.add(real)
    gp = os.path.join(real, ".git")
    if os.path.islink(gp) or not os.path.isfile(gp):
        # git names it, but the folder holds no `.git` file: a stale or forged worktree entry, never a candidate
        ev0: Dict[str, Any] = {"gitdir_missing": False, "prunable": prunable, "not_a_worktree": True}
        if main:
            ev0["main_repo"] = main
            ev0["followup_command"] = "git -C %s worktree prune" % shlex.quote(main)
        _add(out, _cand(ctx, "B", "worktree", real, owner, ev=ev0, list_only=True,
                        reason="listed by git as a worktree but holds no .git file: shown only"))
        return
    missing, main_from_file = _gitdir_of(real)
    # A worktree of an agent is always listed (evidence says how idle). One of the user's own, beside the
    # projects, is listed only when idle or broken.
    min_age = AGE_USER_WORKTREE_DAYS if (owner == "user" and not (prunable or missing)) else None
    main = main or main_from_file
    ev: Dict[str, Any] = {"gitdir_missing": missing, "prunable": prunable}
    if main:
        ev["main_repo"] = main
        ev["followup_command"] = "git -C %s worktree prune" % shlex.quote(main)
    why = "worktree" + (" with a missing gitdir" if missing else "") + (" (git says prunable)" if prunable else "")
    cand = _cand(ctx, "B", "worktree", real, owner, min_age=min_age, git=lambda: git_info(ctx, real), ev=ev,
                 reason=why)
    # A branch kept local on purpose is the owner's call, whatever git says about "published": keep it, like a keep note.
    if (cand is not None and cand["action"] != "list_only" and not cand["evidence"]["git"].get("error")
            and _local_only_note(ctx, real, main)):
        cand["evidence"].update(keep_note=True, local_only_note=True)
        cand["evidence"]["reason"] += "; a note in the repo says this branch is local-only (never push)"
    _add(out, cand)


def _worktree_owner(ctx: Ctx, path: str) -> str:
    real = os.path.realpath(path)
    if (os.sep + ".claude" + os.sep + "worktrees" + os.sep) in real + os.sep or real.startswith(
            str(ctx.claude_dir / "worktrees") + os.sep):
        return "claude"
    if real.startswith(os.path.realpath(str(ctx.codex_dir / "worktrees")) + os.sep):
        return "codex"
    return "user"


def _detect_B(ctx: Ctx, out: List[dict], repos: List[str]) -> None:
    seen: Set[str] = set()
    synced = {r: bool(ctx.safety.is_cloud_or_placeholder(r)[0]) for r in repos}  # reading a synced repo can download it
    have_git = bool(ctx.which("git"))
    listed = [r for r in repos if not synced[r]] if have_git else []
    listings = dict(zip(listed, _pmap(lambda r: _git(ctx, r, "worktree", "list", "--porcelain"), listed)))
    for repo in repos:
        if synced[repo]:
            ctx.note_unverified("worktrees of a cloud-synced repo not listed")
            continue
        for e in _entries(os.path.join(repo, ".claude", "worktrees")):
            if _is_real_dir(e):
                _worktree_cand(ctx, e.path, "claude", repo, False, out, seen)
        if not have_git:
            ctx.note_unverified("git worktree list (git not found)")
            continue
        rc, text = listings[repo]
        if rc != 0:
            continue
        for blk in _parse_worktrees(text)[1:]:  # the first block is the main working tree
            wt = blk.get("worktree")
            if isinstance(wt, str) and not blk.get("bare"):
                _worktree_cand(ctx, wt, _worktree_owner(ctx, wt), repo, "prunable" in blk, out, seen)
    cw = str(ctx.codex_dir / "worktrees")
    if os.path.isdir(cw):
        for dirpath, dirnames, _files in _walk(cw, 2, lambda n, p: False, time.time() + DISCOVERY_SECONDS,
                                               [MAX_DISCOVERY_DIRS, 0]):
            if dirpath != cw and os.path.lexists(os.path.join(dirpath, ".git")):
                _worktree_cand(ctx, dirpath, "codex", None, False, out, seen)
                dirnames[:] = []


# ---------------------------------------------------------------- E: idle node_modules

_E_PRUNE = {"Library", "Applications", "Movies", "Music", "Pictures", "venv", "site-packages", "__pycache__",
            "target", "vendor"}


def project_root_of(home: str, parent: str) -> str:
    """The git root above `parent` (below HOME), else `parent` itself."""
    return _git_ancestor(parent, home) or parent


def _project_root(ctx: Ctx, parent: str) -> str:
    return project_root_of(os.path.realpath(str(ctx.home)), parent)


def _lockfile(parent: str, root: str) -> Optional[str]:
    cur = parent
    while True:
        for name in LOCKFILES:
            if os.path.isfile(os.path.join(cur, name)):
                return name
        if cur == root or os.path.dirname(cur) == cur:
            return None
        cur = os.path.dirname(cur)


def _idle_days(ctx: Ctx, root: str) -> Tuple[Optional[float], bool]:
    """Days since the newest edit outside node_modules/.git or the last commit. (None, True) = cannot prove.

    The caller only compares the result with age_node_modules_days, so the first sign of life ends the search:
    that project is returned with the idle days seen so far (already under the limit), without reading the rest."""
    alive_after = ctx.now - ctx.age_node_modules_days * DAY + 1.0  # margin: never past the exact age test

    def alive(newest: float) -> Tuple[Optional[float], bool]:
        return max(0.0, ctx.now - newest) / DAY, False

    newest = 0.0
    # not FETCH_HEAD (an auto-fetch) nor index (any `git status` may rewrite it): neither is an edit
    for rel in ("HEAD", "ORIG_HEAD", os.path.join("logs", "HEAD")):
        st = _lstat(os.path.join(root, ".git", rel))
        if st:
            newest = max(newest, st.st_mtime)
    if newest > alive_after:
        return alive(newest)
    walked, truncated = newest_mtime(root, {"node_modules", ".git"}, stop_after=alive_after)
    newest = max(newest, walked)
    if newest > alive_after:
        return alive(newest)
    commit = _last_commit_epoch(ctx, root)
    if commit:
        newest = max(newest, commit)
    if truncated or not newest:
        return None, True
    return max(0.0, ctx.now - newest) / DAY, False


def _detect_E(ctx: Ctx, out: List[dict], skip_roots: Iterable[str]) -> None:
    home = str(ctx.home)
    skip = {os.path.realpath(s) for s in skip_roots}
    budget = [MAX_DISCOVERY_DIRS, 0]
    idle_cache: Dict[str, Tuple[Optional[float], bool]] = ctx.memo("idle_days", dict)  # L reads and extends it
    found: List[str] = []
    junk: List[str] = []  # per-project regenerables (_PROJECT_JUNK) seen on the same walk, for L
    cloud_memo: Dict[str, bool] = {}

    def prune(name: str, path: str) -> bool:
        if name.startswith(".") or name in _E_PRUNE or bool(skip and os.path.realpath(path) in skip):
            return True
        if path.count(os.sep) - home.count(os.sep) <= 2:  # synced folders sit at the top of HOME
            if path not in cloud_memo:
                cloud_memo[path] = bool(ctx.safety.is_cloud_or_placeholder(path)[0])
            return cloud_memo[path]
        return False

    for dirpath, dirnames, _files in _walk(home, 7, prune, time.time() + DISCOVERY_SECONDS, budget):
        # `dirnames` still holds the hidden and pruned names here (.venv, .next, target ...): only the descent skips them
        junk.extend(os.path.join(dirpath, d) for d in dirnames if d in _PROJECT_JUNK)
        if "node_modules" in dirnames:
            found.append(os.path.join(dirpath, "node_modules"))
            dirnames.remove("node_modules")
    ctx.memo("project_junk", lambda: {"found": junk, "partial": bool(budget[1])})
    if budget[1]:
        ctx.warnings.append("node_modules search hit its budget: list is partial")
    todo: List[Tuple[str, str, str]] = []  # (node_modules, project root, lockfile) of the synced-free ones
    for nm in found:
        parent = os.path.dirname(nm)
        if not os.path.isfile(os.path.join(parent, "package.json")):
            continue
        root = _project_root(ctx, parent)
        lock = _lockfile(parent, root)
        if not lock:
            continue
        if ctx.safety.is_cloud_or_placeholder(root)[0] or ctx.safety.is_cloud_or_placeholder(nm)[0]:
            _add(out, _cand(ctx, "E", "node_modules", nm, "user", reason="inside a cloud-synced folder"))
            continue
        todo.append((nm, root, lock))
    roots = sorted({root for _nm, root, _lock in todo})  # one idle probe per project, run side by side
    ctx.memo("e_project_roots", lambda: roots)  # the dependency search reads these projects whole
    idle_cache.update(zip(roots, _pmap(lambda r: _idle_days(ctx, r), roots)))
    for nm, root, lock in todo:
        idle, unproven = idle_cache[root]
        if not unproven and idle is not None and idle < ctx.age_node_modules_days:
            continue
        ev = {"project": root, "project_idle_days": None if idle is None else int(idle), "reinstall": LOCKFILES[lock]}
        g = _no_git()
        g["is_repo"] = os.path.lexists(os.path.join(root, ".git"))  # status is not needed: node_modules is derived
        why = ("project idle %dd (>= %dd), lockfile %s" % (int(idle), ctx.age_node_modules_days, lock)
               if idle is not None else "project too large to prove idle")
        _add(out, _cand(ctx, "E", "node_modules", nm, "user", git=g, ev=ev, reason=why, list_only=unproven))


# ---------------------------------------------------------------- F and G: tool caches, models

# {home} {xdg_cache} {xdg_data} {lib_caches} {localappdata} {userprofile} {cargo_home} {gopath} {bun_install}
_CACHE_SPECS: List[Dict[str, Any]] = [
    dict(kind="cache.uv", env=("UV_CACHE_DIR",), dir_cmd=("uv", "cache", "dir"), bins=("uv",), clean="uv cache clean",
         paths={"macos": ["{xdg_cache}/uv"], "linux": ["{xdg_cache}/uv"], "windows": ["{localappdata}/uv/cache"]}),
    dict(kind="cache.pip", env=("PIP_CACHE_DIR",), dir_cmd=("{bin}", "cache", "dir"), bins=("pip", "pip3"),
         clean="{bin} cache purge",
         paths={"macos": ["{lib_caches}/pip"], "linux": ["{xdg_cache}/pip"], "windows": ["{localappdata}/pip/Cache"]}),
    dict(kind="cache.npm", env=("npm_config_cache",), dir_cmd=("npm", "config", "get", "cache"), bins=("npm",),
         clean="npm cache clean --force",
         paths={"macos": ["{home}/.npm"], "linux": ["{home}/.npm"], "windows": ["{localappdata}/npm-cache"]}),
    dict(kind="cache.pnpm_store", env=("npm_config_store_dir",), dir_cmd=("pnpm", "store", "path"), bins=("pnpm",),
         clean="pnpm store prune", note="hardlinked into projects: the real gain is smaller than the size",
         paths={"macos": ["{home}/Library/pnpm/store"], "linux": ["{xdg_data}/pnpm/store"],
                "windows": ["{localappdata}/pnpm/store"]}),
    dict(kind="cache.bun", env=("BUN_INSTALL_CACHE_DIR",), dir_cmd=None, bins=("bun",), clean="bun pm cache rm",
         paths={"macos": ["{bun_install}/install/cache"], "linux": ["{bun_install}/install/cache"],
                "windows": ["{bun_install}/install/cache"]}),
    dict(kind="cache.yarn", env=("YARN_CACHE_FOLDER",), dir_cmd=None, bins=("yarn",), clean="yarn cache clean",
         paths={"macos": ["{lib_caches}/Yarn"], "linux": ["{xdg_cache}/yarn"], "windows": ["{localappdata}/Yarn/Cache"]}),
    dict(kind="cache.cargo_registry", env=(), dir_cmd=None, bins=("cargo-cache",), clean="cargo cache --autoclean",
         note="cargo has no built-in clean command: needs the cargo-cache plugin",
         paths={"macos": ["{cargo_home}/registry"], "linux": ["{cargo_home}/registry"],
                "windows": ["{cargo_home}/registry"]}),
    dict(kind="cache.cargo_git", env=(), dir_cmd=None, bins=("cargo-cache",), clean="cargo cache --autoclean",
         note="cargo has no built-in clean command: needs the cargo-cache plugin",
         paths={"macos": ["{cargo_home}/git"], "linux": ["{cargo_home}/git"], "windows": ["{cargo_home}/git"]}),
    dict(kind="cache.go_build", env=("GOCACHE",), dir_cmd=("go", "env", "GOCACHE"), bins=("go",),
         clean="go clean -cache",
         paths={"macos": ["{lib_caches}/go-build"], "linux": ["{xdg_cache}/go-build"],
                "windows": ["{localappdata}/go-build"]}),
    dict(kind="cache.go_mod", env=("GOMODCACHE",), dir_cmd=("go", "env", "GOMODCACHE"), bins=("go",),
         clean="go clean -modcache",
         paths={"macos": ["{gopath}/pkg/mod"], "linux": ["{gopath}/pkg/mod"], "windows": ["{gopath}/pkg/mod"]}),
    dict(kind="cache.homebrew", env=("HOMEBREW_CACHE",), dir_cmd=("brew", "--cache"), bins=("brew",),
         clean="brew cleanup --prune=all",
         note="the command also removes old versions of installed formulae and other Homebrew leftovers, not only downloads",
         paths={"macos": ["{lib_caches}/Homebrew"], "linux": ["{xdg_cache}/Homebrew"], "windows": []}),
    # npx resolves ./node_modules/.bin before anything else and downloads what it cannot find: --no-install
    # keeps it to a tool that is already installed (no download, no install scripts), and SKILL step 11 runs it from ~
    dict(kind="cache.playwright", env=("PLAYWRIGHT_BROWSERS_PATH",), dir_cmd=None, bins=("npx",),
         clean="npx --no-install playwright uninstall --all",
         note="--no-install downloads nothing: the command fails when playwright is not already installed",
         paths={"macos": ["{lib_caches}/ms-playwright"], "linux": ["{xdg_cache}/ms-playwright"],
                "windows": ["{localappdata}/ms-playwright"]}),
    dict(kind="cache.puppeteer", env=("PUPPETEER_CACHE_DIR",), dir_cmd=None, bins=("npx",),
         clean="npx --no-install @puppeteer/browsers clear --path {path}",
         note="--no-install downloads nothing: the command fails when @puppeteer/browsers is not already installed; it asks yes/No on stdin",
         paths={"macos": ["{home}/.cache/puppeteer"], "linux": ["{home}/.cache/puppeteer"],
                "windows": ["{userprofile}/.cache/puppeteer"]}),
    dict(kind="cache.scoop", env=(), dir_cmd=None, bins=("scoop",), clean="scoop cache rm *",
         paths={"macos": [], "linux": [], "windows": ["{userprofile}/scoop/cache"]}),
]

# G: models are listed, never cleaned by a command: the user picks which one goes.
_MODEL_SPECS: List[Dict[str, Any]] = [
    dict(kind="model.ollama", env=("OLLAMA_MODELS",), hint="ollama list; ollama rm <model>",
         paths=["{home}/.ollama/models"]),
    dict(kind="model.torch", env=("TORCH_HOME",), hint="no cleanup command: delete a checkpoint by hand",
         paths=["{xdg_cache}/torch"]),
    dict(kind="model.whisper", env=(), hint="no cleanup command: delete a model file by hand",
         paths=["{xdg_cache}/whisper"]),
    dict(kind="model.lmstudio", env=(), hint="LM Studio, My Models, or delete a model folder by hand",
         paths=["{home}/.lmstudio/models", "{xdg_cache}/lm-studio/models"]),
    dict(kind="model.llamacpp", env=("LLAMA_CACHE",), hint="no cleanup command: delete a .gguf file by hand",
         paths=["{xdg_cache}/llama.cpp", "{lib_caches}/llama.cpp"]),
]


def clean_commands_for(path: str) -> Set[str]:
    """Every clean command `_detect_F` can build for a cache at `path`. plan.py accepts no other tool_command."""
    out: Set[str] = set()
    for spec in _CACHE_SPECS:
        template = spec.get("clean")
        if template:
            for name in spec["bins"]:
                out.add(template.replace("{bin}", name).replace("{path}", shlex.quote(path)))
    return out


def _template(ctx: Ctx, text: str) -> str:
    h = str(ctx.home)
    return text.format(
        home=h, userprofile=h, lib_caches=h + "/Library/Caches",
        xdg_cache=ctx.env.get("XDG_CACHE_HOME") or h + "/.cache",
        xdg_data=ctx.env.get("XDG_DATA_HOME") or h + "/.local/share",
        localappdata=ctx.env.get("LOCALAPPDATA") or h + "/AppData/Local",
        cargo_home=ctx.env.get("CARGO_HOME") or h + "/.cargo",
        gradle_home=ctx.env.get("GRADLE_USER_HOME") or h + "/.gradle",
        gopath=(ctx.env.get("GOPATH") or h + "/go").split(os.pathsep)[0],
        bun_install=ctx.env.get("BUN_INSTALL") or h + "/.bun",
    )


def _existing_dirs(candidates: Iterable[str]) -> List[str]:
    found: List[str] = []
    real: List[str] = []
    for p in candidates:
        if p and os.path.isabs(p) and os.path.isdir(p) and os.path.realpath(p) not in real:
            found.append(p)
            real.append(os.path.realpath(p))
    return found


def _cache_dirs(ctx: Ctx, spec: Dict[str, Any], bin_name: Optional[str]) -> List[str]:
    """Env override first, then what the tool itself says, then the OS default. Existing dirs only, deduped."""
    forced = [str(ctx._expand(ctx.env[v])) for v in spec.get("env", ()) if ctx.env.get(v) and ctx.env[v] != "0"]
    if forced:
        return _existing_dirs(forced)
    said: List[str] = []
    if spec.get("dir_cmd") and bin_name:
        rc, text = ctx.run([a.replace("{bin}", bin_name) for a in spec["dir_cmd"]], str(ctx.home), 15.0, None)
        if rc == 0 and text.strip():
            said.append(text.splitlines()[0].strip())
    return _existing_dirs(said + [_template(ctx, t) for t in spec["paths"].get(ctx.os_kind, [])])


def _detect_F(ctx: Ctx, out: List[dict]) -> None:
    jobs: List[Tuple[Dict[str, Any], str, Optional[str]]] = []
    for spec in _CACHE_SPECS:
        bin_name = next((b for b in spec["bins"] if ctx.which(b)), None)
        jobs.extend((spec, path, bin_name) for path in _cache_dirs(ctx, spec, bin_name))

    def one(job: Tuple[Dict[str, Any], str, Optional[str]]) -> Optional[dict]:
        spec, path, bin_name = job
        cmd = None
        if bin_name and spec.get("clean"):
            cmd = spec["clean"].replace("{bin}", bin_name).replace("{path}", shlex.quote(path))
        note = spec.get("note", "")
        why = "regenerable tool cache" + ("; " + note if note else "")
        if not cmd:
            why += "; its own clean command is not available on this machine, so it is listed only"
        return _cand(ctx, "F", spec["kind"], path, "tool", tool_command=cmd, list_only=cmd is None, reason=why)

    for cand in _pmap(one, jobs):
        _add(out, cand)


def _detect_G(ctx: Ctx, out: List[dict]) -> None:
    hub = ctx.env.get("HF_HUB_CACHE")
    if not hub and ctx.env.get("HF_HOME"):
        hub = os.path.join(ctx.env["HF_HOME"], "hub")
    hub = str(ctx._expand(hub)) if hub else _template(ctx, "{xdg_cache}/huggingface/hub")
    for e in _entries(hub):
        if _is_real_dir(e) and re.match(r"^(models|datasets|spaces)--", e.name):
            _add(out, _cand(ctx, "G", "model.huggingface", e.path, "tool", list_only=True,
                            ev={"hint": "hf cache ls; hf cache rm <repo>"}, reason="downloaded model: listed, you pick"))
    for spec in _MODEL_SPECS:
        forced = [str(ctx._expand(ctx.env[v])) for v in spec["env"] if ctx.env.get(v)]
        for p in _existing_dirs(forced or [_template(ctx, t) for t in spec["paths"]]):
            _add(out, _cand(ctx, "G", spec["kind"], p, "tool", list_only=True, ev={"hint": spec["hint"]},
                            reason="downloaded models: listed, you pick"))


# ---------------------------------------------------------------- I: duplicates

_COPY_RE = re.compile(r"(\(\d+\)|[ _-]copy|[ _-]copia|[ _-]c[oó]pia)\b|\bcopy of\b", re.I)


def _dup_rank(item: Tuple[str, os.stat_result]) -> Tuple[bool, float, int, str]:
    """Which copy to keep: not named like a copy, then the oldest, then the shortest path."""
    path, st = item
    return bool(_COPY_RE.search(os.path.basename(path))), st.st_mtime, len(path), path


def _hash_file(path: str, partial: bool) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            if partial:
                h.update(fh.read(65536))
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size > 131072:
                    fh.seek(size - 65536)
                    h.update(fh.read(65536))
            else:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


_DUP_SKIP_NAMES = frozenset({"node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git"})


def _detect_I(ctx: Ctx, out: List[dict]) -> None:
    root = str(ctx.home / "Downloads")
    if not os.path.isdir(root):
        return
    if ctx.safety.is_cloud_or_placeholder(root)[0]:
        ctx.warnings.append("Downloads is cloud-synced: duplicate scan skipped (never read synced files)")
        return
    by_size: Dict[int, List[Tuple[str, os.stat_result]]] = {}
    budget = [MAX_DISCOVERY_DIRS, 0]
    def bundle(name: str, _path: str) -> bool:  # a copy inside a package tree or an app bundle is not a duplicate to remove
        return name in _DUP_SKIP_NAMES or name.lower().endswith((".app", ".framework", ".photoslibrary", ".bundle"))

    for dirpath, _dirs, files in _walk(root, 6, bundle, time.time() + DISCOVERY_SECONDS, budget):
        for name in files:
            p = os.path.join(dirpath, name)
            st = _lstat(p)
            if st and stat.S_ISREG(st.st_mode) and st.st_size >= ctx.min_dup_bytes:
                if getattr(st, "st_blocks", 1) == 0:  # dataless placeholder: reading would download it
                    continue
                by_size.setdefault(st.st_size, []).append((p, st))
    for size, items in by_size.items():
        uniq: Dict[Tuple[int, int], Tuple[str, os.stat_result]] = {}
        for p, st in sorted(items, key=_dup_rank):  # hardlinks are one file: keep the best-named path of each
            uniq.setdefault((st.st_dev, st.st_ino), (p, st))
        if len(uniq) < 2:
            continue
        groups: Dict[str, List[Tuple[str, os.stat_result]]] = {}
        for p, st in uniq.values():
            h = _hash_file(p, True)
            if h:
                groups.setdefault(h, []).append((p, st))
        for members in (m for m in groups.values() if len(m) > 1):
            full: Dict[str, List[Tuple[str, os.stat_result]]] = {}
            for p, st in members:
                h = _hash_file(p, False)
                if h:
                    full.setdefault(h, []).append((p, st))
            for digest, copies in full.items():
                if len(copies) < 2:
                    continue
                copies.sort(key=_dup_rank)
                keeper = copies[0][0]
                for p, _st in copies[1:]:
                    _add(out, _cand(ctx, "I", "duplicate", p, "user", ev={
                        "duplicate_key": "sha256:" + digest[:16] + ":%d" % size, "keeper": keeper,
                        "keeper_display": ctx.safety.sanitize_name(keeper, 120), "copies": len(copies)},
                        reason="identical size and sha256 to another file; may be an APFS clone (gain unknown)"))


# ---------------------------------------------------------------- J: what the OS holds

_SNAP_RE = re.compile(r"com\.apple\.TimeMachine\.(\d{4}-\d{2}-\d{2}-\d{6})\.local")
_UNITS = {"B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


def _detect_J(ctx: Ctx, out: List[dict]) -> None:
    h = ctx.home
    if ctx.os_kind == "macos":
        rc, text = ctx.run(["getconf", "DARWIN_USER_TEMP_DIR"], None, 10.0, None)
        if rc == 0 and text.strip():
            xdir = os.path.join(os.path.dirname(text.strip().rstrip("/")), "X")
            for e in _entries(xdir):
                if "code_sign_clone" in e.name and _is_real_dir(e):
                    clones = sum(1 for c in _entries(e.path) if _is_real_dir(c))  # one directory per app copy
                    cand = _cand(ctx, "J", "os.code_sign_clone", e.path, "tool", list_only=True,
                                 ev={"recommend": "reboot", "hint": "released only when the Mac restarts",
                                     "gain_unknown": True, "action": "reboot frees these"},
                                 reason="app signature copy left by a Chromium/Electron app; %d clone(s), the size is a "
                                        "ceiling (APFS clones share blocks), the real gain is unknown" % clones)
                    if cand is not None:
                        # Every clone is counted whole although they share blocks: `bytes` is the sum of the
                        # apparent sizes, never an amount that a cleanup would free.
                        cand["evidence"]["apparent_upper_bound"] = {"bytes": cand["bytes"], "clones": clones}
                    _add(out, cand)
        rc, text = ctx.run(["tmutil", "listlocalsnapshots", "/"], None, 30.0, None)
        for date in dict.fromkeys(_SNAP_RE.findall(text if rc == 0 else "")):
            out.append(_virtual(ctx, "J", "os.tm_snapshot", "tmutil:" + date, "tool",
                                reason="Time Machine local snapshot holds space of deleted files; size not reported by tmutil;"
                                       " macOS deletes it on its own (about 24 h, or sooner when space is needed)",
                                ev={"manual_command": "tmutil deletelocalsnapshots " + date,
                                    "hint": "only to get the space now: no admin, the terminal may need Full Disk Access;"
                                            " printed, never run; the external backup is untouched"}))
        trash = str(h / ".Trash")
    elif ctx.os_kind == "windows":
        t = ctx.env.get("TEMP") or ctx.env.get("TMP")
        if t:
            _add(out, _cand(ctx, "J", "os.temp", t, "unknown", list_only=True, reason="%TEMP% size (old files inside)"))
        trash = ""
    else:
        rc, text = ctx.run(["journalctl", "--disk-usage"], None, 15.0, None)
        m = re.search(r"take up ([\d.]+)([BKMGT])", text) if rc == 0 else None
        if m:
            out.append(_virtual(ctx, "J", "os.journal", "journal:disk-usage", "tool",
                                size=int(float(m.group(1)) * _UNITS[m.group(2)]),
                                reason="systemd journal size", ev={"manual_command": "sudo journalctl --vacuum-time=30d",
                                                                   "hint": "needs root: printed, never run"}))
        trash = os.path.join(ctx.env.get("XDG_DATA_HOME") or str(h / ".local" / "share"), "Trash")
    if trash and os.path.isdir(trash):
        _add(out, _cand(ctx, "J", "os.trash", trash, "user", list_only=True,
                        reason="Trash is not emptied by corecleaner: moved items free space only when you empty it"))


# ---------------------------------------------------------------- K: forgotten processes (list only)

_PROC_EXE = {"ffmpeg", "soffice", "soffice.bin", "inkscape", "mitmdump", "mitmproxy", "mitmweb", "cloudflared",
             "ocrmypdf", "tesseract", "vhs", "auto-editor", "magick", "vips", "chrome-headless-shell", "headless_shell"}
_PROC_ARGS = re.compile(r"--headless|--remote-debugging-port|http\.server|\bphp\s+-S\b|"
                        r"\b(vite|astro|next|wrangler|webpack-dev-server|nodemon|live-server)\b.*\b(dev|serve)\b")


def _detect_K(ctx: Ctx, out: List[dict]) -> None:
    cwds = dict(_cwd_table(ctx))
    for r in _ps_rows(ctx):
        cmd = r["command"]
        exe = os.path.basename(cmd.split(None, 1)[0]) if cmd.strip() else ""
        if r["pid"] == os.getpid() or "--type=" in cmd or _AGENT_RE.search(cmd):
            continue
        if exe.lower().removesuffix(".exe") not in _PROC_EXE and not (ctx.os_kind != "windows" and _PROC_ARGS.search(cmd)):
            continue
        ev = {"pid": r["pid"], "name": ctx.safety.sanitize_name(exe, 60), "rss_bytes": r["rss_bytes"],
              "running_for_s": r["etime_s"]}
        if r["pid"] in cwds:
            ev["cwd"] = ctx.safety.sanitize_name(cwds[r["pid"]], 160)
        out.append(_virtual(ctx, "K", "process", "process:%d" % r["pid"], "unknown", live=True, ev=ev,
                            reason="possibly forgotten process (listed only, never killed)"))


# ---------------------------------------------------------------- L: heavy folders no other category sees (list only)

# Per-project regenerables, found on the node_modules walk (_detect_E). name -> (kind, proof that it is regenerable):
# "derived" = the name alone; "venv" = a pyvenv.cfg inside; "ignored" = the repo's own .gitignore covers it (dist,
# build, target, coverage and Pods can also be tracked source or vendored code).
_PROJECT_JUNK: Dict[str, Tuple[str, str]] = {
    ".wrangler": ("project.wrangler", "derived"), ".build": ("project.swiftpm_build", "derived"),
    ".venv": ("project.venv", "venv"), "venv": ("project.venv", "venv"),
    ".next": ("project.next", "derived"), ".nuxt": ("project.nuxt", "derived"), ".astro": ("project.astro", "derived"),
    ".turbo": ("project.turbo", "derived"), ".parcel-cache": ("project.parcel_cache", "derived"),
    ".gradle": ("project.gradle", "derived"), ".terraform": ("project.terraform", "derived"),
    "dist": ("project.dist", "ignored"), "build": ("project.build", "ignored"), "target": ("project.target", "ignored"),
    "coverage": ("project.coverage", "ignored"), "Pods": ("project.pods", "ignored"),
}
L_PROJECT_SECONDS = 120.0  # idle and status probes of the projects holding such folders; past it they are "not proven"

# Folders the user may want to clear by hand. Always listed, never trashed, size only: no clean command exists, or the
# folder holds more than a cache. kind, paths per OS, why (a fixed label).
_HEAVY_SPECS: List[Dict[str, Any]] = [
    dict(kind="dev.xcode_derived_data", why="Xcode build output; Xcode rebuilds it (close Xcode first)",
         paths={"macos": ["{home}/Library/Developer/Xcode/DerivedData"]}),
    dict(kind="dev.xcode_device_support", why="debug symbols Xcode copied from each connected device; copied again on the next connect",
         paths={"macos": ["{home}/Library/Developer/Xcode/%s DeviceSupport" % n for n in ("iOS", "watchOS", "tvOS", "visionOS")]}),
    dict(kind="dev.core_simulator", why="simulator devices with their installed apps and their data; `xcrun simctl delete unavailable` removes only the broken ones",
         paths={"macos": ["{home}/Library/Developer/CoreSimulator/Devices"]}),
    dict(kind="dev.gradle", why="Gradle download and build cache; no command empties it, it is downloaded again",
         paths={o: ["{gradle_home}/caches"] for o in ("macos", "linux", "windows")}),
    dict(kind="dev.maven", why="Maven local repository; no command empties it, it is downloaded again",
         paths={o: ["{home}/.m2/repository"] for o in ("macos", "linux", "windows")}),
]
_ELECTRON_MARKERS = ("Code Cache", "GPUCache", "Local Storage")  # an app folder holding one of these is Electron/Chromium based
_ELECTRON_CACHES = ("Cache", "Code Cache", "GPUCache", "DawnCache", "GrShaderCache", "ShaderCache", "CachedData",
                    os.path.join("Service Worker", "CacheStorage"))


def _tracked_clean(ctx: Ctx, repo: str, deadline: float) -> bool:
    """No edit to a tracked file (untracked files are not edits of what is tracked). Fails closed on anything unknown."""
    if time.time() > deadline or not ctx.which("git"):
        return False
    if gitguard.unsafe_config(lambda *a: _git(ctx, repo, *a), repo):
        return False  # the repo's config can run programs on status
    rc, out = _git(ctx, repo, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=none")
    return rc == 0 and not out.strip()


def _detect_L_projects(ctx: Ctx, out: List[dict]) -> None:
    """Regenerable folders (.wrangler, .venv, dist ...) inside git repos whose project is idle (the node_modules rule,
    `_idle_days`) and has no change to a tracked file. Active projects keep theirs and are not listed."""
    state = ctx.memo("project_junk", lambda: {"found": [], "partial": False})
    home = str(ctx.home)
    found = set(state["found"])
    roots: Dict[str, List[str]] = {}
    for path in sorted(found):
        up, nested = os.path.dirname(path), False
        while up and up != home and os.path.dirname(up) != up and not nested:
            nested = up in found  # a folder inside another one found here is part of it
            up = os.path.dirname(up)
        root = None if nested else _git_ancestor(os.path.dirname(path), home)
        if root:
            roots.setdefault(root, []).append(path)
    skipped = {"cloud": 0, "unproven": 0}
    for root in [r for r in roots if ctx.safety.is_cloud_or_placeholder(r)[0]]:
        skipped["cloud"] += len(roots.pop(root))  # never probe a synced tree
    deadline = time.time() + L_PROJECT_SECONDS
    idle_cache: Dict[str, Tuple[Optional[float], bool]] = ctx.memo("idle_days", dict)
    todo = [r for r in roots if r not in idle_cache]
    idle_cache.update(zip(todo, _pmap(lambda r: _idle_days(ctx, r) if time.time() < deadline else (None, True), todo)))
    idle_roots: List[str] = []
    for root in roots:
        idle, unproven = idle_cache[root]
        if unproven or idle is None:
            skipped["unproven"] += len(roots[root])
        elif idle >= ctx.age_node_modules_days:
            idle_roots.append(root)
    clean = dict(zip(idle_roots, _pmap(lambda r: _tracked_clean(ctx, r, deadline), idle_roots)))
    jobs: List[Tuple[str, str, str]] = []  # (path, kind, project root)
    for root in idle_roots:
        if not clean[root]:
            continue
        for path in roots[root]:
            kind, proof = _PROJECT_JUNK[os.path.basename(path)]
            if proof == "venv" and not os.path.isfile(os.path.join(path, "pyvenv.cfg")):
                continue
            if proof == "ignored":
                if time.time() > deadline:
                    skipped["unproven"] += 1
                    continue
                if _git(ctx, root, "check-ignore", "-q", "--", path)[0] != 0:
                    continue  # tracked, or just not covered by the repo's .gitignore: it may be source
            jobs.append((path, kind, root))

    def one(job: Tuple[str, str, str]) -> Optional[dict]:
        path, kind, root = job
        g = _no_git()
        g["is_repo"] = True  # status was read for the project as a whole: tracked files are clean
        ev = {"project": root, "project_idle_days": int(idle_cache[root][0] or 0), "regenerable": True}
        return _cand(ctx, "L", kind, path, "user", git=g, ev=ev, list_only=True,
                     reason="regenerable folder of a project idle %dd (>= %dd) with no change to tracked files; listed "
                            "only, size only" % (ev["project_idle_days"], ctx.age_node_modules_days))

    for cand in _pmap(one, jobs):
        _add(out, cand)
    if state["partial"]:
        ctx.warnings.append("regenerable project folder search hit the node_modules walk budget: list is partial")
    if skipped["cloud"] or skipped["unproven"]:
        ctx.warnings.append("regenerable project folders not checked: %d in synced folders, %d in projects whose idle "
                            "time was not proven in time" % (skipped["cloud"], skipped["unproven"]))


def _detect_L_dev(ctx: Ctx, out: List[dict]) -> None:
    jobs: List[Tuple[Dict[str, Any], str]] = []
    for spec in _HEAVY_SPECS:
        jobs.extend((spec, p) for p in _existing_dirs([_template(ctx, t) for t in spec["paths"].get(ctx.os_kind, [])]))

    def one(job: Tuple[Dict[str, Any], str]) -> Optional[dict]:
        spec, path = job
        return _cand(ctx, "L", spec["kind"], path, "tool", list_only=True, reason=spec["why"] + "; listed only, size only")

    for cand in _pmap(one, jobs):
        _add(out, cand)


def _app_data_dir(ctx: Ctx) -> str:
    h = str(ctx.home)
    if ctx.os_kind == "macos":
        return h + "/Library/Application Support"
    if ctx.os_kind == "windows":
        return ctx.env.get("APPDATA") or h + "/AppData/Roaming"
    return ctx.env.get("XDG_CONFIG_HOME") or h + "/.config"


def _detect_L_electron(ctx: Ctx, out: List[dict]) -> None:
    """Cache folders of Electron/Chromium apps (the app folder shows a Code Cache, GPUCache or Local Storage)."""
    jobs: List[Tuple[str, str]] = []
    for app in _entries(_app_data_dir(ctx)):
        if not _is_real_dir(app) or not any(os.path.isdir(os.path.join(app.path, m)) for m in _ELECTRON_MARKERS):
            continue
        for rel in _ELECTRON_CACHES:
            p = os.path.join(app.path, rel)
            if _is_real_dir_path(p):
                jobs.append((p, ctx.safety.sanitize_name(app.name, 60)))

    def one(job: Tuple[str, str]) -> Optional[dict]:
        path, app = job
        return _cand(ctx, "L", "app.electron_cache", path, "tool", list_only=True, ev={"app": app},
                     reason="cache of an Electron/Chromium app; the app rebuilds it; listed only, size only")

    for cand in _pmap(one, jobs):
        _add(out, cand)


def _detect_L_backups(ctx: Ctx, out: List[dict]) -> None:
    """`*.bak*` copies directly inside the Claude config folder (settings.json.bak-2026..., CLAUDE.md.bak)."""
    for e in _entries(ctx.claude_dir):
        if fnmatch.fnmatch(e.name, "*.bak*") and not e.is_symlink():
            _add(out, _cand(ctx, "L", "agent.backup", e.path, "claude", list_only=True,
                            reason="backup copy of an agent file; listed only, size only"))


_DOCKER_UNITS = {"B": 1, "KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9, "TB": 10 ** 12, "PB": 10 ** 15}


def _docker_bytes(text: Any) -> int:
    m = re.match(r"^\s*([\d.]+)\s*([kKMGTP]?B)\b", text) if isinstance(text, str) else None
    return round(float(m.group(1)) * _DOCKER_UNITS[m.group(2).upper()]) if m else 0


def _detect_L_docker(ctx: Ctx, out: List[dict]) -> None:
    """What Docker holds, from `docker system df` when the daemon answers in 5 s. One virtual item; never pruned."""
    if not ctx.which("docker"):
        return
    rc, text = ctx.run(["docker", "system", "df", "--format", "{{json .}}"], None, 5.0, None)
    rows: List[dict] = []
    for ln in text.splitlines() if rc == 0 else []:
        try:
            row = json.loads(ln)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("Type"), str):
            rows.append({"type": ctx.safety.sanitize_name(row["Type"], 30), "size": _docker_bytes(row.get("Size")),
                         "reclaimable": _docker_bytes(row.get("Reclaimable"))})
    if not rows:
        ctx.note_unverified("docker usage (the daemon did not answer within 5 s)")
        return
    out.append(_virtual(
        ctx, "L", "dev.docker", "docker:system-df", "tool", size=sum(r["size"] for r in rows),
        reason="space held by Docker images, containers, volumes and build cache (docker system df); listed only, size only",
        ev={"docker": rows, "manual_command": "docker system prune",
            "hint": "printed, never run; volumes hold data, and Docker Desktop's disk image keeps its size until compacted"}))


def _detect_L(ctx: Ctx, out: List[dict]) -> None:
    for name, fn in (("L projects", _detect_L_projects), ("L dev folders", _detect_L_dev),
                     ("L electron caches", _detect_L_electron), ("L backups", _detect_L_backups),
                     ("L docker", _detect_L_docker)):
        _guard(ctx, name, lambda fn=fn: fn(ctx, out))


# ---------------------------------------------------------------- post-processing

def _resolve_nesting(cands: List[dict]) -> List[dict]:
    """A candidate inside another one is merged into the outer one: trashing the outer moves both, so the
    outer must carry the inner's risk (dirty, unpushed, stash, live, protected, cloud)."""
    real = sorted((c for c in cands if not c["virtual"]), key=lambda c: len(c["path"]))
    kept: Dict[str, dict] = {}
    for c in real:
        if c["path"] in kept:
            continue
        outer = None
        parent = os.path.dirname(c["path"])
        while parent and parent != os.path.dirname(parent):
            if parent in kept:
                outer = kept[parent]
                break
            parent = os.path.dirname(parent)
        if outer is None:
            kept[c["path"]] = c
            continue
        ev, inner = outer["evidence"], c["evidence"]
        og, ig = ev["git"], inner["git"]
        og["is_repo"] = og["is_repo"] or ig["is_repo"]
        og["dirty"] = og["dirty"] or ig["dirty"]
        og["unpushed"] += ig["unpushed"]
        og["stash"] += ig["stash"]
        for key in ("live_process", "cloud", "protected"):
            ev[key] = ev[key] or inner[key]
        ev["live_reasons"] += [r for r in inner["live_reasons"] if r not in ev["live_reasons"]]
        ev.setdefault("contains", []).append({"kind": c["kind"], "bytes": c["bytes"]})
        if ev["live_process"] or ev["cloud"] or ev["protected"]:
            outer["action"] = "list_only"
        elif outer["action"] == "trash" and og["is_repo"] and (og["dirty"] or og["unpushed"] or og["stash"]):
            outer["action"] = "archive_then_trash"
    ordered = list(kept.values()) + [c for c in cands if c["virtual"]]
    return sorted(ordered, key=lambda c: (c["category"], -c["bytes"], c["path"]))


def _ref_roots(ctx: Ctx, projects: Sequence[str]) -> List[str]:
    cd, xd, h = ctx.claude_dir, ctx.codex_dir, ctx.home
    paths = [cd / n for n in ("CLAUDE.md", "settings.json", "settings.local.json", "MEMORY.md", "skills", "commands",
                              "hooks", "scripts", "bin", "agents", "rules", "memory")]
    paths += [xd / n for n in ("AGENTS.md", "config.toml", "skills", "memories", "memory", "hooks")]
    paths += [h / "AGENTS.md", h / "CLAUDE.md", h / ".agents"]
    skip_cd = {"projects", "file-history", "backups", "paste-cache", "shell-snapshots", "debug", "cache", "telemetry",
               "session-env", "statsig", "todos", "downloads", "plans"}
    paths += [Path(e.path) for e in _entries(cd) if _is_real_dir(e) and e.name not in skip_cd]  # any agent dir may hold scripts
    paths += [h / n for n in REF_HOME_FILES + REF_HOME_DIRS]  # user code that lives outside any project folder
    paths += [Path(e.path) / "memory" for e in _entries(cd / "projects")]
    for proj in projects:
        p = Path(proj)
        paths += [p / n for n in ("CLAUDE.md", "AGENTS.md", "package.json", "Makefile", "justfile", "scripts",
                                  os.path.join(".claude", "settings.json"), os.path.join(".claude", "settings.local.json"),
                                  os.path.join(".claude", "skills"), os.path.join(".claude", "commands"),
                                  os.path.join(".claude", "hooks"))]
    return sorted({str(p) for p in paths if p.exists()})


def _mentions(text: str, pat: str, lead: bool = False) -> bool:
    """`pat` cited in `text` as a whole name: `lib` is not cited by `lib-b`, `lib.bak` or `lib2`. lead: it must also
    not be the tail of a longer name (`xref/lib`); the short relative forms ask for it."""
    start = 0
    while True:
        i = text.find(pat, start)
        if i < 0:
            return False
        end = i + len(pat)
        if lead and i > 0 and (text[i - 1].isalnum() or text[i - 1] in "_-."):
            start = i + 1
            continue
        if end >= len(text) or not (text[end].isalnum() or text[end] in "_-."):
            return True
        if text[end] == "." and (end + 1 >= len(text) or not (text[end + 1].isalnum() or text[end + 1] in "_-")):
            return True  # "see ~/x/lib." : a full stop, not an extension
        start = i + 1


def _standalone(text: str, pat: str) -> bool:
    """`pat` names a folder on its own (`cd X && ./lib/run`, `LIBS=X`), not a path that goes through it (`X/other/f`)."""
    start = 0
    while True:
        i = text.find(pat, start)
        if i < 0:
            return False
        end = i + len(pat)
        c0 = text[end] if end < len(text) else ""
        c1 = text[end + 1] if end + 1 < len(text) else ""
        if not c0:
            return True
        if c0.isalnum() or c0 in "_-":
            pass
        elif c0 in "./" and c1 and (c1.isalnum() or c1 in "_-.~$"):
            pass
        else:
            return True
        start = i + 1


def _forms(text: str) -> Set[str]:
    """The text as typed plus its NFC and NFD spelling: macOS stores a name in either, a file may cite the other."""
    return {text, unicodedata.normalize("NFC", text), unicodedata.normalize("NFD", text)}


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _case_insensitive(path: str) -> bool:
    """True when `path` and its case-swapped spelling are the same folder (the macOS and Windows default): a
    citation in the wrong case still works at run time there, so it still counts."""
    swapped = path.swapcase()
    if swapped == path:
        return False
    try:
        return os.path.samestat(os.stat(path), os.stat(swapped))
    except (OSError, ValueError):
        return False


def _env_bases(ctx: Ctx) -> List[Tuple[str, str]]:
    """(variable, folder) for every variable a script may build a path from: $XDG_CACHE_HOME/x, $TMPDIR/x ..."""
    home = str(ctx.home)
    out: Set[Tuple[str, str]] = set()
    for var, default in REF_ENV_BASES:
        raw = ctx.env.get(var)
        values: List[str] = []
        if raw:
            values.append(os.path.join(home, raw[2:]) if raw.startswith("~/") else raw)
        elif default:
            values.append(os.path.join(home, default))
        if var in REF_TMP_VARS:
            values += list(ctx.tmp_bases)
        for value in values:
            if os.path.isabs(value) and value.strip(os.sep):
                out.add((var, value.rstrip(os.sep)))
                out.add((var, os.path.realpath(value).rstrip(os.sep)))
    return sorted(out)


def _abs_spellings(p: str, sep: str) -> Set[str]:
    posix = p.replace(sep, "/") if sep != "/" else p
    out = {p, posix}
    for alias in ("/private/tmp", "/private/var", "/private/etc"):
        if posix == alias or posix.startswith(alias + "/"):
            out.add(posix[len("/private"):])
    return out


def _under(p: str, base: str, sep: str) -> Optional[str]:
    """The part of `p` below the folder `base` (native separators), or None."""
    root = base.rstrip(sep)
    return p[len(root) + 1:] if root and p.startswith(root + sep) and len(p) > len(root) + 1 else None


def _place_forms(homes: Sequence[str], p: str, bases: Sequence[Tuple[str, str]], sep: str) -> Set[str]:
    """Every way a script can write the folder `p`, before NFC/NFD and escaping."""
    forms = _abs_spellings(p, sep)
    for h in homes:
        rel = _under(p, h, sep)
        if not rel:
            continue
        rp = rel.replace(sep, "/")
        forms |= {"~/" + rp, "$HOME/" + rp, "${HOME}/" + rp, '"$HOME"/' + rp, '"${HOME}"/' + rp}
        if sep == "\\":
            forms |= {"%USERPROFILE%\\" + rel, "%USERPROFILE%/" + rp, "$env:USERPROFILE\\" + rel, "$env:USERPROFILE/" + rp}
        if "/" in rp:  # `.npm` alone would match every dotfile mention; two segments name a place
            forms |= {rp, rel}
    for var, base in bases:
        for spelled in _abs_spellings(p, sep):
            rel = _under(spelled, base, sep)
            if not rel:
                continue
            rp = rel.replace(sep, "/")
            forms |= {"$%s/%s" % (var, rp), "${%s}/%s" % (var, rp), '"$%s"/%s' % (var, rp), '"${%s}"/%s' % (var, rp)}
            if "/" in rp:
                forms.add("}/" + rp)  # "${VAR:-default}/rel": the default is whatever the script chose
            if sep == "\\":
                forms |= {"%%%s%%\\%s" % (var, rel), "%%%s%%/%s" % (var, rp)}
    return forms


def _spellings(forms: Iterable[str], rich: bool = True) -> Set[str]:
    """Each form in NFC and NFD; rich: also as JSON writes it (`\\/`, `\\\\`), with a backslash-escaped space, and
    percent-encoded (file:// URLs)."""
    out: Set[str] = set()
    for f in forms:
        for g in _forms(f):
            out.add(g)
            if not rich:
                continue
            if "/" in g:
                out.add(g.replace("/", "\\/"))
            if "\\" in g:
                out.add(g.replace("\\", "\\\\"))
            if " " in g:
                out.add(g.replace(" ", "\\ "))
            if re.match(r"^(/|[A-Za-z]:/)", g):
                encoded = quote(g, safe="/:")
                if encoded != g:
                    out.add(encoded)
    return {x for x in out if x.strip()}


def _ref_patterns(home: Any, path: str, bases: Sequence[Tuple[str, str]] = (), aliases: Sequence[str] = (),
                  rich: bool = True) -> Set[str]:
    """Every way a file can cite `path` (or one of its `aliases`, the names a linked ancestor gives it): absolute,
    ~/, $HOME/, ${HOME}/, relative to HOME, $VAR/ for the folders in `bases`, /tmp for /private/tmp; each in NFC
    and NFD and, when `rich`, JSON-escaped, space-escaped and percent-encoded. A hit on a longer path (a file
    INSIDE the candidate) counts: see _mentions. `home` is one folder or several spellings of it."""
    sep = os.sep
    homes = [home] if isinstance(home, str) else [h for h in home]
    forms: Set[str] = set()
    for p in dict.fromkeys([path, *aliases]):
        forms |= _place_forms(homes, p, bases, sep)
    return _spellings(forms, rich)


def _weak_name_ok(path: str) -> bool:
    """A "possibly cited" guess needs a folder name of REF_WEAK_MIN_NAME characters that is not a generic word."""
    name = os.path.basename(path.rstrip("/\\"))
    return len(name) >= REF_WEAK_MIN_NAME and name.lower() not in REF_WEAK_STOP_NAMES


def _weak_patterns(homes: Sequence[str], path: str, aliases: Sequence[str], plain: bool) -> Tuple[Set[str], Set[str]]:
    """(tails, parents): spellings that may mean the candidate without naming it whole. tails: its last two names
    written as separate strings (`"ref", "lib"`, `"ref" / "lib"`, and `ref/lib` when `plain`); parents: a folder one
    or two levels up, deep enough to be specific, which a script may extend at run time (`cd X && ./lib/f`)."""
    sep = os.sep
    tails: Set[str] = set()
    parents: Set[str] = set()
    for p in dict.fromkeys([path, *aliases]):
        parts = p.replace(sep, "/").rstrip("/").split("/")
        if len(parts) >= 3 and parts[-1] and parts[-2] and not any(q in s for s in parts[-2:] for q in "\"'"):
            a, b = parts[-2], parts[-1]
            for quote_char in ('"', "'"):
                for glue in (", ", ",", " / ", "/"):
                    tails.add(quote_char + a + quote_char + glue + quote_char + b + quote_char)
            if plain and len(a) + len(b) >= 8:
                tails.add(a + "/" + b)
        parent = p
        for _ in range(2):
            parent = os.path.dirname(parent)
            if not parent or parent == os.path.dirname(parent):
                break
            depth = next((r.count(sep) + 1 for r in (_under(parent, h, sep) for h in homes) if r), 0)
            if depth >= 3 or (depth == 0 and parent.count(sep) >= 4):
                parents |= _place_forms(homes, parent, (), sep)
    return _spellings(tails, rich=False), _spellings(parents, rich=False)


_TOKEN_RE = re.compile(r"[\w.\-]+")


def _tokens(line: str) -> Set[str]:
    toks = set(_TOKEN_RE.findall(line))
    return toks | {t.rstrip(".-") for t in toks}


class _PatIndex:
    """pattern -> candidate paths, indexed by the pattern's last name. A line can only cite a candidate if that name
    is one of the line's tokens, so a line is checked against a handful of patterns, not thousands."""

    def __init__(self, check: Callable[[str, str], bool]) -> None:
        self.check = check
        self.pats: Dict[str, List[str]] = {}
        self.fast: Dict[str, List[str]] = {}
        self.slow: List[str] = []

    def add(self, pat: str, cpath: str) -> None:
        if not pat.strip() or "\n" in pat or "\r" in pat:
            return
        owners = self.pats.get(pat)
        if owners is not None:
            owners.append(cpath)
            return
        self.pats[pat] = [cpath]
        found = _TOKEN_RE.findall(pat) if _TOKEN_RE.fullmatch(pat[-1]) else []
        if found:
            self.fast.setdefault(found[-1], []).append(pat)
        else:
            self.slow.append(pat)

    def cited(self, line: str, toks: Set[str]) -> List[str]:
        wanted = set(self.slow)
        for tok in toks:
            wanted.update(self.fast.get(tok, ()))
        out: List[str] = []
        for pat in wanted:
            if self.check(line, pat):
                out.extend(self.pats[pat])
        return out


def _long_line(path: str, number: int) -> Optional[str]:
    """Line `number` of a file rg reported but omitted for length (the file is <= 2 MB)."""
    try:
        with open(path, "rb") as fh:
            for i, raw in enumerate(fh, 1):
                if i == number:
                    return raw.decode("utf-8", "replace")
    except OSError:
        pass
    return None


def _tree_roots(ctx: Ctx, known: Sequence[str]) -> Tuple[List[str], List[str]]:
    """(project trees searched whole, trees skipped because they are cloud-synced).

    Every visible folder of HOME (a link to another volume is followed) except media and package stores, plus every
    project the inventory already knows (session folders) and every node_modules owner it found. A synced tree is
    never read (rg would download its placeholders): it is reported, so the candidates come out "unverified"
    instead of "unreferenced". Only HOME itself and the places the candidates live in (~/.cache), the tool's state
    and the Trash are dropped without a word."""
    home = os.path.realpath(str(ctx.home))
    never = [os.path.join(home, n) for n in REF_NEVER_READ]
    cloud_memo: Dict[str, bool] = {}

    def synced(path: str) -> bool:
        if path not in cloud_memo:
            cloud_memo[path] = bool(ctx.safety.is_cloud_or_placeholder(path)[0])
        return cloud_memo[path]

    def state(path: str) -> str:
        """"skip" (not a project folder), "cloud" (synced: reported, not read) or "read"."""
        if path == home or home.startswith(path.rstrip(os.sep) + os.sep) or not os.path.isdir(path):
            return "skip"
        if any(path == t or path.startswith(t + os.sep) for t in never):
            return "skip"
        return "cloud" if synced(path) else "read"

    roots: List[str] = []
    skipped: List[str] = []
    for top in _entries(home):
        if top.name.startswith(".") or top.name in REF_TOP_SKIP:
            continue
        base = os.path.realpath(top.path)
        verdict = state(base)
        if verdict == "skip":
            continue
        if verdict == "cloud":
            skipped.append(base)
            continue
        kids = [e.path for e in _entries(base) if _is_real_dir(e)]
        bad = [k for k in kids if synced(k)]
        if bad:  # a synced folder inside a project folder: read its siblings one by one, leave it out
            skipped.extend(bad)
            roots.extend(k for k in kids if k not in bad)
        else:
            roots.append(base)
    for p in [*known, *(ctx.memo("e_project_roots", lambda: []) or [])]:
        rp = os.path.realpath(p)
        verdict = state(rp)
        if verdict == "cloud":
            skipped.append(rp)
        elif verdict == "read":
            roots.append(rp)
    ordered = sorted(set(roots), key=len)
    kept: List[str] = []
    for r in ordered:
        if not any(r == k or r.startswith(k + os.sep) for k in kept):
            kept.append(r)
    return sorted(kept), sorted(set(skipped))


def _home_links(ctx: Ctx) -> List[Tuple[str, str]]:
    """(link, folder it points to) for each link directly in HOME: a file may cite ~/Projects/app for what is
    really /Volumes/x/Projects/app."""
    out: List[Tuple[str, str]] = []
    for e in _entries(ctx.home):
        try:
            if e.is_symlink() and e.is_dir():
                out.append((e.path, os.path.realpath(e.path)))
        except OSError:
            continue
    return out


def _aliases(cand: dict, home_links: Sequence[Tuple[str, str]]) -> List[str]:
    """The other names of the candidate's path: the one its walker saw, and the ones a HOME-level link gives it."""
    p = cand["path"]
    out = [a for a in (cand["evidence"].get("alias_paths") or []) if isinstance(a, str)]
    out += [link + p[len(real):] for link, real in home_links if p == real or p.startswith(real + os.sep)]
    return list(dict.fromkeys(a for a in out if a != p))


def _crontab_lines(ctx: Ctx) -> List[str]:
    """The user's crontab: scheduled commands are user code that no project folder holds."""
    rc, text = ctx.run(["crontab", "-l"], None, 10.0, None)
    return text.split("\n") if rc == 0 and text else []


_LINK_SKIP = frozenset(d for d in REF_SKIP_DIRS if d != "node_modules") | {".git"}


def _links_into(roots: Sequence[str], wanted: Set[str], seconds: float) -> Tuple[Dict[str, List[str]], bool]:
    """({candidate path: links that point into it}, partial). A link is a dependency rg cannot see: the text of the
    code only names the link. node_modules is read two levels deep (`file:` and linked packages live there)."""
    found: Dict[str, List[str]] = {}
    deadline = time.time() + seconds
    budget = MAX_DISCOVERY_DIRS

    def check(link: str) -> None:
        cur = os.path.realpath(link)
        while True:
            if cur in wanted:
                if link != cur and not link.startswith(cur + os.sep):  # a link inside the candidate is no outside user
                    found.setdefault(cur, []).append(link)
                return
            up = os.path.dirname(cur)
            if up == cur:
                return
            cur = up

    def listing(path: str) -> List[os.DirEntry]:
        try:
            with os.scandir(path) as it:
                return list(it)
        except OSError:
            return []

    def shallow(modules: str) -> None:
        for e in listing(modules):
            try:
                if e.is_symlink():
                    check(e.path)
                elif e.name.startswith("@") and e.is_dir(follow_symlinks=False):
                    for sub in listing(e.path):
                        if sub.is_symlink():
                            check(sub.path)
            except OSError:
                continue

    stack = list(roots)
    while stack:
        if budget <= 0 or time.time() > deadline:
            return found, True
        budget -= 1
        cur = stack.pop()
        if os.path.islink(cur):
            check(cur)
            continue
        if not os.path.isdir(cur):
            continue
        for e in listing(cur):
            try:
                if e.is_symlink():
                    check(e.path)
                elif e.is_dir(follow_symlinks=False):
                    if e.name == "node_modules":
                        shallow(e.path)
                    elif e.name not in _LINK_SKIP:
                        stack.append(e.path)
            except OSError:
                continue
    return found, False


def _apply_refs(ctx: Ctx, cands: List[dict], projects: Sequence[str], known: Sequence[str] = ()) -> dict:
    """ONE `rg -F -f` for every candidate path over agent instructions, settings, memories, skills, shell start-up
    files and the whole tree of every project folder (code included: a script citing a clone is a live dependency),
    plus the crontab and the links that point into a candidate. Returns the search stats; a search that did not run
    or did not finish leaves each candidate "unverified". A path a script assembles at run time cannot be proven
    by text: its likely forms (`"ref", "lib"`, `cd X && ./lib`) mark the candidate "possibly cited", never clean.
    That guess is narrow (a generic or short folder name gets none, a *.log never makes one): see _weak_name_ok."""
    stats: Dict[str, Any] = {"roots": 0, "skipped_cloud": 0, "seconds": 0.0, "status": "not run",
                             "not_searched": REF_NOT_SEARCHED}
    targets = [c for c in cands if not c["virtual"]]
    if not targets:
        stats["status"] = "no candidates"
        return stats

    def unverify(why: str) -> None:
        ctx.note_unverified("referenced_by and keep_note (%s)" % why)
        for c in targets:
            c["evidence"]["unverified"].append("referenced_by: not verified (%s)" % why)

    if not ctx.which("rg"):
        stats["status"] = "rg not found"
        unverify("rg not found")
        return stats
    trees, skipped = _tree_roots(ctx, known)
    stats["roots"], stats["skipped_cloud"] = len(trees), len(skipped)
    agent_files = _ref_roots(ctx, projects)
    roots = sorted(set(trees) | {r for r in agent_files if not any(r == t or r.startswith(t + os.sep) for t in trees)})
    cron = _crontab_lines(ctx)
    if not roots and not cron:
        stats["status"] = "nothing to search in"
        unverify("nothing to search in: no agent instruction, settings or project files found")
        return stats
    real_home = os.path.realpath(str(ctx.home))
    homes = list(dict.fromkeys([real_home, os.path.abspath(str(ctx.home))]))
    bases, home_links, sep = _env_bases(ctx), _home_links(ctx), os.sep
    fold = _case_insensitive(real_home)

    def spelled(pat: str) -> str:
        return pat.lower() if fold else pat

    strong = _PatIndex(_mentions)
    tail = _PatIndex(lambda text, pat: _mentions(text, pat, True))
    parent = _PatIndex(_standalone)
    weak_room = REF_WEAK_MAX_PATTERNS
    for c in targets:
        p = c["path"]
        if "\n" in p or "\r" in p:
            c["evidence"]["unverified"].append("referenced_by: path has a line break, not searched")
            continue
        aliases = _aliases(c, home_links)
        light = c["category"] == "A"  # thousands of transcripts: nobody cites one through $VAR or as JSON
        for pat in _ref_patterns(homes, p, () if light else bases, aliases, rich=not light):
            strong.add(spelled(pat), p)
        if c["category"] not in REF_WEAK_CATEGORIES or not _weak_name_ok(p):
            continue
        if weak_room <= 0:
            c["evidence"]["unverified"].append("referenced_by: possible citations not checked (too many candidates)")
            continue
        tails, parents = _weak_patterns(homes, p, aliases, plain=c["category"] in ("C", "D"))
        weak_room -= len(tails) + len(parents)
        for pat in tails:
            tail.add(spelled(pat), p)
        for pat in parents:
            parent.add(spelled(pat), p)
    every = set(strong.pats) | set(tail.pats) | set(parent.pats)
    if not strong.pats:
        stats["status"] = "no searchable path"
        return stats
    argv = ["rg", "-F", "-f", "-", "--no-config", "--no-heading", "--with-filename", "-n", "--null", "--no-messages",
            "--hidden", "--no-ignore", "--max-filesize", "2M", "--max-columns", "4000"]
    if fold:  # a regex of every pattern in both cases: rg's default size limit is too small for it
        argv += ["-i", "--regex-size-limit", "1G", "--dfa-size-limit", "1G"]
    for g in REF_SKIP_GLOBS:
        argv += ["-g", "!" + g]
    argv += ["--"] + roots
    started = time.monotonic()
    rc, text = ctx.run(argv, None, ctx.ref_seconds, "\n".join(sorted(every)) + "\n") if roots else (1, "")  # no root: rg would read the cwd
    stats["seconds"] = round(time.monotonic() - started, 1)
    partial: List[str] = []
    if rc not in (0, 1):
        timed_out = not text and stats["seconds"] >= ctx.ref_seconds * 0.9
        stats["status"] = "timed out" if timed_out else "failed"
        partial.append("timed out after %ds" % ctx.ref_seconds if timed_out else "rg failed or could not read everything")
        if not text:
            unverify(partial[0])
            return stats
    else:
        stats["status"] = "ok"
    if skipped:
        partial.append("%d cloud-synced folder(s) not read" % len(skipped))
    hits: Dict[str, Dict[str, bool]] = {}
    maybe: Dict[str, Dict[str, bool]] = {}
    nfc_memo: Dict[str, str] = {}
    own = [_nfc(r) for r in OWN_ROOTS]

    def consume(fpath: str, line: str) -> None:
        shown = line.lower() if fold else line
        toks = _tokens(shown)
        keep = bool(KEEP_RE.search(line))
        nf = _nfc(fpath)
        if any(nf == r or nf.startswith(r + sep) for r in own):
            return
        for index, bucket in ((strong, hits), (tail, maybe), (parent, maybe)):
            if bucket is maybe and _LOG_FILE_RE.search(fpath):
                continue  # a log names temp folders and caches all day: it proves nothing about one path
            for cpath in index.cited(shown, toks):
                ncp = nfc_memo.setdefault(cpath, _nfc(cpath))
                if nf == ncp or nf.startswith(ncp + sep):
                    continue  # the candidate citing itself is no dependency
                files = bucket.setdefault(cpath, {})
                files[fpath] = files.get(fpath, False) or (keep and bucket is hits)

    lines = text.split("\n")  # rg ends a line at \n only: splitlines() would cut at U+2028, \x0c, \x85 and lose the path
    if len(lines) > REF_MAX_LINES:
        partial.append("more than %d matching lines" % REF_MAX_LINES)
        lines = lines[:REF_MAX_LINES]
    reread = 0
    for ln in lines:
        fpath, sep_found, rest = ln.partition("\0")
        if not sep_found:
            continue
        number, _, line = rest.partition(":")
        if line.startswith("[Omitted long"):  # rg hid a very long line: read it from the file
            reread += 1
            full = _long_line(fpath, int(number)) if number.isdigit() and reread <= REF_LONG_LINES else None
            if full is None:
                partial.append("a very long matching line could not be read")
                continue
            line = full
        consume(fpath, line)
    for ln in cron:
        consume("crontab -l", ln)
    links, links_partial = _links_into(roots, {c["path"] for c in targets}, min(DISCOVERY_SECONDS, ctx.ref_seconds))
    for cpath, linked in links.items():
        files = hits.setdefault(cpath, {})
        for link in linked:
            files.setdefault(link, False)
    if links_partial:
        partial.append("the search for links into a candidate stopped at its budget")
    if partial:
        why = "; ".join(dict.fromkeys(partial))
        ctx.note_unverified("referenced_by and keep_note (partial: %s)" % why)
        for c in targets:
            c["evidence"]["unverified"].append("referenced_by: partly verified (%s)" % why)
    for c in targets:
        files = hits.get(c["path"], {})
        c["evidence"]["referenced_by_total"] = len(files)
        c["evidence"]["referenced_by"] = [ctx.safety.sanitize_name(f, 200) for f in sorted(files)[:10]]
        c["evidence"]["keep_note"] = bool(c["evidence"].get("keep_note")) or any(files.values())  # a worktree's own note stays
        if files and c["action"] != "list_only":
            c["evidence"]["reason"] += "; referenced by %d agent or project file(s): live dependency, check before removing" % len(files)
        guess = sorted(f for f in maybe.get(c["path"], {}) if f not in files)
        if guess:
            c["evidence"]["referenced_maybe"] = [ctx.safety.sanitize_name(f, 200) for f in guess[:10]]
            c["evidence"]["unverified"].append(
                "referenced_by: possibly cited in %d file(s), the path may be assembled from parts" % len(guess))
    return stats


def retention(ctx: Ctx) -> dict:
    """Retention the agents are configured with (read-only): Claude cleanupPeriodDays, Codex [history]."""
    res: Dict[str, Any] = {"claude_cleanup_period_days": None, "codex_history_max_bytes": None,
                           "codex_history_persistence": None}
    for name in ("settings.json", "settings.local.json"):
        try:
            data = json.loads((ctx.claude_dir / name).read_text("utf-8"))
        except (OSError, ValueError):
            continue
        val = data.get("cleanupPeriodDays") if isinstance(data, dict) else None
        if isinstance(val, int) and not isinstance(val, bool):
            res["claude_cleanup_period_days"] = val
    try:
        section = ""
        for ln in (ctx.codex_dir / "config.toml").read_text("utf-8", "replace").splitlines():
            s_ = ln.strip()
            if s_.startswith("["):
                section = s_.strip("[] ")
                continue
            m = re.match(r'^(max_bytes|persistence)\s*=\s*"?([^"#\s]+)', s_) if section == "history" else None
            if m and m.group(1) == "max_bytes" and m.group(2).isdigit():
                res["codex_history_max_bytes"] = int(m.group(2))
            elif m and m.group(1) == "persistence":
                res["codex_history_persistence"] = m.group(2)
    except OSError:
        pass
    return res


# ---------------------------------------------------------------- entry points

def _guard(ctx: Ctx, name: str, fn: Callable[[], Any]) -> Any:
    ctx.progress("inventory: " + name)
    try:
        return fn()
    except (CorecleanerError, NotImplementedError):
        raise  # safety unavailable or broken: fail closed, never "no deny list"
    except Exception as exc:  # one detector failing must not hide the others; it is reported, not silent
        ctx.warnings.append("%s failed: %s" % (name, type(exc).__name__))
        return None


def collect(ctx: Ctx) -> Tuple[List[dict], dict]:
    out: List[dict] = []
    _guard(ctx, "processes", lambda: (_ps_rows(ctx), _cwd_table(ctx)))  # filled once, before worker threads read it
    projects = _guard(ctx, "known projects", lambda: _known_projects(ctx)) or []
    repos = [p for p in projects if os.path.lexists(os.path.join(p, ".git"))]
    _guard(ctx, "A", lambda: _detect_A(ctx, out))
    claimed = _guard(ctx, "D", lambda: _detect_D(ctx, out)) or set()
    stray = _guard(ctx, "C", lambda: _detect_C(ctx, out, claimed)) or []
    _guard(ctx, "B", lambda: _detect_B(ctx, out, sorted(set(repos) | set(stray))))
    _guard(ctx, "E", lambda: _detect_E(ctx, out, [str(ctx.claude_dir), str(ctx.codex_dir), *claimed]))
    _guard(ctx, "F", lambda: _detect_F(ctx, out))
    _guard(ctx, "G", lambda: _detect_G(ctx, out))
    _guard(ctx, "I", lambda: _detect_I(ctx, out))
    _guard(ctx, "J", lambda: _detect_J(ctx, out))
    _guard(ctx, "K", lambda: _detect_K(ctx, out))
    _guard(ctx, "L", lambda: _detect_L(ctx, out))
    out = _resolve_nesting(out)
    ref_stats = _guard(ctx, "references", lambda: _apply_refs(ctx, out, projects + stray, projects)) or {}
    meta = {
        "tools": {n: bool(ctx.which(n)) for n in ("git", "rg", "lsof", "ps")},
        "retention": retention(ctx),
        "live_agents": _agent_pids(ctx),
        "unverified": list(ctx.unverified),
        "warnings": list(ctx.warnings),
        "reference_search": ref_stats,
        "scope_note": "H (raw already transformed) is not detected here: it needs a per-item match by identifier",
    }
    return out, meta


def inventory(ctx: Optional[Ctx] = None) -> List[dict]:
    return collect(ctx or default_ctx())[0]


def run(args: Any = None) -> dict:
    cands, meta = collect(default_ctx())
    out: Dict[str, Any] = {"candidates": cands, "ts": now_iso()}
    out.update(meta)
    return out
