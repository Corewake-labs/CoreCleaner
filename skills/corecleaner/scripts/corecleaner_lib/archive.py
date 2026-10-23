"""Safety archive for git repos with work that exists nowhere else. (T7; no subcommand)

Called by trash.py before a repo goes to the Trash. Runs git only; writes only inside `dest`
(a new or empty directory, default ~/corecleaner-archive/<date>/<id>). Never touches the repo itself
and never deletes anything of the user's. The single deletion in this module is
`_remove_own_temp`, which removes the scratch clone this module created inside dest/tmp.

needs_archive(repo) -> (bool, why)
  True when the repo has uncommitted changes (`git status --porcelain`), untracked files, commits
  on no remote (`git rev-list --branches --not --remotes`, HEAD included for a detached head;
  no remote at all = everything is unpublished) or a stash. `why` lists which, with counts only
  (git output is parsed into numbers, never forwarded raw). Large ignored files/dirs
  (>= IGNORED_MIN_BYTES) are listed in `why` as information; they never flip the bool and are
  never archived (usually rebuildable caches, but a `.env` or a local DB is not: the caller
  shows the list). Ignored paths whose NAME is protected (.env, keys) DO flip it: archive_repo keeps them.
  Not a repo root -> (False, "not a git repository"). Any doubt (git cannot read
  it, git missing, timeout, config that can run programs) -> (True, ...): it fails toward archiving,
  never toward Trash.

archive_repo(repo, dest=None) -> dict
  1. Estimate (du of the git dir + changed/untracked bytes); free space on dest's volume below
     SPACE_FACTOR x estimate -> CorecleanerError(EXIT_NO_SPACE_FOR_ARCHIVE) before anything is
     created: the caller skips the item, never trashes without the archive.
  2. dest/bundle.git   `git bundle create --all` (every branch, tag, stash, HEAD)
     dest/dirty.patch  `git diff --binary HEAD` (staged + unstaged), only when non-empty
     dest/untracked.tar.gz  untracked, non-ignored files (`git ls-files --others --exclude-standard`)
  3. Verify, all of it or the archive fails: `git bundle verify`; every non-remote ref is listed in
     the bundle; a scratch `git clone --no-checkout` of the bundle under dest/tmp has HEAD equal to
     the source HEAD, every ref object present, `git fsck --connectivity-only` clean, and
     dirty.patch passes `git apply --cached --check` against the clone's HEAD; the tar reads back
     with the member count it was written with. The refs must not move while archiving.
  4. dest/MANIFEST.txt written last (so no MANIFEST.txt = incomplete archive): repo, counts,
     sha256 + size of each file, restore commands, ignored-large list.
  Returns {"dest", "bundle": str|None, "diff": str|None, "untracked_tar": str|None, "manifest",
  "bytes", "verified": True, "restore_test", "files": [...], "counts": {...}, "ignored_large": [...],
  "warnings": [...]}. `bundle` is None only for a repo with no refs at all (untracked files only).
  dest/ignored-protected.tar.gz  ignored paths whose NAME is protected (.env, keys, .ssh), up to
     PROTECTED_MAX_BYTES; more = CorecleanerError, never silently left out. `protected_tar`.
  Files are mode 0o600 inside a 0o700 dest: an untracked `.env` lands in the tar.
  `incomplete` lists submodule checkouts, linked worktrees and repos nested in ignored folders (up to
  NESTED_SEARCH_DEPTH levels; NESTED_CUT_NOTE when that search was cut) with work the archive does not
  cover, and PROTECTED_CUT_NOTE when the scan for protected names could not finish (an ignored tree too big or
  unreadable: a `.env` in it may be missing from ignored-protected.tar.gz); the caller must not trash
  while it is non-empty. needs_archive carries the same note in `why`, whatever its bool. Config that can run programs (gitguard) = CorecleanerError
  with details unsafe_config=True; git's own stderr never reaches a message (it is `exc.stderr`).

estimate_archive_bytes(repo) -> int, ignored_large(repo, min_bytes=None, limit=20) -> list

Shallow clone (`git rev-parse --is-shallow-repository`): its history was fetched from a remote and stops at
  boundary commits (`.git/shallow`). A boundary commit that names parents, all absent, is published by
  definition: it never counts as "a commit on no remote" (a clone made with `git fetch --depth 1 <url> <sha>`
  has no remote-tracking ref). So a clean shallow clone needs no archive. A shallow clone with work is
  archived as dest/shallow-repo.tar.gz, the whole repo with `.git` (modified, untracked and ignored files
  included), because a bundle of it cannot be cloned back (the boundary parents are missing: "remote did
  not send all necessary objects"). The tar is read to the end and must list .git/HEAD and .git/shallow;
  the result has `repo_tar` and `shallow: True`, and `bundle`, `diff`, `untracked_tar`, `protected_tar` are None.
  A shallow checkout whose .git is a file (linked worktree, submodule) is refused: its history is elsewhere.

Archive store (the folder all archives share, ~/corecleaner-archive) has a cap, ARCHIVE_CAP_BYTES
(20 GiB; env CORECLEANER_ARCHIVE_CAP_GIB overrides):
check_quota(root, repos) raises CorecleanerError(EXIT_NO_SPACE_FOR_ARCHIVE, quota=True) when the
  store plus the estimate of `repos` would pass the cap; the caller skips the item and creates nothing.
store_report(root, days=ARCHIVE_STALE_DAYS) -> dict   read-only listing: store size, cap, and the archives
  untouched for `days` or more (oldest first, STALE_LISTED at most). Nothing here deletes an archive: an
  archive can be the only copy of a repo, so the user decides which ones go (trash.py prints a command).
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from . import gitguard, safety
from .common import (
    EXIT_ERROR,
    EXIT_NO_SPACE_FOR_ARCHIVE,
    CorecleanerError,
    log,
    now_iso,
)

MIB = 1024 * 1024
SPACE_FACTOR = 2  # free space must be >= SPACE_FACTOR x estimate (bundle + scratch clone)
MIN_ESTIMATE = MIB
IGNORED_MIN_BYTES = 10 * MIB
IGNORED_MAX_LISTED = 20
SCAN_BUDGET = 200_000  # directory entries visited when sizing ignored directories
GIB = 1024 * MIB
ARCHIVE_CAP_BYTES = 20 * GIB  # all archives together; one more that would pass it is skipped (exit 44)
ARCHIVE_CAP_ENV = "CORECLEANER_ARCHIVE_CAP_GIB"
ARCHIVE_STALE_DAYS = 90  # archives untouched this long are listed for the user to remove; never removed here
STALE_LISTED = 50

BUNDLE_NAME = "bundle.git"
PATCH_NAME = "dirty.patch"
TAR_NAME = "untracked.tar.gz"
PROTECTED_TAR_NAME = "ignored-protected.tar.gz"
SHALLOW_TAR_NAME = "shallow-repo.tar.gz"  # a shallow clone: the whole repo, .git included, instead of a bundle
SHALLOW_FILE_MAX_BYTES = MIB
SHALLOW_MAX_BOUNDARY = 5000
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PROTECTED_MAX_BYTES = 64 * MIB  # ignored files with protected names (.env, keys); more than this = refuse, not skip
# Fixed text: an ignored tree the protected-name scan could not finish. trash.py looks for it in `needs_archive`'s
# answer and in `archive_repo`'s `incomplete`; either one means the repo is NOT trashed, because a `.env` or a key
# in the part nobody read would go to the Trash with no copy.
PROTECTED_CUT_NOTE = "an ignored tree was too big to scan for protected names (.env, keys)"
NESTED_CUT_NOTE = "an ignored tree was too big or unreadable to search for nested repos"
NESTED_SEARCH_DEPTH = 6  # levels below an ignored folder searched for a nested repo
MANIFEST_NAME = "MANIFEST.txt"

_READ_TIMEOUT = 900
_WRITE_TIMEOUT = 7200

# Env that would redirect git to another repository than the one we mean.
_STRIP_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
)
_CTRL = re.compile("[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]+")


class _Repo(NamedTuple):
    root: str  # realpath of the work tree (or of the git dir for a bare repo)
    bare: bool


class _Unreadable(Exception):
    """A .git exists but git cannot read it (corrupt, foreign owner): treat as needing archive."""


# ---------------------------------------------------------------- helpers


def _clean(value, maxlen: int = 200) -> str:
    """File names and git messages are DATA: strip control/bidi characters, bound the length."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "backslashreplace")
    text = _CTRL.sub(" ", value).strip()
    return text if len(text) <= maxlen else text[: maxlen - 3] + "..."


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return ("%d %s" % (size, unit)) if unit == "B" else ("%.1f %s" % (size, unit))
        size /= 1024
    return "%d B" % n


def _git_env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _STRIP_ENV}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_OPTIONAL_LOCKS": "0",  # `status`/`diff` must not rewrite the index of a repo we only read
            "GIT_NO_LAZY_FETCH": "1",  # a partial clone must not fetch (and run its remote helpers) while we read it
            "LC_ALL": "C",
        }
    )
    return env


def _git(
    cwd,
    *args: str,
    check: bool = True,
    timeout: int = _READ_TIMEOUT,
    stdout=None,
    input_bytes: Optional[bytes] = None,
) -> "subprocess.CompletedProcess[bytes]":
    # fsmonitor/hooks/signature display come from the repo's own config, which an agent may have written.
    cmd = [
        "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
        "-c", "log.showSignature=false", "-C", str(cwd),
    ]
    cmd.extend(args)
    label = next((a for a in args if not a.startswith("-") and "=" not in a), "?")
    stdin_kw: dict = {"stdin": subprocess.DEVNULL} if input_bytes is None else {"input": input_bytes}
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if stdout is None else stdout,
            stderr=subprocess.PIPE,
            env=_git_env(),
            timeout=timeout,
            **stdin_kw
        )
    except FileNotFoundError:
        raise CorecleanerError(EXIT_ERROR, "git not found in PATH")
    except subprocess.TimeoutExpired:
        raise CorecleanerError(EXIT_ERROR, "git %s timed out after %d s" % (label, timeout))
    if check and proc.returncode != 0:
        err = proc.stderr or b""
        if b"No space left on device" in err:
            raise CorecleanerError(EXIT_NO_SPACE_FOR_ARCHIVE, "no space left while running git " + label)
        # git's stderr can carry text a repo author chose (config values, ref names): it stays out of
        # the message, which reaches the agent; callers that want it read `.stderr`.
        failure = CorecleanerError(EXIT_ERROR, "git %s failed (exit %d)" % (label, proc.returncode))
        failure.stderr = _clean(err)  # type: ignore[attr-defined]
        raise failure
    return proc


def _lines(out: bytes) -> List[bytes]:
    return [x for x in out.splitlines() if x]


def _nul(out: bytes) -> List[bytes]:
    return [x for x in out.split(b"\0") if x]


def _same_path(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _locate(repo: str) -> Optional[_Repo]:
    """The repo whose ROOT is `repo`, else None. Raises _Unreadable when .git exists but is unusable."""
    if not os.path.isdir(repo):
        return None
    real = os.path.realpath(repo)
    if not (os.path.lexists(os.path.join(real, ".git")) or os.path.isfile(os.path.join(real, "HEAD"))):
        return None  # no .git entry and not a bare layout: no need to ask git
    proc = _git(real, "rev-parse", "--is-bare-repository", check=False, timeout=60)
    if proc.returncode != 0:
        if os.path.lexists(os.path.join(real, ".git")):
            raise _Unreadable("git rev-parse failed")
        return None
    if proc.stdout.strip() == b"true":
        gd = _git(real, "rev-parse", "--absolute-git-dir", check=False, timeout=60)
        if gd.returncode == 0 and _same_path(os.fsdecode(gd.stdout.rstrip(b"\r\n")), real):
            return _Repo(real, True)
        return None
    top = _git(real, "rev-parse", "--show-toplevel", check=False, timeout=60)
    if top.returncode != 0:
        return None  # e.g. inside a .git directory
    if _same_path(os.fsdecode(top.stdout.rstrip(b"\r\n")), real):
        return _Repo(real, False)
    return None  # a sub-directory of some repo is not a repo


def _parse_status(out: bytes) -> Tuple[int, int]:
    """(tracked changes, untracked) from `status --porcelain -z`."""
    tracked = untracked = 0
    items = out.split(b"\0")
    i = 0
    while i < len(items):
        entry = items[i]
        i += 1
        if len(entry) < 3:
            continue
        xy = entry[:2]
        if xy == b"??":
            untracked += 1
        elif xy != b"!!":
            tracked += 1
            if b"R" in xy or b"C" in xy:
                i += 1  # rename/copy carries the original path as its own entry
    return tracked, untracked


def _commit_parents(out: bytes) -> Dict[str, List[str]]:
    """{commit sha: parent shas} from `git cat-file --batch` output; other types and missing objects are skipped."""
    parents: Dict[str, List[str]] = {}
    pos = 0
    while pos < len(out):
        end = out.find(b"\n", pos)
        if end < 0:
            break
        head = out[pos:end].split()
        pos = end + 1
        if len(head) != 3 or not head[2].isdigit():
            continue  # "<sha> missing": no body follows
        size = int(head[2])
        body = out[pos:pos + size]
        pos += size + 1
        if head[1] != b"commit":
            continue
        found: List[str] = []
        for line in body.split(b"\n"):
            if not line:
                break  # the blank line ends the commit headers
            if line.startswith(b"parent "):
                found.append(line[7:].decode("ascii", "replace").strip())
        parents[head[0].decode("ascii", "replace")] = found
    return parents


def _shallow(info: _Repo) -> Tuple[bool, List[str]]:
    """(is a shallow clone, its boundary commits).

    A boundary commit was fetched without its parents, so it came from a remote and is not local work: it
    must not count as "a commit on no remote" when no remote-tracking ref points at it (a clone made by
    `git fetch --depth 1 <url> <sha>`). Only a commit that names parents, all of them absent, counts. A
    commit made here has its parents and a root commit has none, so neither can hide behind a `shallow`
    file edited by hand. Any doubt leaves the commit out of the list, which means "unpublished" (archive).
    """
    flag = _git(info.root, "rev-parse", "--is-shallow-repository", check=False, timeout=60)
    if flag.returncode != 0 or flag.stdout.strip() != b"true":
        return False, []
    try:
        with open(os.path.join(_git_common_dir(info), "shallow"), "rb") as fh:
            raw = fh.read(SHALLOW_FILE_MAX_BYTES)
    except OSError:
        return True, []
    shas = [x.decode("ascii") for x in raw.split() if _SHA.match(x.decode("ascii", "replace"))]
    shas = list(dict.fromkeys(shas))[:SHALLOW_MAX_BOUNDARY]
    if not shas:
        return True, []
    listed = _git(info.root, "cat-file", "--batch", input_bytes=("\n".join(shas) + "\n").encode("ascii"), check=False)
    parents = _commit_parents(listed.stdout) if listed.returncode == 0 else {}
    wanted = sorted({p for ps in parents.values() for p in ps if _SHA.match(p)})
    absent = set()
    if wanted:
        seen = _git(info.root, "cat-file", "--batch-check", input_bytes=("\n".join(wanted) + "\n").encode("ascii"), check=False)
        if seen.returncode != 0:
            return True, []
        absent = {ln.split()[0].decode("ascii", "replace") for ln in _lines(seen.stdout) if ln.endswith(b" missing")}
    boundary = [sha for sha in shas if parents.get(sha) and all(p in absent for p in parents[sha])]
    return True, boundary


def _facts(info: _Repo) -> dict:
    root = info.root
    head_proc = _git(root, "rev-parse", "--verify", "-q", "HEAD", check=False, timeout=60)
    head = head_proc.stdout.strip().decode("ascii", "replace") if head_proc.returncode == 0 else None
    br = _git(root, "symbolic-ref", "-q", "--short", "HEAD", check=False, timeout=60)
    branch = _clean(br.stdout) if br.returncode == 0 else None
    refs_out = _git(root, "for-each-ref", "--format=%(objectname) %(refname)").stdout
    shallow, boundary = _shallow(info)
    rev_args = ["rev-list", "--count"] + (["HEAD"] if head else []) + ["--branches", "--not", "--remotes"] + boundary
    unpublished = int(_git(root, *rev_args).stdout.strip() or b"0")
    tag_only = int(
        _git(root, "rev-list", "--count", "--tags", "--not", "--branches", "--remotes", *boundary).stdout.strip() or b"0"
    )
    stashes = 0  # `git stash list` needs a work tree; the reflog of refs/stash works in bare repos too
    if _git(root, "rev-parse", "--verify", "-q", "refs/stash", check=False, timeout=60).returncode == 0:
        stashes = max(1, len(_lines(_git(root, "reflog", "show", "--format=%gd", "refs/stash").stdout)))
    remotes = len(_lines(_git(root, "remote").stdout))
    tracked = untracked = 0
    if not info.bare:
        status = _git(
            root, "status", "--porcelain", "-z", "--untracked-files=normal", "--ignore-submodules=none"
        ).stdout
        tracked, untracked = _parse_status(status)
    return {
        "head": head,
        "branch": branch,
        "refs": [tuple(x.split(b" ", 1)) for x in _lines(refs_out)],
        "refs_fingerprint": hashlib.sha256(refs_out + (head or "").encode()).hexdigest(),
        "unpublished": unpublished,
        "tag_only": tag_only,
        "stashes": stashes,
        "remotes": remotes,
        "tracked": tracked,
        "untracked": untracked,
        "shallow": shallow,
    }


def _tree_bytes(path: str, budget: Optional[List[int]] = None) -> Tuple[int, bool]:
    """Apparent size of a tree via lstat (never follows symlinks). (bytes, truncated by budget)."""
    total = 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    if budget is not None:
                        if budget[0] <= 0:
                            return total, True
                        budget[0] -= 1
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(entry.path)
                    else:
                        total += st.st_size
        except OSError:
            continue
    return total, False


def _lstat_size(path: str) -> int:
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    return _tree_bytes(path)[0] if stat.S_ISDIR(st.st_mode) else st.st_size


def _untracked_entries(info: _Repo, has_head: bool) -> List[bytes]:
    """Untracked, non-ignored paths relative to the root; nested repos appear as 'dir/'."""
    if info.bare:
        return []
    args = ["ls-files", "--others", "--exclude-standard", "-z"]
    if not has_head:
        args.insert(1, "--cached")  # unborn branch: staged files exist only in the index
    return _nul(_git(info.root, *args).stdout)


def _changed_tracked(info: _Repo, has_head: bool) -> List[bytes]:
    if info.bare or not has_head:
        return []
    return _nul(_git(info.root, "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "HEAD").stdout)


def _git_common_dir(info: _Repo) -> str:
    out = _git(info.root, "rev-parse", "--git-common-dir", timeout=60).stdout.rstrip(b"\r\n")
    return os.path.normpath(os.path.join(info.root, os.fsdecode(out)))


def _estimate(info: _Repo, facts: dict, untracked: List[bytes]) -> int:
    if facts.get("shallow"):  # the whole repo goes into one tar (see _archive_shallow_into)
        return max(_tree_bytes(info.root)[0], MIN_ESTIMATE)
    total = _tree_bytes(_git_common_dir(info))[0]
    for rel in _changed_tracked(info, facts["head"] is not None) + untracked:
        total += _lstat_size(os.path.join(info.root, os.fsdecode(rel)))
    return max(total, MIN_ESTIMATE)


def _unsafe(info: _Repo) -> List[str]:
    """Program-running settings in the repo's own config (gitguard); [] when none."""

    def run(*args: str) -> Tuple[int, str]:
        proc = _git(info.root, *args, check=False, timeout=60)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    return gitguard.unsafe_config(run, info.root)


def _need_repo(repo: str) -> _Repo:
    try:
        info = _locate(repo)
    except _Unreadable as exc:
        raise CorecleanerError(EXIT_ERROR, "git cannot read the repository: " + str(exc), repo=repo)
    if info is None:
        raise CorecleanerError(EXIT_ERROR, "not the root of a git repository", repo=repo)
    kinds = _unsafe(info)
    if kinds:
        raise CorecleanerError(
            EXIT_ERROR,
            "repo config can run programs (%s): it is not read, so it cannot be archived safely" % ", ".join(kinds),
            repo=repo,
            unsafe_config=True,
        )
    return info


def _ignored_protected(info: _Repo) -> Tuple[List[str], bool]:
    """Ignored paths whose NAME is protected (.env, keys, .ssh): in neither the bundle nor the untracked tar.

    Returns (paths relative to the root, truncated). Ignored trees that are too big to scan are reported
    as truncated, not skipped silently.
    """
    if info.bare:
        return [], False
    out = _git(info.root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z").stdout
    hits: List[str] = []
    truncated = False
    for raw in _nul(out):
        is_dir = raw.endswith(b"/")
        rel = os.fsdecode(raw).rstrip("/")
        parts = rel.split("/")
        if any(safety.protected_component(c) for c in parts):
            hits.append(rel + ("/" if is_dir else ""))
        elif is_dir and parts[-1] not in safety._SCAN_SKIP_DIRS:
            found, cut = safety.find_protected_inside(os.path.join(info.root, rel), skip_repos=False)
            truncated = truncated or cut
            hits.extend(rel + "/" + h for h in found)
    return hits, truncated


def _is_dir_entry(root: str, rel: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(os.path.join(root, rel.rstrip("/"))).st_mode)
    except OSError:
        return False


def _nested_repos(info: _Repo, skip: Sequence[str] = ()) -> Tuple[List[str], bool]:
    """Repos (a `.git` entry) inside the IGNORED folders of this repo, and whether the search was cut.

    Git ignores them, so they are in neither the bundle nor any tar of the outer repo: a clone inside an
    ignored `vendor/` with unsaved work would reach the Trash with it. An untracked (not ignored) repo is
    stored by the untracked tar, and submodules and linked worktrees (`skip`) have their own check, so
    those are not looked for here. Folders named like regenerable trees (`node_modules`, `site-packages`)
    are not entered, a repo is not entered, and nothing deeper than NESTED_SEARCH_DEPTH levels is seen.
    A folder git or the OS would not let us read, or more entries than safety.FIND_CAP in one ignored
    folder, make the answer `cut` (not proven), never "none".
    """
    if info.bare:
        return [], False
    listing = _git(info.root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z").stdout
    skip_real = {os.path.realpath(p) for p in skip}
    try:
        root_dev = os.lstat(info.root).st_dev
    except OSError:
        return [], True
    found: List[str] = []
    seen: set = set()
    cut = False
    for raw in _nul(listing):
        if not raw.endswith(b"/"):
            continue
        top = os.path.join(info.root, os.fsdecode(raw).rstrip("/"))
        if os.path.basename(top) in safety._SCAN_SKIP_DIRS:
            continue
        budget = safety.FIND_CAP
        stack = [(top, 0)]
        while stack and budget >= 0:
            cur, depth = stack.pop()
            if os.path.lexists(os.path.join(cur, ".git")):
                real = os.path.realpath(cur)
                if real not in skip_real and real not in seen:
                    seen.add(real)  # git lists an ignored folder under more than one parent
                    found.append(cur)
                continue  # a repo is judged on its own, never entered
            if depth >= NESTED_SEARCH_DEPTH:
                continue
            try:
                it = os.scandir(cur)
            except OSError:
                cut = True
                continue
            with it:
                for entry in it:
                    budget -= 1
                    if budget < 0:
                        break
                    if entry.name in safety._SCAN_SKIP_DIRS:
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode) and not (st.st_dev and root_dev and st.st_dev != root_dev):
                        stack.append((entry.path, depth + 1))
        if budget < 0:
            cut = True
    return found, cut


def _incomplete(info: _Repo) -> List[str]:
    """Work this archive does not cover: submodule checkouts, linked worktrees and repos nested in ignored
    folders that are not clean and published.

    The bundle holds every ref of the shared object store, but a submodule has its own history, a
    linked worktree has its own files and a repo inside an ignored folder is in no tar. Fixed labels only
    (they reach the agent).
    """
    if info.bare:
        return []
    subs: List[str] = []
    if os.path.exists(os.path.join(info.root, ".gitmodules")):
        proc = _git(info.root, "config", "--file", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$", check=False, timeout=60)
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            value = line.partition(" ")[2].strip()
            full = os.path.normpath(os.path.join(info.root, value))
            if value and os.path.commonpath([full, info.root]) == info.root and os.path.isdir(full):
                subs.append(full)
    proc = _git(info.root, "ls-files", "--stage", "-z", check=False, timeout=60)  # gitlinks with no .gitmodules entry
    for ent in proc.stdout.decode("utf-8", "replace").split("\0"):
        rel = ent.partition("\t")[2] if ent.startswith("160000 ") else ""
        full = os.path.normpath(os.path.join(info.root, rel)) if rel else ""
        if full and full not in subs and os.path.commonpath([full, info.root]) == info.root \
                and os.path.lexists(os.path.join(full, ".git")):
            subs.append(full)
    trees: List[str] = []
    if os.path.isdir(os.path.join(info.root, ".git")):  # a linked worktree or a submodule checkout owns no other worktree
        proc = _git(info.root, "worktree", "list", "--porcelain", check=False, timeout=60)
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("worktree "):
                path = line[len("worktree "):]
                if os.path.isdir(path) and not _same_path(path, info.root):
                    trees.append(path)

    def open_work(paths: List[str], first_only: bool = False) -> int:
        count = 0
        for path in paths:
            try:
                needs, _why = needs_archive(path)
            except CorecleanerError:
                needs = True
            count += 1 if needs else 0
            if needs and first_only:
                break  # one is enough to refuse; a monorepo can hold dozens of clones to inspect
        return count

    out: List[str] = []
    n = open_work(subs)
    if n:
        out.append("%d submodule checkout(s) with work this archive does not cover" % n)
    n = open_work(trees)
    if n:
        out.append("%d linked worktree(s) with work this archive does not cover" % n)
    nested, nested_cut = _nested_repos(info, subs + trees)
    if open_work(nested, first_only=True):
        out.append("at least 1 repo nested in an ignored folder has work this archive does not cover")
    if nested_cut:
        out.append(NESTED_CUT_NOTE)
    if not info.bare:  # assume-unchanged / skip-worktree: edits that status and diff cannot see
        flags = _git(info.root, "ls-files", "-v", "-z", check=False, timeout=60).stdout.split(b"\0")
        hidden = sum(1 for ent in flags if ent[:1] in (b"h", b"S"))
        if hidden:
            out.append("%d tracked file(s) hidden from status (assume-unchanged or skip-worktree) this archive does not cover" % hidden)
    return out


# ---------------------------------------------------------------- public: inspection


def ignored_large(repo: str, min_bytes: Optional[int] = None, limit: int = IGNORED_MAX_LISTED) -> List[dict]:
    """Ignored files/directories >= min_bytes, biggest first. Read-only; sizes are apparent.

    Sizing stops after SCAN_BUDGET directory entries (later entries are not sized).
    """
    try:
        info = _locate(repo)
    except _Unreadable:
        return []
    if info is None:
        return []
    return _ignored_large(info, IGNORED_MIN_BYTES if min_bytes is None else min_bytes, limit)


def _ignored_large(info: _Repo, threshold: int, limit: int) -> List[dict]:
    if info.bare:
        return []
    out = _git(
        info.root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"
    ).stdout
    budget = [SCAN_BUDGET]
    found: List[dict] = []
    for raw in _nul(out):
        if budget[0] <= 0:
            break
        full = os.path.join(info.root, os.fsdecode(raw))
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode):
            size, truncated = _tree_bytes(full, budget)
        else:
            size, truncated = st.st_size, False
        if size >= threshold:
            found.append({"path": _clean(os.fsdecode(raw), 300), "bytes": size, "approx": truncated})
    found.sort(key=lambda item: item["bytes"], reverse=True)
    return found[:limit]


def _ignored_note(items: List[dict]) -> str:
    if not items:
        return ""
    shown = ", ".join("%s (%s)" % (i["path"], _human(i["bytes"])) for i in items[:5])
    more = " +%d more" % (len(items) - 5) if len(items) > 5 else ""
    return " | ignored large, NOT archived: " + shown + more


def needs_archive(repo: str) -> Tuple[bool, str]:
    try:
        info = _locate(repo)
        if info is None:
            return False, "not a git repository"
    except _Unreadable as exc:
        return True, "git cannot read this repository, treated as needing archive: " + str(exc)
    except CorecleanerError as exc:
        return True, "could not inspect the repository, treated as needing archive: " + exc.message
    kinds = _unsafe(info)
    if kinds:
        return True, "repo config can run programs (%s): not read, treated as needing archive" % ", ".join(kinds)
    try:
        f = _facts(info)
        note = _ignored_note(_ignored_large(info, IGNORED_MIN_BYTES, IGNORED_MAX_LISTED))
        protected, protected_cut = _ignored_protected(info)
    except CorecleanerError as exc:
        return True, "could not inspect the repository, treated as needing archive: " + exc.message
    reasons = []
    if f["tracked"]:
        reasons.append("%d uncommitted change(s)" % f["tracked"])
    if f["untracked"]:
        reasons.append("%d untracked file(s)" % f["untracked"])
    if f["unpublished"]:
        reasons.append(
            "%d commit(s) on no remote%s" % (f["unpublished"], "" if f["remotes"] else " (no remote configured)")
        )
    if f.get("tag_only"):
        reasons.append("%d commit(s) reachable only from local tags" % f["tag_only"])
    if f["stashes"]:
        reasons.append("%d stash entr%s" % (f["stashes"], "y" if f["stashes"] == 1 else "ies"))
    if protected:
        reasons.append("%d ignored path(s) with protected names (.env, keys)" % len(protected))
    if protected_cut:
        note += " | " + PROTECTED_CUT_NOTE
    if reasons:
        if f.get("shallow"):
            note += " | shallow clone: archived as one tar of the whole repo, not as a bundle"
        return True, "; ".join(reasons) + note
    if f.get("shallow"):  # its history was fetched from a remote: nothing here to save
        return False, "clean, shallow clone with nothing local, no stash" + note
    return False, "clean, published, no stash" + note


def incomplete(repo: str) -> List[str]:
    """Fixed labels for work an archive of `repo` would NOT cover (see `_incomplete`); read-only, [] = covered."""
    try:
        info = _locate(repo)
        return _incomplete(info) if info is not None else []
    except _Unreadable:
        return []  # archive_repo refuses an unreadable repo by itself; nothing partial to warn about
    except CorecleanerError:
        return ["could not inspect submodules and linked worktrees"]


def estimate_archive_bytes(repo: str) -> int:
    info = _need_repo(repo)
    facts = _facts(info)
    return _estimate(info, facts, _untracked_entries(info, facts["head"] is not None))


# ---------------------------------------------------------------- archive store: cap and old archives


def archive_cap_bytes() -> int:
    """The cap on the whole archive store: ARCHIVE_CAP_BYTES, or CORECLEANER_ARCHIVE_CAP_GIB when it is a positive number."""
    raw = os.environ.get(ARCHIVE_CAP_ENV, "").strip()
    if raw:
        try:
            gib = float(raw)
        except ValueError:
            gib = 0.0
        if 0 < gib <= 1_000_000:
            return int(gib * GIB)
    return ARCHIVE_CAP_BYTES


def store_bytes(root) -> int:
    """Apparent bytes of everything under the archive store (lstat only, links not followed); 0 when it does not exist."""
    return _tree_bytes(os.fspath(root))[0]


def check_quota(root, repos: Sequence[str]) -> None:
    """Raise CorecleanerError(EXIT_NO_SPACE_FOR_ARCHIVE, quota=True) when archiving `repos` would pass the cap.

    Read-only; run before anything is created. A repo whose estimate cannot be read counts as the minimum:
    archive_repo refuses an unreadable repo by itself, with its own reason.
    """
    cap = archive_cap_bytes()
    used = store_bytes(root)
    need = 0
    for repo in repos:
        try:
            need += estimate_archive_bytes(repo)
        except CorecleanerError:
            need += MIN_ESTIMATE
    if used + need > cap:
        raise CorecleanerError(
            EXIT_NO_SPACE_FOR_ARCHIVE,
            "the archive folder holds %s of its %s cap and this archive needs about %s more: older archives must go first"
            % (_human(used), _human(cap), _human(need)),
            quota=True,
            used_bytes=used,
            cap_bytes=cap,
            need_bytes=need,
        )


def _archive_dirs(root: str) -> List[str]:
    """`<root>/<day>/<archive>` folders (real directories only; a link is never followed)."""
    out: List[str] = []
    try:
        days = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return out
    for day in days:
        try:
            if not day.is_dir(follow_symlinks=False):
                continue
            kids = sorted(os.scandir(day.path), key=lambda e: e.name)
        except OSError:
            continue
        out.extend(k.path for k in kids if k.is_dir(follow_symlinks=False))
    return out


def store_report(root, days: int = ARCHIVE_STALE_DAYS, now: Optional[float] = None) -> dict:
    """Read-only picture of the archive store: size, cap and the archives untouched for `days` or more.

    Age is the archive folder's own mtime (its files are written once, MANIFEST.txt last). Nothing is
    removed; `old` is oldest first, at most STALE_LISTED rows, `old_count` / `old_bytes` cover all of them.
    """
    root = os.fspath(root)
    stamp = time.time() if now is None else now
    old: List[dict] = []
    total = 0
    for path in _archive_dirs(root):
        total += 1
        try:
            mtime = os.lstat(path).st_mtime
        except OSError:
            continue
        age = int((stamp - mtime) // 86400)
        if age >= days:
            old.append({"path": path, "age_days": age, "bytes": _tree_bytes(path)[0]})
    old.sort(key=lambda row: (-row["age_days"], row["path"]))
    return {
        "root": root,
        "bytes": store_bytes(root),
        "cap_bytes": archive_cap_bytes(),
        "archives": total,
        "older_than_days": days,
        "old_count": len(old),
        "old_bytes": sum(row["bytes"] for row in old),
        "old": old[:STALE_LISTED],
    }


# ---------------------------------------------------------------- archive pieces


def _default_dest(root: str) -> Path:
    now = datetime.now(timezone.utc)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(root)).strip("._")[:40] or "repo"
    tag = hashlib.sha256(root.encode("utf-8", "surrogateescape")).hexdigest()[:6]
    return Path.home() / "corecleaner-archive" / now.strftime("%Y-%m-%d") / ("%s-%s-%s" % (slug, now.strftime("%H%M%S"), tag))


def _resolve_dest(root: str, dest: Optional[str]) -> Path:
    path = _default_dest(root) if dest is None else Path(os.path.expanduser(str(dest)))
    path = Path(os.path.abspath(str(path)))
    if os.path.islink(path):
        raise CorecleanerError(EXIT_ERROR, "archive destination is a symlink; refusing", dest=str(path))
    real = os.path.realpath(str(path))
    try:
        inside_repo = os.path.commonpath([real, root]) == root
    except ValueError:
        inside_repo = False
    if inside_repo:
        raise CorecleanerError(EXIT_ERROR, "archive destination is inside the repository; refusing", dest=str(path))
    if os.path.lexists(path):
        if not path.is_dir() or any(path.iterdir()):
            raise CorecleanerError(EXIT_ERROR, "archive destination exists and is not an empty directory", dest=str(path))
    return path


def _existing_ancestor(path: Path) -> Path:
    cur = path
    while not cur.exists() and cur.parent != cur:
        cur = cur.parent
    return cur


def _create_private(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(str(path), flags, 0o600), "wb")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _create_bundle(root: str, out: Path) -> None:
    # --reflog: older stash entries (stash@{1..n}) and dropped commits live only in the reflog
    _git(root, "bundle", "create", "--quiet", str(out), "--all", "--reflog", timeout=_WRITE_TIMEOUT)
    if os.name == "posix":
        os.chmod(out, 0o600)


def _verify_bundle(root: str, bundle: Path, refs: List[tuple]) -> None:
    _git(root, "bundle", "verify", "--quiet", str(bundle), timeout=_WRITE_TIMEOUT)
    listed = {x.split(b" ", 1)[1].strip() for x in _lines(_git(root, "bundle", "list-heads", str(bundle)).stdout) if b" " in x}
    missing = [r[1] for r in refs if len(r) == 2 and not r[1].startswith(b"refs/remotes/") and r[1] not in listed]
    if missing:
        raise CorecleanerError(
            EXIT_ERROR, "bundle is missing %d ref(s), e.g. %s" % (len(missing), _clean(missing[0], 120))
        )


def _write_patch(root: str, out: Path) -> bool:
    """`git diff --binary HEAD` to out. False (nothing written) when there is no tracked change."""
    if _git(root, "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", check=False).returncode == 0:
        return False
    with _create_private(out) as fh:
        _git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", stdout=fh, timeout=_WRITE_TIMEOUT)
    return True


def _write_untracked_tar(root: str, out: Path, entries: List[bytes], label: str = "untracked") -> Tuple[int, List[str]]:
    """Tar.gz of untracked paths, symlinks stored as links. Returns (members, vanished paths)."""
    vanished: List[str] = []
    with _create_private(out) as fh:
        with tarfile.open(fileobj=fh, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
            for raw in entries:
                rel = os.fsdecode(raw)
                full = os.path.join(root, rel)
                try:
                    tf.add(full.rstrip("/"), arcname=rel.rstrip("/"), recursive=rel.endswith("/"))
                except FileNotFoundError:
                    vanished.append(_clean(rel, 200))
                except OSError as exc:
                    code = EXIT_NO_SPACE_FOR_ARCHIVE if exc.errno == errno.ENOSPC else EXIT_ERROR
                    raise CorecleanerError(code, "cannot archive %s file %s: %s" % (label, _clean(rel, 120), exc.strerror))
            members = len(tf.getmembers())
    with tarfile.open(str(out), "r:gz") as tf:  # a full read-back checks the gzip CRC
        seen = sum(1 for _ in tf)
    if seen != members:
        raise CorecleanerError(EXIT_ERROR, "%s tar read back %d members, wrote %d" % (label, seen, members))
    return members, vanished


def _force(fn, path: str) -> None:
    try:
        fn(path)
    except PermissionError:
        os.chmod(path, stat.S_IRWXU)
        fn(path)


def _remove_own_temp(path: Path, root: Path) -> None:
    """Delete a scratch directory this module created. The only deletion in the module.

    Refuses anything that is not strictly inside `root`; symlinks are unlinked, never followed.
    """
    real_root = os.path.realpath(str(root))
    real = os.path.realpath(str(path))
    try:
        inside = real != real_root and os.path.commonpath([real, real_root]) == real_root
    except ValueError:
        inside = False
    if os.path.islink(str(path)) or not inside:
        raise CorecleanerError(EXIT_ERROR, "refusing to delete outside the scratch directory", path=str(path))
    for cur, dirs, files in os.walk(str(path), topdown=False):
        for name in files:
            _force(os.unlink, os.path.join(cur, name))
        for name in dirs:
            full = os.path.join(cur, name)
            _force(os.unlink if os.path.islink(full) else os.rmdir, full)
    _force(os.rmdir, str(path))


def _restore_test(dest: Path, bundle: Path, patch: Optional[Path], facts: dict) -> str:
    """Clone the bundle into scratch space under dest and check the result. Raises on any failure."""
    scratch_root = dest / "tmp"
    scratch_root.mkdir(mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="restore-", dir=str(scratch_root)))
    try:
        clone = work / "clone"
        _git(work, "clone", "--quiet", "--no-checkout", str(bundle), str(clone), timeout=_WRITE_TIMEOUT)
        if facts["head"]:
            got = _git(clone, "rev-parse", "--verify", "HEAD").stdout.strip().decode("ascii", "replace")
            if got != facts["head"]:
                raise CorecleanerError(EXIT_ERROR, "restore test: clone HEAD %s != source HEAD %s" % (got[:12], facts["head"][:12]))
        shas = b"".join(r[0] + b"\n" for r in facts["refs"] if len(r) == 2)
        if shas:
            checked = _git(clone, "cat-file", "--batch-check", input_bytes=shas).stdout
            if b" missing" in checked:
                raise CorecleanerError(EXIT_ERROR, "restore test: a ref object is missing from the clone")
        _git(clone, "fsck", "--connectivity-only", "--no-dangling", "--no-progress", timeout=_WRITE_TIMEOUT)
        if patch is not None:
            _git(clone, "read-tree", "HEAD")
            _git(clone, "apply", "--cached", "--check", str(patch))
        return "git clone of the bundle, fsck --connectivity-only" + (", dirty.patch applies" if patch else "")
    finally:
        try:
            _remove_own_temp(work, scratch_root)
            scratch_root.rmdir()
        except (OSError, CorecleanerError) as exc:
            log("could not remove scratch clone %s: %s" % (work, exc))


def _manifest_text(src: str, facts: dict, files: List[dict], extra: dict, ignored: List[dict], warnings: List[str], restore_test: str) -> str:
    restore = [
        "  git clone bundle.git restored        # every branch is there as origin/<name>",
        "  git -C restored apply ../dirty.patch # if dirty.patch exists",
        "  tar -xzf untracked.tar.gz -C restored # if untracked.tar.gz exists",
        "  tar -xzf ignored-protected.tar.gz -C restored # ignored .env/keys, if the file exists",
        "  git -C restored fetch ../bundle.git refs/stash:refs/stash   # only if stash_entries > 0",
    ]
    if extra.get("shallow"):
        restore = [
            "  mkdir restored && tar -xzf %s -C restored   # the whole repo: work tree, ignored files and .git" % SHALLOW_TAR_NAME,
            "  git -C restored status               # a shallow clone: its history stops at the boundary commits",
        ]
    out = [
        "corecleaner archive manifest",
        "created: " + now_iso(),
        "repo: " + _clean(src, 500),
        "head: %s%s" % (facts["head"] or "none (no commits)", " (branch %s)" % facts["branch"] if facts["branch"] else ""),
        "refs: %d" % len(facts["refs"]),
        "unpublished_commits: %d" % facts["unpublished"],
        "stash_entries: %d" % facts["stashes"],
        "uncommitted_changes: %d" % facts["tracked"],
        "untracked_files: %d (tar members: %d)" % (facts["untracked"], extra["tar_members"]),
    ]
    if extra.get("shallow"):
        out.append("shallow: yes (no bundle can be cloned from a shallow repo; %s holds everything)" % SHALLOW_TAR_NAME)
    out += [
        "verified: " + restore_test,
        "",
        "restore (run inside this directory):",
        *restore,
        "",
        "files (sha256  bytes  name):",
    ]
    out.extend("  %s  %d  %s" % (f["sha256"], f["bytes"], f["name"]) for f in files)
    if ignored:
        out += ["", "ignored files NOT archived (>= %s):" % _human(IGNORED_MIN_BYTES)]
        out.extend("  %d  %s%s" % (i["bytes"], i["path"], " (approx)" if i["approx"] else "") for i in ignored)
    if warnings:
        out += ["", "warnings:"] + ["  " + w for w in warnings]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- public: archive


def archive_repo(repo: str, dest: Optional[str] = None) -> dict:
    info = _need_repo(repo)
    root = info.root
    dest_path = _resolve_dest(root, dest)
    facts = _facts(info)
    has_head = facts["head"] is not None
    entries = _untracked_entries(info, has_head)
    estimate = _estimate(info, facts, entries)
    need = SPACE_FACTOR * estimate
    free = shutil.disk_usage(str(_existing_ancestor(dest_path))).free
    if free < need:
        raise CorecleanerError(
            EXIT_NO_SPACE_FOR_ARCHIVE,
            "not enough free space to archive: need %s, free %s" % (_human(need), _human(free)),
            need_bytes=need,
            free_bytes=free,
            estimate_bytes=estimate,
        )

    created = not dest_path.exists()
    dest_path.mkdir(parents=True, exist_ok=True)
    if created and os.name == "posix":
        os.chmod(dest_path, 0o700)
    try:
        return _archive_into(info, dest_path, facts, entries)
    except CorecleanerError as exc:
        exc.details.setdefault("dest", str(dest_path))
        exc.details["note"] = "partial files may remain in dest; no MANIFEST.txt means the archive is incomplete"
        raise
    except OSError as exc:
        code = EXIT_NO_SPACE_FOR_ARCHIVE if exc.errno == errno.ENOSPC else EXIT_ERROR
        raise CorecleanerError(code, "archive failed: %s" % (exc.strerror or exc), dest=str(dest_path))


def _whole_repo_entries(root: str) -> List[bytes]:
    """Every top-level entry of the repo folder (`.git` included), folders with a trailing '/' so the tar recurses."""
    out: List[bytes] = []
    for name in sorted(os.listdir(root)):
        full = os.path.join(root, name)
        is_dir = os.path.isdir(full) and not os.path.islink(full)
        out.append(os.fsencode(name + ("/" if is_dir else "")))
    return out


def _verify_whole_tar(tar: Path, bare: bool) -> str:
    """List the tar from start to end (so the gzip CRC is read) and require the git dir's HEAD and shallow file in it."""
    prefix = "" if bare else ".git/"
    with tarfile.open(str(tar), "r:gz") as tf:
        names = {m.name for m in tf}
    missing = [n for n in (prefix + "HEAD", prefix + "shallow") if n not in names]
    if missing:
        raise CorecleanerError(EXIT_ERROR, "whole-repo tar does not list %s" % ", ".join(missing))
    return "tar listed to the end (%d members), %sHEAD and %sshallow present" % (len(names), prefix, prefix)


def _archive_shallow_into(info: _Repo, dest: Path, facts: dict) -> dict:
    """A shallow clone cannot be bundled (the bundle misses the objects behind the boundary and `git clone` of it
    fails with "remote did not send all necessary objects"): the whole repo goes into one tar instead.

    The tar holds the work tree (modified, untracked and ignored files, `.env` included) and `.git` as they
    are, so no patch, no untracked tar and no scan for protected names are needed.
    """
    root = info.root
    if not info.bare and not os.path.isdir(os.path.join(root, ".git")):
        raise CorecleanerError(
            EXIT_ERROR,
            "shallow checkout whose .git is not a folder (linked worktree or submodule): its history lives outside this folder",
        )
    tar = dest / SHALLOW_TAR_NAME
    members, vanished = _write_untracked_tar(root, tar, _whole_repo_entries(root), "whole-repo")
    restore_test = _verify_whole_tar(tar, info.bare)
    warnings: List[str] = []
    if vanished:
        warnings.append("%d top-level path(s) vanished while archiving, e.g. %s" % (len(vanished), vanished[0]))
    after = _facts(info)
    if after["refs_fingerprint"] != facts["refs_fingerprint"]:
        raise CorecleanerError(EXIT_ERROR, "the repository changed while it was being archived; try again when it is idle")
    incomplete = _incomplete(info)
    warnings.extend(incomplete)
    files = [{"name": tar.name, "bytes": tar.stat().st_size, "sha256": _sha256(tar)}]
    manifest = dest / MANIFEST_NAME
    text = _manifest_text(root, facts, files, {"tar_members": members, "shallow": True}, [], warnings, restore_test)
    with _create_private(manifest) as fh:
        fh.write(text.encode("utf-8", "backslashreplace"))
    return {
        "dest": str(dest),
        "bundle": None,
        "diff": None,
        "untracked_tar": None,
        "protected_tar": None,
        "repo_tar": str(tar),
        "shallow": True,
        "incomplete": incomplete,
        "manifest": str(manifest),
        "bytes": sum(f["bytes"] for f in files) + manifest.stat().st_size,
        "verified": True,
        "restore_test": restore_test,
        "files": files,
        "counts": {
            "refs": len(facts["refs"]),
            "unpublished_commits": facts["unpublished"],
            "stash_entries": facts["stashes"],
            "uncommitted_changes": facts["tracked"],
            "untracked_files": facts["untracked"],
            "tar_members": members,
            "ignored_protected": 0,
        },
        "ignored_large": [],
        "warnings": warnings,
    }


def _archive_into(info: _Repo, dest: Path, facts: dict, entries: List[bytes]) -> dict:
    root = info.root
    if facts.get("shallow"):
        return _archive_shallow_into(info, dest, facts)
    has_head = facts["head"] is not None
    warnings: List[str] = []
    bundle: Optional[Path] = None
    if facts["refs"] or has_head:
        bundle = dest / BUNDLE_NAME
        _create_bundle(root, bundle)
        _verify_bundle(root, bundle, facts["refs"])
    patch: Optional[Path] = None
    if has_head and not info.bare and _write_patch(root, dest / PATCH_NAME):
        patch = dest / PATCH_NAME
    tar: Optional[Path] = None
    members, vanished = 0, []
    if entries:
        tar = dest / TAR_NAME
        members, vanished = _write_untracked_tar(root, tar, entries)
    if vanished:
        warnings.append("%d untracked path(s) vanished while archiving, e.g. %s" % (len(vanished), vanished[0]))
    protected_tar: Optional[Path] = None
    protected, protected_cut = _ignored_protected(info)
    if protected:
        total = sum(_lstat_size(os.path.join(root, h.rstrip("/"))) for h in protected)
        if total > PROTECTED_MAX_BYTES:
            raise CorecleanerError(
                EXIT_ERROR,
                "ignored files with protected names hold %s (limit %s): move them out by hand" % (_human(total), _human(PROTECTED_MAX_BYTES)),
            )
        protected_tar = dest / PROTECTED_TAR_NAME
        _write_untracked_tar(root, protected_tar, [os.fsencode(h) for h in protected])
    if bundle is not None:
        restore_test = _restore_test(dest, bundle, patch, facts)
    else:
        restore_test = "no commits: nothing to bundle, untracked tar read back"

    after = _facts(info)
    if after["refs_fingerprint"] != facts["refs_fingerprint"]:
        raise CorecleanerError(EXIT_ERROR, "the repository changed while it was being archived; try again when it is idle")
    if os.path.exists(os.path.join(root, ".gitmodules")):
        warnings.append("submodules present: their working trees are not archived")
    incomplete = _incomplete(info)
    if protected_cut:  # not a mere warning: the caller must not trash what was not fully read
        incomplete.append(PROTECTED_CUT_NOTE)
    warnings.extend(incomplete)

    ignored = _ignored_large(info, IGNORED_MIN_BYTES, IGNORED_MAX_LISTED)
    files = []
    for path in (bundle, patch, tar, protected_tar):
        if path is not None:
            files.append({"name": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)})
    manifest = dest / MANIFEST_NAME
    text = _manifest_text(root, facts, files, {"tar_members": members}, ignored, warnings, restore_test)
    with _create_private(manifest) as fh:
        fh.write(text.encode("utf-8", "backslashreplace"))
    return {
        "dest": str(dest),
        "bundle": str(bundle) if bundle else None,
        "diff": str(patch) if patch else None,
        "untracked_tar": str(tar) if tar else None,
        "protected_tar": str(protected_tar) if protected_tar else None,
        "incomplete": incomplete,
        "manifest": str(manifest),
        "bytes": sum(f["bytes"] for f in files) + manifest.stat().st_size,
        "verified": True,
        "restore_test": restore_test,
        "files": files,
        "counts": {
            "refs": len(facts["refs"]),
            "unpublished_commits": facts["unpublished"],
            "stash_entries": facts["stashes"],
            "uncommitted_changes": facts["tracked"],
            "untracked_files": facts["untracked"],
            "tar_members": members,
            "ignored_protected": len(protected),
        },
        "ignored_large": ignored,
        "warnings": warnings,
    }
