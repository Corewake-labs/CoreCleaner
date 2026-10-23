"""Audit of the git repos under HOME, biggest first. (M1 of docs/SPEC-migrate.md; subcommand `repos`)

Read-only. inventory.find_repos finds them; per repo: allocated bytes and node_modules bytes (lstat walk, an upper
bound), idle days (newest mtime outside node_modules and .git/objects, or the last commit, whichever is newer),
git state (gitguard first: a repo whose own config runs programs is not read), remotes as host/owner, local
branches on no remote, notes that say a branch must never be pushed, and every reason the repo cannot be moved
(`blockers`, fixed labels). Citations come from inventory's dependency search (one rg for all repos).

run(args): args.roots (None = HOME), args.min_days. Saves the full result to state/repos/repos-<ts>.json, signed
("repos"), and returns a sanitized summary; `migrate-plan --repos` accepts only that file.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import common, gitguard, inventory, safety, views
from . import migrate_copy as mc
from . import plan as plan_mod
from .common import CorecleanerError

MIN_IDLE_DAYS = 45
DISCOVERY_DEPTH = 6
WALK_CAP = 3_000_000
SUMMARY_ROWS = 50
NOTE_MAX_FILES = 200
NOTE_MAX_BYTES = 1 << 20
SKIP_NAMES = ("node_modules",)
NEVER_PUSH_RE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s*n[o']t|should\s*n[o']t|shall\s+not|cannot|can'?t)\s+(?:ever\s+)?(?:be\s+)?"
    r"(?:push|publish|upload|share)(?:ed|d)?\b|\bnot\s+(?:to\s+)?be\s+(?:push|publish)ed\b"
    r"|\b(?:nunca|n[aã]o|jamais)\s+(?:se\s+)?(?:pode\s+|deve\s+)?(?:fa[cç]a\s+|fazer\s+|d[eê]\s+|dar\s+)?"
    r"(?:push|sobe|subir|suba|envie|enviar|envia|publique|publicar|publica)\b"
    r"|\blocal[ -]only\b|\bs[oó]\s+local\b|\b(?:apenas|somente)\s+local\b|\bkeep\s+(?:it\s+|this\s+)?local\b", re.I)
_NOTE_EXT = (".md", ".txt", ".rst", ".markdown")
_NOTE_DIRS = ("docs", "doc", "notes", ".claude", ".github")
_NOTE_DEPTH = 3
# git grep pre-filter (ERE, case-insensitive); NEVER_PUSH_RE decides on the lines it returns.
_GREP_HINT = r"push|publi|sob|sub|envi|local|share|upload"
_NOTE_SPECS = tuple(":(glob,icase)**/*" + e for e in _NOTE_EXT) + tuple(
    ":(glob,icase)**/%s*" % n for n in ("NOTES", "TODO", "README", "CLAUDE", "AGENTS")) + tuple(
    ":(glob)%s/**" % d for d in _NOTE_DIRS)
_TOKEN_RE = re.compile(r"[\w./@+-]+")


def _git(ctx: inventory.Ctx, repo: str, *args: str) -> Tuple[int, str]:
    return inventory._git(ctx, repo, *args)


# ---------------------------------------------------------------- sizes and idle time

def walk_sizes(root: str, cap: int = WALK_CAP) -> Dict[str, Any]:
    """{bytes, node_modules_bytes, newest, entries, truncated, unreadable}. lstat only, one device.

    `newest` counts files and links only (a folder's mtime moves when Finder writes a .DS_Store), leaves out
    node_modules, Finder files and everything in .git but HEAD, ORIG_HEAD and logs/HEAD: an install, a browse,
    a fetch, a `git status` or a gc is not an edit of the project. 0.0 when the tree holds no file."""
    st = os.lstat(root)
    out = {"bytes": inventory._alloc(st), "node_modules_bytes": 0, "newest": 0.0, "entries": 0,
           "truncated": False, "unreadable": 0}
    gitdir = os.path.join(root, ".git")
    signals = {os.path.join(gitdir, r) for r in ("HEAD", "ORIG_HEAD", os.path.join("logs", "HEAD"))}
    stack: List[Tuple[str, bool, bool]] = [(root, False, False)]
    while stack:
        d, in_nm, in_git = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            out["unreadable"] += 1
            continue
        with it:
            for e in it:
                out["entries"] += 1
                if out["entries"] > cap:
                    out["truncated"] = True
                    return out
                try:
                    est = e.stat(follow_symlinks=False)
                except OSError:
                    out["unreadable"] += 1
                    continue
                size = inventory._alloc(est)
                out["bytes"] += size
                nm = in_nm or (e.name in SKIP_NAMES and stat.S_ISDIR(est.st_mode) and mc.regenerable_node_modules(root, e.path))
                if nm:
                    out["node_modules_bytes"] += size
                git = in_git or e.path == gitdir
                if not nm and not inventory.is_noise(e.name) and not stat.S_ISDIR(est.st_mode) and (not git or e.path in signals):
                    out["newest"] = max(out["newest"], est.st_mtime)
                if stat.S_ISDIR(est.st_mode) and est.st_dev == st.st_dev:
                    stack.append((e.path, nm, git))
    return out


# ---------------------------------------------------------------- remotes

def parse_remote(url: str) -> Tuple[str, str]:
    """(host, owner) of a remote URL; owner = the path component before the repo name. Local paths: host "local"."""
    host, parts = remote_parts(url)
    return host, (parts[-2] if len(parts) >= 2 else "")


def remote_parts(url: str) -> Tuple[str, List[str]]:
    """(host, path components) of a remote URL; ("", []) when it cannot be read."""
    url = url.strip()
    path = ""
    host = "local"
    if re.match(r"^[A-Za-z]:[\\/]", url) or url.startswith(("/", ".", "~")):
        path = url
    elif url.lower().startswith("file://"):
        path = url[7:]
    else:
        m = re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://(?:[^@/]*@)?([^/:]+)(?::\d+)?/(.*)$", url)
        m = m or re.match(r"^(?:[^@/]+@)?([^/:]+):(?!/)(.*)$", url)
        if not m:
            return "", []
        host, path = m.group(1).lower(), m.group(2)
    return host, [p for p in re.split(r"[\\/]+", path) if p]


def remotes_of(run: Any) -> List[dict]:
    """[{name, push: [{host, owner, depth, url}], mirror}] (push URLs after insteadOf rewriting: where a push goes)."""
    rc, out = run("remote")
    found: List[dict] = []
    for name in (out.split() if rc == 0 else []):
        rc, urls = run("remote", "get-url", "--push", "--all", name)
        targets = [dict(zip(("host", "owner"), parse_remote(u)), depth=len(remote_parts(u)[1]), url=u.strip())
                   for u in urls.splitlines() if u.strip()] if rc == 0 else []
        rc, mirror = run("config", "--bool", "--get", "remote.%s.mirror" % name)
        found.append({"name": name, "push": targets, "mirror": rc == 0 and mirror.strip() == "true"})
    return found


# ---------------------------------------------------------------- branches and never-push notes

def branches_of(run: Any) -> List[dict]:
    """Local branches: [{name, sha, upstream_remote, pending}] where pending = commits on no remote-tracking ref."""
    rc, out = run("for-each-ref", "--format=%(refname)%00%(objectname)%00%(upstream:remotename)", "refs/heads")
    rows: List[dict] = []
    for ln in (out.splitlines() if rc == 0 else []):
        parts = ln.split("\0")
        if len(parts) < 3 or not parts[0].startswith("refs/heads/"):
            continue
        parts[0] = parts[0][len("refs/heads/"):]  # :short turns into "heads/x" when a tag shares the name
        rc2, cnt = run("rev-list", "--count", parts[1], "--not", "--remotes")
        pending = int(cnt.strip()) if rc2 == 0 and cnt.strip().isdigit() else -1  # -1 = unknown, never "clean"
        rows.append({"name": parts[0], "sha": parts[1], "upstream_remote": parts[2] or None, "pending": pending})
    return rows


def _is_note(name: str) -> bool:
    return name.lower().endswith(_NOTE_EXT) or ("." not in name and name.upper() == name and name.isalpha())


def _note_files(repo: str) -> Tuple[List[str], bool]:
    """Note-like files in the work tree: top level, and up to _NOTE_DEPTH folders down in docs/, notes/, .claude/...
    Second value True = more than NOTE_MAX_FILES (not all read: the caller fails closed)."""
    files = [e.path for e in inventory._entries(repo) if inventory._is_real_file(e) and _is_note(e.name)]
    stack = [(os.path.join(repo, d), 1) for d in _NOTE_DIRS]
    while stack:
        d, depth = stack.pop()
        for e in inventory._entries(d):
            if inventory._is_real_file(e) and _is_note(e.name):
                files.append(e.path)
            elif depth < _NOTE_DEPTH and inventory._is_real_dir(e):
                stack.append((e.path, depth + 1))
    return files[:NOTE_MAX_FILES], len(files) > NOTE_MAX_FILES


def never_push(repo: str, branches: Sequence[str], run: Any, tips: Sequence[str] = ()) -> Dict[str, Any]:
    """Branches a note says must never be pushed: {"all": bool, "branches": [...]}.

    Read from note-like files of the work tree, from the same files committed at each of `tips` (a note may live
    only on the branch it guards; `git grep` reads the tree, nothing is checked out) and from
    `branch.<b>.description`. A note line that names no branch of this repo covers them all: the safe reading of
    "this repo is local-only". Anything not read to the end also covers them all (fail closed)."""
    found: List[str] = []
    every = False
    names = set(branches)

    def take(line: str, only: Optional[str] = None) -> None:
        nonlocal every
        if not NEVER_PUSH_RE.search(line):
            return
        if only is not None:
            found.append(only)
            return
        hit = [b for b in _TOKEN_RE.findall(line.replace("`", " ")) if b in names]
        if hit:
            found.extend(hit)
        else:
            every = True

    files, cut = _note_files(repo)
    every = cut
    for f in files:
        try:
            with open(f, "rb") as fh:
                text = fh.read(NOTE_MAX_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            take(line)
    for sha in dict.fromkeys(tips):
        rc, out = run("grep", "-I", "-i", "-E", "-h", "--no-color", "-e", _GREP_HINT, sha, "--", *_NOTE_SPECS)
        if rc not in (0, 1):
            every = True
            continue
        for line in out.splitlines():
            take(line)
    for b in branches:
        rc, desc = run("config", "--get", "branch.%s.description" % b)
        if rc == 0:
            for line in desc.splitlines():
                take(line, b)
    return {"all": every, "branches": sorted(set(found))}


# ---------------------------------------------------------------- what makes a repo unmovable

def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _gitdir_file(dotgit: str) -> Optional[str]:
    try:
        with open(dotgit, "rb") as fh:
            m = re.match(r"gitdir:\s*(.+)", fh.read(4096).decode("utf-8", "replace"))
    except OSError:
        return None
    if not m:
        return None
    gd = m.group(1).strip()
    return os.path.realpath(gd if os.path.isabs(gd) else os.path.join(os.path.dirname(dotgit), gd))


def blockers(ctx: inventory.Ctx, repo: str) -> List[str]:
    """Fixed labels for every reason `repo` must not be moved; [] = movable. Also re-run right before a move."""
    out: List[str] = []
    if plan_mod.has_control(repo):
        out.append("path has control characters")
    protected, _why = safety.is_protected(repo)
    if protected:
        out.append("protected by the deny list")
    cloud, _kind = safety.is_cloud_or_placeholder(repo)
    if cloud:
        return out + ["in a cloud-synced folder"]  # never read a synced tree further (it may download)
    dotgit = os.path.join(repo, ".git")
    if os.path.islink(dotgit) or not os.path.isdir(dotgit):
        return out + ["its .git is a file or link: a linked worktree or a gitdir that lives elsewhere"]
    if not ctx.which("git"):
        return out + ["git not found: cannot inspect"]
    run = lambda *a: _git(ctx, repo, *a)  # noqa: E731
    unsafe = gitguard.unsafe_config(run, repo)
    if unsafe:
        return out + ["repo config can run programs (%s)" % ", ".join(unsafe)]
    try:
        alt = Path(dotgit, "objects", "info", "alternates").read_text("utf-8", "replace").strip()
    except OSError:
        alt = ""
    if alt:
        out.append("borrows objects from another repo (alternates)")
    rc, wt = run("config", "--get", "core.worktree")
    if rc == 0 and wt.strip():
        out.append("core.worktree points the work tree elsewhere")
    rc, text = run("worktree", "list", "--porcelain")
    if rc != 0:
        out.append("git worktree list failed: cannot prove no linked worktree")
    for blk in inventory._parse_worktrees(text)[1:] if rc == 0 else []:
        wt_path = blk.get("worktree")
        if isinstance(wt_path, str) and os.path.isdir(wt_path) and not _inside(os.path.realpath(wt_path), repo):
            out.append("linked worktree outside the tree (moving would break it)")
            break
    if os.path.exists(os.path.join(repo, ".gitmodules")):
        rc, mods = run("config", "--file", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$")
        for line in (mods.splitlines() if rc == 0 else []):
            sub = line.partition(" ")[2].strip()
            subgit = os.path.join(repo, sub, ".git")
            if sub and os.path.isfile(subgit) and not os.path.islink(subgit):
                gd = _gitdir_file(subgit)
                if gd is None or not _inside(gd, repo):
                    out.append("submodule whose gitdir is outside the tree")
                    break
            elif sub and os.path.islink(subgit):
                out.append("submodule whose .git is a link")
                break
    return out


# ---------------------------------------------------------------- audit

def _git_state(ctx: inventory.Ctx, repo: str) -> Dict[str, Any]:
    run = lambda *a: _git(ctx, repo, *a)  # noqa: E731
    info = inventory.git_info(ctx, repo)
    branches = branches_of(run)
    rc, tags_only = run("rev-list", "--count", "--tags", "--not", "--branches", "--remotes")
    return {
        "dirty": bool(info.get("dirty")), "stash": int(info.get("stash") or 0), "error": info.get("error"),
        "remotes": [{"name": r["name"], "mirror": r["mirror"], "push": [{"host": t["host"], "owner": t["owner"]} for t in r["push"]]}
                    for r in remotes_of(run)],
        "branches": branches,
        "tag_only_commits": int(tags_only.strip()) if rc == 0 and tags_only.strip().isdigit() else 0,
        "never_push": never_push(repo, [b["name"] for b in branches], run, [b["sha"] for b in branches if b["pending"] != 0]),
        "last_commit_epoch": inventory._last_commit_epoch(ctx, repo),
    }


def _one(ctx: inventory.Ctx, path: str, min_days: int) -> Optional[dict]:
    real = os.path.realpath(path)
    try:
        st = os.lstat(real)
    except OSError:
        return None
    block = blockers(ctx, real)
    readable = not any(b.startswith(("in a cloud", "repo config can run", "its .git is", "git not found")) for b in block)
    sizes = walk_sizes(real) if not any(b.startswith("in a cloud") for b in block) else \
        {"bytes": 0, "node_modules_bytes": 0, "newest": st.st_mtime, "entries": 0, "truncated": True, "unreadable": 0}
    if sizes["truncated"] or sizes["unreadable"]:
        block.append("tree not read to the end: idle time and size not proven")
    git = _git_state(ctx, real) if readable else None
    newest = max(sizes["newest"], (git or {}).get("last_commit_epoch") or 0.0)
    if not newest:  # no file and no commit: nothing says when it was last touched
        newest = st.st_mtime
        block.append("tree holds no file and no commit: idle time not proven")
    live = inventory._live_reasons(ctx, real, newest)
    if live:
        block.append("live: " + ("modified within the last hour" if live[0].startswith("modified") else "a process works inside"))
    idle = inventory._age_days(ctx, newest)
    return {
        "path": real, "inode": st.st_ino, "bytes": sizes["bytes"], "node_modules_bytes": sizes["node_modules_bytes"],
        "copy_bytes": max(0, sizes["bytes"] - sizes["node_modules_bytes"]), "entries": sizes["entries"],
        "newest": newest, "idle_days": idle, "offered": not block and idle >= min_days, "git": git, "blockers": block,
        "cloud": any(b.startswith("in a cloud") for b in block),
        "referenced_by": [], "referenced_by_total": 0,
    }


def _discover(ctx: inventory.Ctx, roots: Sequence[str]) -> Tuple[List[str], bool]:
    home = os.path.realpath(str(ctx.home))
    skip = [os.path.join(home, n) for n in ("Library", ".Trash", "corecleaner-archive")] + [str(common.state_dir())]
    found: List[str] = []
    cut = False
    for root in roots:
        repos, truncated = inventory.find_repos(os.path.realpath(root), DISCOVERY_DEPTH, skip)
        cut = cut or truncated
        found.extend(os.path.realpath(r) for r in repos)
    return sorted(set(found)), cut


def audit(roots: Optional[Sequence[str]] = None, min_days: int = MIN_IDLE_DAYS, ctx: Optional[inventory.Ctx] = None) -> dict:
    ctx = ctx or inventory.default_ctx()
    roots = [str(r) for r in roots] if roots else [str(ctx.home)]
    for r in roots:
        if not os.path.isdir(r):
            raise CorecleanerError(common.EXIT_USAGE, "root is not a directory", root=safety.sanitize_name(r, 200))
    inventory._ps_rows(ctx)
    inventory._cwd_table(ctx)  # filled once, before the worker threads read it
    paths, truncated = _discover(ctx, roots)
    rows = [r for r in inventory._pmap(lambda p: _one(ctx, p, min_days), paths) if r]
    cands = [{"category": "R", "path": r["path"], "virtual": False, "action": "trash",
              "evidence": {"unverified": [], "reason": ""}} for r in rows if not r["cloud"]]
    projects = inventory._known_projects(ctx)
    refs = inventory._apply_refs(ctx, cands, projects, projects) if cands else {"status": "no repos"}
    by_path = {c["path"]: c["evidence"] for c in cands}
    for r in rows:
        ev = by_path.get(r["path"], {})
        r["referenced_by"] = ev.get("referenced_by", [])
        r["referenced_by_total"] = ev.get("referenced_by_total", 0)
        r["references_unverified"] = bool(ev.get("unverified"))
    rows.sort(key=lambda r: (-r["bytes"], r["path"]))
    return {"version": 1, "ts": common.now_iso(), "created_epoch": time.time(), "roots": roots, "min_days": min_days,
            "home": os.path.realpath(str(ctx.home)), "repos": rows, "truncated": truncated,
            "reference_search": refs, "size_method": "allocated blocks (st_blocks), an upper bound",
            "unverified": list(ctx.unverified), "warnings": list(ctx.warnings)}


def _summary_row(r: dict) -> dict:
    git = r.get("git") or {}
    pending = sum(1 for b in git.get("branches", []) if b["pending"] != 0)
    remotes = sorted({"%s/%s" % (t["host"], t["owner"]) for rm in git.get("remotes", []) for t in rm["push"]})
    return {
        "display": views._name(r["path"]), "bytes": r["bytes"], "node_modules_bytes": r["node_modules_bytes"],
        "copy_bytes": r["copy_bytes"], "idle_days": r["idle_days"], "offered": r["offered"],
        "dirty": bool(git.get("dirty")), "stash": git.get("stash", 0), "unpublished_branches": pending,
        "remotes": [safety.sanitize_name(x, 80) for x in remotes[:5]],
        "cited_by": r["referenced_by_total"], "blockers": [safety.sanitize_name(b, 120) for b in r["blockers"]],
    }


def save(result: dict) -> Path:
    body = dict(result)
    body.pop("mac", None)
    body["mac"] = common.sign(body, "repos")
    return views.save_json("repos", "repos", body)


def load(src: str) -> dict:
    """Only the file `repos` saved: in the state dir, ours, private, signed. Never a hand-written list (exit 41)."""
    def reject(why: str) -> CorecleanerError:
        return CorecleanerError(common.EXIT_PLAN_TAMPERED, "repos file rejected: " + why)

    try:
        st = os.lstat(src)
        inside = os.path.dirname(os.path.realpath(src)) == os.path.realpath(str(common.state_subdir("repos")))
        data = json.loads(Path(src).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorecleanerError(common.EXIT_USAGE, "cannot read the repos file: " + type(exc).__name__)
    if not stat.S_ISREG(st.st_mode) or not inside:
        raise reject("not a file saved by `repos` in the state directory")
    if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
        raise reject("file is not private to the current user")
    if not isinstance(data, dict) or not common.verify({k: v for k, v in data.items() if k != "mac"}, data.get("mac"), "repos"):
        raise reject("missing or wrong signature: only `repos` output is accepted")
    if data.get("version") != 1 or not isinstance(data.get("repos"), list):
        raise reject("unsupported shape")
    return data


def run(args: Any) -> dict:
    min_days = getattr(args, "min_days", None)
    min_days = MIN_IDLE_DAYS if min_days is None else int(min_days)
    if min_days < 0:
        raise CorecleanerError(common.EXIT_USAGE, "--min-days must be 0 or more")
    result = audit(getattr(args, "roots", None), min_days)
    saved = save(result)
    rows = result["repos"]
    shown = [r for r in rows if r["offered"]] + [r for r in rows if not r["offered"]][:SUMMARY_ROWS]  # offered first, then biggest
    return {
        "repos_file": str(saved),
        "count": len(rows),
        "offered": sum(1 for r in rows if r["offered"]),
        "total_bytes": sum(r["bytes"] for r in rows),
        "node_modules_bytes": sum(r["node_modules_bytes"] for r in rows),
        "offered_copy_bytes": sum(r["copy_bytes"] for r in rows if r["offered"]),
        "min_days": min_days,
        "truncated": result["truncated"],
        "size_method": result["size_method"],
        "reference_search": {"status": safety.sanitize_name(str(result["reference_search"].get("status", "")), 40)},
        "repos": [_summary_row(r) for r in shown],
        "more": len(rows) - len(shown),
        "note": "Names are sanitized. Next: `migrate-plan --repos <repos_file> --to <external disk folder>`.",
    }
