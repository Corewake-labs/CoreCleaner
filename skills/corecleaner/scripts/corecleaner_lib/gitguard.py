"""Repo-local git config that makes git run a program. (shared by inventory.py and archive.py)

`git status` runs a clean filter, `git log` runs `gpg.program` when `log.showSignature` is on, and
`git diff` runs diff drivers. All of them come from the repo's own `.git/config`, which anything that
wrote into the repo (an unpacked tarball, an agent) controls. Reading a repo must never run its code,
so both modules ask `unsafe_config` first and, on any answer, skip every command that reads content.

Only the repo's own scopes count (local, worktree, and what they include). The user's global and
system config is theirs: git-lfs and delta live there.
"""

from __future__ import annotations

import os
import re
from typing import Callable, Iterator, List, Optional, Tuple

# run_git(*git_args) -> (returncode, stdout text); the caller picks the repo and the process runner.
RunGit = Callable[..., Tuple[int, str]]

_KINDS = (
    ("filter driver", re.compile(r"^filter\..+\.(?:clean|smudge|process)$", re.I)),
    ("gpg program", re.compile(r"^gpg\.(?:(?:openpgp|x509|ssh)\.)?program$", re.I)),
    ("diff driver", re.compile(r"^diff\.(?:external|.+\.(?:command|textconv))$", re.I)),
    ("merge driver", re.compile(r"^merge\..+\.driver$", re.I)),
)
# Run only by a push or ls-remote; reading the repo stays allowed, publishing from it does not.
_PUSH_KINDS = (
    ("credential helper", re.compile(r"^credential\.(?:.+\.)?helper$", re.I)),
    ("ssh command", re.compile(r"^core\.(?:sshcommand|askpass|gitproxy)$", re.I)),
    ("protocol allow", re.compile(r"^protocol\.(?:.+\.)?allow$", re.I)),
    ("remote program", re.compile(r"^remote\..+\.(?:receivepack|uploadpack|vcs)$", re.I)),
)
# The standard git-lfs wiring only runs git-lfs; anything else under filter.lfs.* is not that.
_LFS = {
    "filter.lfs.clean": "git-lfs clean -- %f",
    "filter.lfs.smudge": "git-lfs smudge -- %f",
    "filter.lfs.process": "git-lfs filter-process",
}
_MAX_MODULE_CONFIGS = 64
UNREADABLE = "git config could not be read in full (treated as unsafe)"
CONDITIONAL = "conditional include in a submodule config (not evaluated here, treated as unsafe)"


def _has_conditional_include(cfg: str) -> bool:
    """`includeIf "gitdir:..."` is judged from the submodule's own cwd, which `--file` cannot reproduce."""
    try:
        with open(cfg, "rb") as fh:
            text = fh.read(1 << 20)
    except OSError:
        return True
    return re.search(rb"^\s*\[\s*includeIf\b", text, re.I | re.M) is not None


def _scoped(out: str) -> Iterator[Tuple[str, str, str]]:
    """(scope, key, value) from `config --list --show-scope -z`: `scope NUL key NL value NUL` repeated."""
    parts = out.split("\0")
    for i in range(0, len(parts) - 1, 2):
        key, _, value = parts[i + 1].partition("\n")
        yield parts[i], key, value


def _unscoped(out: str) -> Iterator[Tuple[str, str, str]]:
    for part in out.split("\0"):
        if part:
            key, _, value = part.partition("\n")
            yield "local", key, value


def _kinds(entries: Iterator[Tuple[str, str, str]], kinds: tuple = _KINDS) -> List[str]:
    found: List[str] = []
    for scope, key, value in entries:
        if scope not in ("local", "worktree"):
            continue
        if _LFS.get(key.lower()) == value.strip():
            continue
        for label, pattern in kinds:
            if pattern.match(key) and label not in found:
                found.append(label)
    return found


def _module_configs(common_dir: str) -> List[str]:
    base = os.path.join(common_dir, "modules")
    found: List[str] = []
    for cur, dirs, files in os.walk(base, followlinks=False):
        if "config" in files and "HEAD" in files:
            found.append(os.path.join(cur, "config"))
            if len(found) >= _MAX_MODULE_CONFIGS:
                break
    return found


def _gitdir(dotgit: str) -> Optional[str]:
    """The folder a submodule's `.git` stands for: itself, or the `gitdir:` its file names. None = unusable."""
    if os.path.islink(dotgit):
        return None
    if os.path.isdir(dotgit):
        return dotgit
    try:
        with open(dotgit, "rb") as fh:
            m = re.match(r"gitdir:\s*(.+)", fh.read(4096).decode("utf-8", "replace"))
    except OSError:
        return None
    gd = m.group(1).strip() if m else ""
    return os.path.normpath(os.path.join(os.path.dirname(dotgit), gd)) if gd else None


def _submodule_configs(run_git: RunGit, repo_root: str) -> Tuple[List[str], bool]:
    """Config files of every populated submodule, nested ones too, found by .gitmodules paths and gitlinks.

    `git status --ignore-submodules=none` runs git inside each of them, under that submodule's own config.
    Second value True = something could not be read (the caller fails closed)."""
    found: List[str] = []
    bad = False
    stack = [repo_root]
    while stack and len(found) < _MAX_MODULE_CONFIGS:
        top = stack.pop()
        paths = set()
        gm = os.path.join(top, ".gitmodules")
        if os.path.lexists(gm):
            rc, out = run_git("config", "--file", gm, "--get-regexp", r"^submodule\..*\.path$")
            bad = bad or rc not in (0, 1)
            paths.update(ln.partition(" ")[2].strip() for ln in out.splitlines())
        rc, out = run_git("-C", top, "ls-files", "--stage", "-z")
        if rc != 0:
            bad = True
            continue
        paths.update(ent.partition("\t")[2] for ent in out.split("\0") if ent.startswith("160000 "))
        for rel in sorted(p for p in paths if p):
            sub = os.path.normpath(os.path.join(top, rel))
            if not sub.startswith(top.rstrip(os.sep) + os.sep):
                bad = True
                continue
            dotgit = os.path.join(sub, ".git")
            if not os.path.lexists(dotgit):
                continue  # not checked out: git does not enter it
            gd = _gitdir(dotgit)
            if gd is None:
                bad = True
                continue
            cfg = os.path.join(gd, "config")
            if cfg not in found and os.path.lexists(cfg):
                found.append(cfg)
            stack.append(sub)
    return found, bad


def unsafe_config(run_git: RunGit, repo_root: str, push: bool = False) -> List[str]:
    """Kinds of program-running settings in the repo's own config ([] = none; fixed labels, never key names).

    A config git cannot read at all also answers non-empty: the caller must not assume it is clean.
    push=True adds what only a push or ls-remote runs (credential helper, ssh command, protocol, remote programs).
    """
    kinds = _KINDS + _PUSH_KINDS if push else _KINDS
    rc, out = run_git("config", "--list", "--show-scope", "-z", "--includes")
    if rc != 0:
        return [UNREADABLE]
    found = _kinds(_scoped(out), kinds)
    cfgs: List[str] = []
    if os.path.exists(os.path.join(repo_root, ".gitmodules")):
        rc, common = run_git("rev-parse", "--git-common-dir")
        if rc != 0 or not common.strip():
            return found + ([UNREADABLE] if UNREADABLE not in found else [])
        cfgs = _module_configs(os.path.normpath(os.path.join(repo_root, common.strip())))
    subs, bad = _submodule_configs(run_git, repo_root)
    if bad and UNREADABLE not in found:
        found.append(UNREADABLE)
    for cfg in cfgs + [c for c in subs if c not in cfgs]:
        if _has_conditional_include(cfg):
            if CONDITIONAL not in found:
                found.append(CONDITIONAL)
            continue
        rc, out = run_git("config", "--file", cfg, "--list", "-z", "--includes")
        if rc != 0:
            if UNREADABLE not in found:
                found.append(UNREADABLE)
            continue
        found.extend(k for k in _kinds(_unscoped(out), kinds) if k not in found)
    return found
