"""Move big idle repos to an external disk: `migrate-plan` and `migrate`. (M2, M4, M6 of docs/SPEC-migrate.md)

migrate-plan --repos F --to DIR: F must be the signed file `repos` saved. The destination must be mounted on
  another device than HOME, outside HOME, synced folders and the deny list, APFS/HFS+/ext4/NTFS (FAT32 and exFAT
  are refused), writable and local, with free >= bytes x 1.1 + 1 GiB. Group 2 = offered (idle >= min days, no
  blocker, fits, no case collision, its folder on the disk free or a verified copy of this very repo); group 3 =
  shown with the reason. Writes plans/migrate-<ts>.json (hash + HMAC "migrate-plan").
migrate --plan F --ids ... [--apply] [--push-owners a,b]: dry-run by default. With --apply, per id: re-check
  (blockers, inode, newest mtime, live), publish unpublished branches as tags `arquivo-<date>/<branch>` (only to a
  remote whose every push URL has an owner in the list; never `sec/*`, never a branch a note keeps local; checked
  with ls-remote), copy into a staging folder, verify, write the manifest, rename into place, update INDEX.md,
  read the original again and only if it is unchanged send it to the Trash (run manifest: `undo --run R` works).
  Any verification difference deletes only the staging copy this run made; nothing is moved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import archive, common, gitguard, inventory, platform_info, repos, safety, trash, views
from . import migrate_copy as mc
from . import plan as plan_mod
from .common import CorecleanerError

GIB = 1 << 30
SPACE_FACTOR = 1.1
PLAN_VERSION = 1
ALLOWED_FS = {"apfs": "APFS", "hfs": "HFS+", "ext4": "ext4", "ntfs": "NTFS", "ntfs3": "NTFS"}
REFUSED_FS = {"msdos": "FAT32", "vfat": "FAT32", "fat": "FAT32", "fat32": "FAT32", "exfat": "exFAT"}
TAG_PREFIX = "arquivo-"
DEFAULT_HOST = "github.com"
PARTIAL_MARK = ".corecleaner-partial-"
PUSH_TIMEOUT = 600
BATCH = 4
WHERE_CLEAN = "limpo no GitHub"
WHERE_PUSHED = "enviado e conferido"
WHERE_NO_REMOTE = "só no HD (sem remoto)"
WHERE_PENDING = "pendência não enviada: "
NOTE = ("Copies stay on the disk. The Trash frees nothing until you empty it; `undo --run <run_id>` brings an "
        "original back from the Trash, and the copy on the disk stays where it is.")


def _dev_of(path: str) -> int:
    return os.stat(path).st_dev


def _free_bytes(path: str) -> int:
    return shutil.disk_usage(path).free


def _need(nbytes: int) -> int:
    return int(nbytes * SPACE_FACTOR) + GIB


def _bad_dest(why: str) -> CorecleanerError:
    return CorecleanerError(common.EXIT_BAD_DESTINATION, "destination refused: " + why)


def _home() -> str:
    return os.path.realpath(str(Path.home()))


# ---------------------------------------------------------------- destination (trava 1)

def check_destination(dest: str, need_bytes: int = 0) -> Dict[str, Any]:
    if not isinstance(dest, str) or not dest or plan_mod.has_control(dest):
        raise _bad_dest("empty path or control characters")
    dest = os.path.abspath(os.path.expanduser(dest))
    if os.path.islink(dest):
        raise _bad_dest("it is a symlink")
    real = os.path.realpath(dest)
    if os.path.lexists(real) and not os.path.isdir(real):
        raise _bad_dest("it exists and is not a folder")
    anchor = platform_info._existing_ancestor(real)
    home = _home()
    if anchor is None:
        raise _bad_dest("nothing of this path exists (is the disk mounted?)")
    if repos._inside(real, home) or repos._inside(home, real):
        raise _bad_dest("it is inside HOME (or holds it): use a folder on the external disk")
    if _dev_of(anchor) == _dev_of(home):
        raise _bad_dest("same device as HOME: not an external disk (is it mounted?)")
    for p in (real, anchor):
        cloud, _why = safety.is_cloud_or_placeholder(p)
        if cloud:
            raise _bad_dest("inside a cloud-synced folder")
    probe = os.path.join(real, ".corecleaner-probe") if os.path.ismount(real) else real
    protected, _rule = safety.is_protected(probe)
    if protected:
        raise _bad_dest("protected by the deny list")
    vol = platform_info._volume(anchor)
    if not vol:
        raise _bad_dest("the volume cannot be identified")
    fs = str(vol.get("fs") or "").lower()
    kind = platform_info.os_kind()
    if fs in REFUSED_FS:
        raise _bad_dest("%s keeps no symlinks or permissions%s: format the disk as APFS, HFS+, ext4 or NTFS"
                        % (REFUSED_FS[fs], " and caps files at 4 GB" if REFUSED_FS[fs] == "FAT32" else ""))
    if fs not in ALLOWED_FS:
        raise _bad_dest("filesystem %s is not one of APFS, HFS+, ext4, NTFS" % safety.sanitize_name(fs or "unknown", 30))
    if platform_info._is_network(kind, vol.get("fs"), vol.get("opts") or set()):
        raise _bad_dest("network volume")
    if platform_info._is_read_only(kind, vol.get("opts") or set()):
        raise _bad_dest("read-only volume")
    free = _free_bytes(anchor)
    if need_bytes and free < _need(need_bytes):
        raise CorecleanerError(common.EXIT_NO_SPACE_FOR_ARCHIVE, "not enough free space on the destination",
                            free=free, need=_need(need_bytes))
    return {"path": real, "anchor": anchor, "fs": ALLOWED_FS[fs], "free": free, "mount": vol.get("mount"),
            "dev": _dev_of(anchor)}


def rel_of(path: str, home: str) -> str:
    return os.path.relpath(path, home) if repos._inside(path, home) and path != home else os.path.join("_outside", path.lstrip(os.sep))


def _nfc_fold(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def case_collision(dest_root: str, rel: str) -> bool:
    """True when some component of `rel` already exists on the disk with another case (or Unicode form)."""
    cur = dest_root
    for comp in rel.split(os.sep):
        try:
            names = os.listdir(cur)
        except OSError:
            return False
        same = [n for n in names if _nfc_fold(n) == _nfc_fold(comp)]
        if any(n != comp for n in same):
            return True
        if comp not in names:
            return False
        cur = os.path.join(cur, comp)
    return False


def rel_state(dest_root: str, rel: str, origin: str) -> str:
    """"free", "resume" (a verified copy of this very repo is already there) or "taken"."""
    final = os.path.join(dest_root, rel)
    if not os.path.lexists(final):
        return "free"
    man = mc.read_manifest(final) if os.path.isdir(final) and not os.path.islink(final) else None
    if man and man.get("origin") == origin and man.get("status") == "verified":
        return "resume"
    return "taken"


def dest_problem(dest_root: str, dev: int, rel: str) -> Optional[str]:
    """Why the folder for `rel` would not land on the planned disk, or None. Every part of the way that exists must
    be a real folder (never a link: makedirs would follow it off the disk) on the device the plan recorded."""
    try:
        if os.path.realpath(dest_root) != dest_root or _dev_of(dest_root) != dev:
            return "the destination is not the disk in the plan (unmounted, replaced or now a link)"
        cur = dest_root
        for comp in rel.split(os.sep):
            cur = os.path.join(cur, comp)
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or _dev_of(cur) != dev:
                return "a folder on its way on the disk is a link, not a folder, or on another disk"
    except OSError as exc:
        return "the destination cannot be read (%s)" % (exc.strerror or type(exc).__name__)
    return None


def partials(dest_root: str, rel: str) -> int:
    """Staging folders an interrupted run left next to `rel` (never deleted: only the run that made one may)."""
    parent, base = os.path.split(os.path.join(dest_root, rel))
    try:
        return sum(1 for n in os.listdir(parent) if n.startswith(base + PARTIAL_MARK))
    except OSError:
        return 0


# ---------------------------------------------------------------- plan file

def _make_id(path: str) -> str:
    return plan_mod._make_id(path, ())


def _id_ok(item: dict) -> bool:
    digest = hashlib.sha256(item["path"].encode("utf-8", "surrogatepass")).hexdigest()
    return item["id"] == "c" + digest[:6] and item["display"] == safety.sanitize_name(os.path.basename(item["path"]))


def build_plan(audit: dict, dest: str) -> dict:
    d = check_destination(dest)
    home = audit.get("home") or _home()
    items: List[dict] = []
    space_only = 0
    for r in audit["repos"]:
        path = r["path"]
        rel = rel_of(path, home)
        why = list(r.get("blockers") or [])
        if r["idle_days"] < audit["min_days"]:
            why.append("idle %d day(s), under %d" % (r["idle_days"], audit["min_days"]))
        if repos._inside(d["path"], path) or repos._inside(path, d["path"]):
            why.append("the destination overlaps the repo")
        state = "free"
        bad_way = dest_problem(d["path"], d["dev"], rel)
        if not why and bad_way:
            why.append(bad_way)
        if not why:
            if case_collision(d["path"], rel):
                why.append("case collision on the disk: a folder with another case exists")
            else:
                state = rel_state(d["path"], rel, path)
                if state == "taken":
                    why.append("its folder on the disk already exists and is not a verified copy of it")
        if not why and d["free"] < _need(r["copy_bytes"]):
            space_only += 1
            why.append("does not fit on the destination")
        git = r.get("git") or {}
        items.append({
            "id": _make_id(path), "path": path, "display": safety.sanitize_name(os.path.basename(path)), "rel": rel,
            "inode": r["inode"], "mtime": r["newest"], "bytes": r["bytes"], "copy_bytes": r["copy_bytes"],
            "idle_days": r["idle_days"], "group": 3 if why else 2, "deny": "; ".join(why) or None,
            "resume": state == "resume", "cited_by": r.get("referenced_by_total", 0),
            "partials": 0 if bad_way else partials(d["path"], rel),
            "git": {"dirty": bool(git.get("dirty")), "stash": int(git.get("stash") or 0),
                    "remotes": len(git.get("remotes") or []),
                    "unpublished_branches": sum(1 for b in git.get("branches", []) if b["pending"] != 0)},
        })
    if space_only and not any(i["group"] == 2 for i in items):
        smallest = min(i["copy_bytes"] for i in items if i["deny"] and i["deny"].endswith("does not fit on the destination"))
        raise CorecleanerError(common.EXIT_NO_SPACE_FOR_ARCHIVE, "not enough free space on the destination for any idle repo",
                            free=d["free"], need=_need(smallest))
    if len({it["id"] for it in items}) != len(items):
        raise CorecleanerError(common.EXIT_ERROR, "two repos share a plan id; re-run `repos`")
    plan = {"version": PLAN_VERSION, "kind": "migrate", "created": common.now_iso(), "dest": d["path"],
            "dest_fs": d["fs"], "dest_dev": d["dev"], "home": home, "min_days": audit["min_days"], "items": items}
    plan["sha256"] = plan_mod.plan_hash(plan)
    return plan


def write_plan(plan: dict) -> Path:
    signed = {k: v for k, v in plan.items() if k != "mac"}
    signed["mac"] = common.sign(signed, "migrate-plan")
    folder = common.state_subdir("plans")
    data = (json.dumps(signed, ensure_ascii=True, indent=1) + "\n").encode("ascii")
    stamp = common.file_stamp()
    for n in range(100):
        target = folder / ("migrate-%s%s.json" % (stamp, "" if n == 0 else "-%d" % n))
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return target
    raise CorecleanerError(common.EXIT_ERROR, "could not create a unique plan file in the state directory")


def load_plan(f: str) -> dict:
    def bad(why: str) -> CorecleanerError:
        return CorecleanerError(common.EXIT_PLAN_TAMPERED, "plan rejected: " + why)

    try:
        st = os.lstat(f)
        if not stat.S_ISREG(st.st_mode):
            raise bad("not a regular file")
        if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
            raise bad("file is not private to the current user (owner or write bits)")
        data = json.loads(Path(f).read_bytes().decode("utf-8"))
    except CorecleanerError:
        raise
    except (OSError, ValueError):
        raise bad("unreadable or not valid JSON")
    if not isinstance(data, dict) or not hmac.compare_digest(str(data.get("sha256", "")), plan_mod.plan_hash(data)):
        raise bad("hash mismatch (edited after it was written)")
    if not common.verify({k: v for k, v in data.items() if k != "mac"}, data.get("mac"), "migrate-plan"):
        raise bad("not written by this tool (missing or wrong signature)")
    if data.get("version") != PLAN_VERSION or data.get("kind") != "migrate" or not isinstance(data.get("items"), list):
        raise bad("not a migrate plan")
    for it in data["items"]:
        ok = (isinstance(it, dict) and isinstance(it.get("path"), str) and os.path.isabs(it["path"])
              and isinstance(it.get("id"), str) and isinstance(it.get("display"), str) and it.get("group") in (2, 3)
              and isinstance(it.get("rel"), str) and not os.path.isabs(it["rel"]) and ".." not in it["rel"].split(os.sep)
              and isinstance(it.get("inode"), int) and isinstance(it.get("mtime"), (int, float))
              and not (it["group"] == 2 and it.get("deny")))
        if not ok or not _id_ok(it):
            raise bad("malformed item")
    return data


def _question(it: dict, dest_name: str) -> dict:
    g = it["git"]
    facts = ["idle %d days" % it["idle_days"]]
    if not g["remotes"]:
        facts.append("no remote: the disk will be its only copy")
    elif g["unpublished_branches"]:
        facts.append("%d branch(es) on no remote" % g["unpublished_branches"])
    if g["dirty"] or g["stash"]:
        facts.append("uncommitted work or stash (kept in the copy only)")
    if it.get("cited_by"):
        facts.append("cited by %d file(s): moving it breaks them" % it["cited_by"])
    if it["bytes"] > it["copy_bytes"]:
        facts.append("node_modules left out (%s; reinstall it from the lockfile)" % archive._human(it["bytes"] - it["copy_bytes"]))
    if it.get("resume"):
        facts.append("a verified copy is already on the disk")
    if it.get("partials"):
        facts.append("%d partial copy folder(s) from an interrupted run are on the disk (not deleted)" % it["partials"])
    return {"id": it["id"], "question": "Move %s, in %s (%s, %s), to %s?" % (
        it["display"], views._name(os.path.dirname(it["path"])), archive._human(it["copy_bytes"]), "; ".join(facts), dest_name),
        "options": [{"label": "Keep it here", "ids": []}, {"label": "Move it to the disk", "ids": [it["id"]]}]}


def plan_view(plan: dict, target: Path) -> dict:
    dest_name = views._name(plan["dest"])
    rows = [{"id": it["id"], "group": it["group"], "display": it["display"], "path_display": views._name(it["path"]),
             "rel": safety.sanitize_name(it["rel"], 160), "bytes": it["bytes"], "copy_bytes": it["copy_bytes"],
             "idle_days": it["idle_days"], "deny": safety.sanitize_name(it["deny"], 300) if it["deny"] else None,
             "resume": it["resume"], "partials": it.get("partials", 0), "git": it["git"], "cited_by": it["cited_by"]}
            for it in plan["items"]]
    offered = sorted((it for it in plan["items"] if it["group"] == 2), key=lambda i: -i["copy_bytes"])
    qs = [_question(it, dest_name) for it in offered]
    return {"plan_file": str(target), "dest": dest_name, "dest_fs": plan["dest_fs"], "sha256": plan["sha256"],
            "offered": len(offered), "offered_copy_bytes": sum(i["copy_bytes"] for i in offered),
            "items": rows, "batches": [qs[i:i + BATCH] for i in range(0, len(qs), BATCH)],
            "note": "Ask in these batches; build --ids only from explicit 'Move' answers. Push needs --push-owners."}


# ---------------------------------------------------------------- publication (trava 6)

def _g(repo: str, *args: str, timeout: int = 120) -> Tuple[int, str]:
    try:
        proc = archive._git(repo, *args, check=False, timeout=timeout)
    except CorecleanerError:
        return 127, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")  # stderr is dropped: it never reaches the agent


def _ssh_args(repo: str) -> List[str]:
    if os.environ.get("GIT_SSH_COMMAND") or os.environ.get("GIT_SSH"):
        return []
    rc, out = _g(repo, "config", "--get", "core.sshCommand")  # the repo's own is refused before: this one is the user's
    return ["-c", "protocol.ext.allow=never"] + ([] if rc == 0 and out.strip() else ["-c", "core.sshCommand=ssh -o BatchMode=yes"])


def pending_work(repo: str) -> Dict[str, Any]:
    run = lambda *a: _g(repo, *a)  # noqa: E731
    rc, status = run("status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none")
    rc_s, _ = run("rev-parse", "--verify", "-q", "refs/stash")
    rc_t, tags = run("rev-list", "--count", "--tags", "--not", "--branches", "--remotes")
    rc_h, sym = run("symbolic-ref", "-q", "HEAD")
    rc_d, det = run("rev-list", "--count", "HEAD", "--not", "--branches", "--remotes") if rc_h != 0 else (0, "0")
    branches = repos.branches_of(run)
    return {"branches": branches, "remotes": repos.remotes_of(run),
            "never": repos.never_push(repo, [b["name"] for b in branches], run, [b["sha"] for b in branches if b["pending"] != 0]),
            "unsafe": gitguard.unsafe_config(run, repo, push=True),
            "dirty": rc != 0 or bool(status.strip()), "stash": rc_s == 0,
            "tag_only": rc_t != 0 or (tags.strip() not in ("", "0")),
            "detached": rc_d != 0 or (det.strip() not in ("", "0"))}


def parse_owners(value: Any) -> frozenset:
    """--push-owners: "owner" means github.com/owner; "host/owner" names another host ("local/x" = a local path)."""
    items = value.split(",") if isinstance(value, str) else list(value or ())
    out = set()
    for o in (str(x).strip().casefold() for x in items):
        if o:
            out.add(o if "/" in o else DEFAULT_HOST + "/" + o)
    return frozenset(out)


def _target_ok(t: dict, owners: frozenset) -> bool:
    if not t["host"] or not t["owner"] or ("%s/%s" % (t["host"], t["owner"])).casefold() not in owners:
        return False
    return t["host"] == "local" or t.get("depth") == 2  # exactly owner/repo: no subgroup, no path tricks


def _allowed(remote: dict, owners: frozenset) -> bool:
    return bool(owners) and not remote["mirror"] and bool(remote["push"]) and all(_target_ok(t, owners) for t in remote["push"])


def _pick_remote(branch: dict, remotes: List[dict], owners: frozenset) -> Optional[dict]:
    ok = [r for r in remotes if _allowed(r, owners)]
    for name in (branch.get("upstream_remote"), "origin"):
        for r in ok:
            if r["name"] == name:
                return r
    return sorted(ok, key=lambda r: r["name"])[0] if ok else None


def publish(repo: str, owners: frozenset, date: str, apply: bool) -> Dict[str, Any]:
    """Tags for every branch on no remote, where the rules allow; returns {pushed, pending, where}."""
    owners = parse_owners(owners)
    w = pending_work(repo)
    pushed: List[dict] = []
    pending: List[str] = []
    if w["dirty"]:
        pending.append("alterações não commitadas (só na cópia)")
    if w["stash"]:
        pending.append("stash (só na cópia)")
    if w["tag_only"]:
        pending.append("commits só em tags locais")
    if w["detached"]:
        pending.append("commits só no HEAD solto")
    def local_only(b: dict) -> bool:
        return b["name"].lower().startswith("sec/") or w["never"]["all"] or b["name"] in w["never"]["branches"]

    held = [b for b in w["branches"] if b["pending"] != 0 and local_only(b)]

    def carries_held(b: dict) -> bool:
        """A branch that holds unpublished commits of a sec/* or noted branch would push them under another name."""
        for h in held:
            if h["name"] == b["name"]:
                continue
            rc, out = _g(repo, "rev-list", "--count", h["sha"], "--not", "--remotes", b["sha"])
            if rc != 0 or not out.strip().isdigit() or int(out.strip()) < h["pending"]:
                return True
        return False

    for b in w["branches"]:
        if b["pending"] == 0:
            continue
        name = b["name"]
        label = "branch " + safety.sanitize_name(name, 80)
        if not w["remotes"]:
            continue  # said once below: no remote at all
        if name.lower().startswith("sec/"):
            pending.append(label + ": sec/* nunca sobe")
            continue
        if w["never"]["all"] or name in w["never"]["branches"]:
            pending.append(label + ": nota diz que não sobe")
            continue
        if carries_held(b):
            pending.append(label + ": leva commits de uma branch que não sobe")
            continue
        if w["unsafe"]:
            pending.append(label + ": config do repo roda programa no push")
            continue
        if not owners:
            pending.append(label + ": sem lista --push-owners")
            continue
        remote = _pick_remote(b, w["remotes"], owners)
        if remote is None:
            pending.append(label + ": dono do remoto fora da lista")
            continue
        tag = "%s%s/%s" % (TAG_PREFIX, date, name)
        if _g(repo, "check-ref-format", "refs/tags/" + tag)[0] != 0:
            pending.append(label + ": nome de tag inválido")
            continue
        row = {"branch": safety.sanitize_name(name, 120), "tag": safety.sanitize_name(tag, 160), "remote": remote["name"],
               "owner": safety.sanitize_name(remote["push"][0]["owner"], 60), "verified": False}
        if not apply:
            pushed.append(row)
            continue
        rc, _ = _g(repo, *_ssh_args(repo), "-c", "push.followTags=false", "-c", "gc.auto=0", "push", "--no-verify",
                   "--recurse-submodules=no", "--no-follow-tags", remote["name"],
                   "refs/heads/%s:refs/tags/%s" % (name, tag), timeout=PUSH_TIMEOUT)
        ok = rc == 0
        for target in remote["push"] if ok else []:
            rc2, out = _g(repo, *_ssh_args(repo), "ls-remote", target["url"], "refs/tags/" + tag, timeout=PUSH_TIMEOUT)
            ok = ok and rc2 == 0 and any(ln.split("\t")[0] == b["sha"] for ln in out.splitlines())
        row["verified"] = ok
        pushed.append(row)
        if not ok:
            pending.append(label + ": push falhou ou não conferiu")
    if not w["remotes"]:
        where = WHERE_NO_REMOTE
    elif pending:
        where = WHERE_PENDING + "; ".join(pending)
    elif pushed:
        where = WHERE_PUSHED
    else:
        hosts = {t["host"] for r in w["remotes"] for t in r["push"]}
        where = WHERE_CLEAN if hosts == {"github.com"} else "limpo no remoto"
    return {"pushed": pushed, "pending": pending, "where": where}


# ---------------------------------------------------------------- apply (travas 2-5 again, then 3-5, then Trash)

def _recheck(item: dict, ctx: inventory.Ctx) -> Tuple[Optional[str], Optional[int], float]:
    """(reason, exit code, newest mtime) of the first thing that changed since the plan, or (None, None, newest)."""
    path = item["path"]
    why = trash._recheck({"path": path, "inode": item["inode"], "mtime": None})
    if why:
        return why, common.EXIT_STATE_CHANGED, 0.0
    block = repos.blockers(ctx, path)
    if block:
        return block[0], common.EXIT_DENYLISTED, 0.0
    sizes = repos.walk_sizes(path)
    if sizes["truncated"] or sizes["unreadable"]:
        return "could not read the whole tree: idle not proven", common.EXIT_LIVE_PROCESS, 0.0
    if sizes["newest"] > item["mtime"] + plan_mod.MTIME_EPS:
        return "modified since the plan", common.EXIT_STATE_CHANGED, 0.0
    live = trash._live_reason(path, newest=sizes["newest"])
    if live:
        return live, common.EXIT_LIVE_PROCESS, 0.0
    return None, None, sizes["newest"]


def _row(item: dict, status: str, reason: str, code: Optional[int] = None, **extra: Any) -> dict:
    out = {"id": item["id"], "display": item["display"], "status": status, "reason": reason,
           "bytes": item["bytes"], "copy_bytes": item["copy_bytes"], "rel": safety.sanitize_name(item["rel"], 160)}
    if code is not None:
        out["code"] = code
    out.update(extra)
    return out


def _copy_and_verify(plan: dict, item: dict, final: str, run_id: str) -> Tuple[Optional[str], Dict[str, Any], str]:
    """(problem, facts, folder holding the verified copy). A failed copy of this run is deleted; nothing else is."""
    path, dest_root = item["path"], plan["dest"]
    if item.get("resume"):
        problem, facts = mc.verify(path, final)
        return (("the copy already on the disk differs from the original; left as is: " + problem) if problem else None), facts, final
    try:
        os.makedirs(os.path.dirname(final), exist_ok=True)
    except OSError as exc:
        return "cannot create its folder on the disk (%s): nothing copied" % (exc.strerror or type(exc).__name__), {}, ""
    bad_way = dest_problem(dest_root, plan["dest_dev"], item["rel"])  # makedirs may have raced a link in
    if bad_way:
        return bad_way + ": nothing copied", {}, ""
    staging = "%s%s%s" % (final, PARTIAL_MARK, run_id)
    if os.path.lexists(staging):  # only a folder this run creates may ever be deleted below
        return "a staging folder with this run's name already exists on the disk: nothing done", {}, ""
    try:
        copied = mc.copy_tree(path, staging)
    except OSError as exc:
        if os.path.lexists(staging):
            mc.remove_partial(staging, dest_root)
        return "copy failed (%s): nothing moved, the partial copy was deleted" % (exc.strerror or type(exc).__name__), {}, ""
    problem, facts = mc.verify(path, staging)
    if problem:
        mc.remove_partial(staging, dest_root)
        return problem + ": nothing moved, the partial copy was deleted", {}, ""
    facts["specials"] = copied["specials"]
    return None, facts, staging


def _manifest(item: dict, facts: dict, pub: dict, run_id: str, date: str, status: str) -> dict:
    return {"corecleaner": common.VERSION, "origin": item["path"], "rel": item["rel"], "date": date, "run_id": run_id,
            "files": facts.get("files", 0), "bytes": facts.get("bytes", 0), "entries": facts.get("entries", 0),
            "merkle_sha256": facts.get("merkle"), "specials_not_copied": facts.get("specials", []),
            "tags": [p for p in pub["pushed"] if p["verified"]], "where": pub["where"], "status": status,
            "excluded": sorted(mc.SKIP_NAMES)}


def _origin_label(item: dict, home: str) -> str:
    p = item["path"]
    return "~/" + os.path.relpath(p, home).replace(os.sep, "/") if repos._inside(p, home) and p != home else p


def _apply_item(plan: dict, item: dict, run_id: str, owners: frozenset, trasher: Callable[[str], str],
                ctx: inventory.Ctx, date: str) -> Tuple[dict, Optional[Tuple[int, str]]]:
    dest_root = plan["dest"]
    final = os.path.join(dest_root, item["rel"])
    bad_way = dest_problem(dest_root, plan["dest_dev"], item["rel"])
    if bad_way:
        return _row(item, "deny", bad_way, common.EXIT_BAD_DESTINATION), (common.EXIT_BAD_DESTINATION, bad_way)
    if not item.get("resume") and (os.path.lexists(final) or case_collision(dest_root, item["rel"])):
        return _row(item, "deny", "its folder on the disk appeared since the plan", common.EXIT_STATE_CHANGED), None
    pub = publish(item["path"], owners, date, apply=True)
    bad_way = dest_problem(dest_root, plan["dest_dev"], item["rel"])
    if bad_way:
        return (_row(item, "deny", bad_way, common.EXIT_BAD_DESTINATION, where=pub["where"], tags=pub["pushed"]),
                (common.EXIT_BAD_DESTINATION, bad_way))
    try:
        before = mc.fingerprint(item["path"])
    except OSError:
        return _row(item, "failed", "the original could not be read to the end: nothing copied", common.EXIT_STATE_CHANGED,
                    where=pub["where"], tags=pub["pushed"]), None
    problem, facts, folder = _copy_and_verify(plan, item, final, run_id)
    if problem:
        return _row(item, "failed", problem, common.EXIT_STATE_CHANGED, where=pub["where"], tags=pub["pushed"]), None
    row = lambda where: mc.index_row(item["rel"], facts.get("bytes", 0), _origin_label(item, plan["home"]), where, date,  # noqa: E731
                                     (item["rel"].replace(os.sep, "/") + "/" + mc.MANIFEST_NAME))

    def stale() -> dict:
        mc.write_manifest(final, _manifest(item, facts, pub, run_id, date, "stale"))
        mc.merge_index(dest_root, item["rel"], row("cópia desatualizada: o original mudou e ficou no Mac"))
        return _row(item, "copied", "the original changed after the copy: it stays here, the copy is marked stale",
                    common.EXIT_STATE_CHANGED, where=pub["where"], tags=pub["pushed"])

    try:
        mc.write_manifest(folder, _manifest(item, facts, pub, run_id, date, "verified"))
        if folder != final:
            trash._rename_noreplace(folder, final)
        try:
            after: Optional[Dict[str, Any]] = mc.fingerprint(item["path"])
        except OSError:
            after = None
        if after != before:
            return stale(), None
        mc.merge_index(dest_root, item["rel"], row(pub["where"]))
    except (OSError, CorecleanerError) as exc:  # the verified copy stays (in staging or in place); the original is kept
        why = exc.message if isinstance(exc, CorecleanerError) else (exc.strerror or type(exc).__name__)
        return _row(item, "copied", "verified copy kept, but writing its manifest, folder or INDEX.md failed (%s): "
                    "original kept" % trash._clean(why, 120), common.EXIT_ERROR, where=pub["where"]), None
    newest = max((e[2] for e in after.values()), default=0) / 1e9 if after else 0.0
    live = trash._live_reason(item["path"], newest=newest)
    available, tool = platform_info.trash_available(item["path"])
    if live or not available:
        why = live or ("no Trash for this volume: " + trash._clean(tool))
        stop = (common.EXIT_NO_TRASH, why) if not available else None
        return _row(item, "copied", "copied and verified, original kept: " + why, where=pub["where"], tags=pub["pushed"]), stop
    bad_way = dest_problem(dest_root, plan["dest_dev"], item["rel"])
    if bad_way:
        return (_row(item, "copied", "copied and verified, original kept: " + bad_way, common.EXIT_BAD_DESTINATION,
                     where=pub["where"], tags=pub["pushed"]), (common.EXIT_BAD_DESTINATION, bad_way))
    ident = trash._identity(item["path"])
    entry = {"id": item["id"], "src": item["path"], "bytes": item["bytes"], "copy": final, **ident}
    trash.write_manifest(run_id, dict(entry, phase="intent"))
    try:
        last: Optional[Dict[str, Any]] = mc.fingerprint(item["path"])  # the last look, right before the move
    except OSError:
        last = None
    if last != before:
        trash.write_manifest(run_id, dict(entry, phase="fail", error="the original changed right before the Trash"))
        try:
            return stale(), None
        except (OSError, CorecleanerError):
            return _row(item, "copied", "the original changed after the copy: it stays here", common.EXIT_STATE_CHANGED,
                        where=pub["where"], tags=pub["pushed"]), None
    try:
        moved = trasher(item["path"])
    except trash.DestinationUnknown as exc:
        trash.write_manifest(run_id, dict(entry, phase="done", error="destination unknown: " + exc.message))
        return _row(item, "ok", "copied, verified and moved to the Trash, but its place there is unknown: undo cannot "
                    "restore it", where=pub["where"], tags=pub["pushed"]), (exc.code, exc.message)
    except Exception as exc:  # any surprise: record it and stop the batch, never retry blindly
        msg = exc.message if isinstance(exc, CorecleanerError) else "%s: %s" % (type(exc).__name__, trash._clean(exc, 160))
        code = exc.code if isinstance(exc, CorecleanerError) else common.EXIT_ERROR
        trash.write_manifest(run_id, dict(entry, phase="fail", error=msg))
        return _row(item, "copied", "copied and verified; the Trash failed, original kept: " + trash._clean(msg),
                    code, where=pub["where"]), (code, msg)
    trash.write_manifest(run_id, dict(entry, phase="done", dest=moved))
    return _row(item, "ok", "copied, verified and moved to the Trash", where=pub["where"], tags=pub["pushed"]), None


def _dry_item(item: dict, owners: frozenset, date: str, dest: str) -> dict:
    pub = publish(item["path"], owners, date, apply=False)
    copy_to = views._name(os.path.join(dest, item["rel"]))
    what = "would copy %s to %s" % (archive._human(item["copy_bytes"]), copy_to)
    if item.get("resume"):
        what = "would re-verify the copy already on the disk"
    if pub["pushed"]:
        what += "; would push %d tag(s)" % len(pub["pushed"])
    return _row(item, "ok", what + ", then move the original to the Trash", where=pub["where"], tags=pub["pushed"],
                copy_to=copy_to)


def _run_migrate(args: Any, trasher: Callable[[str], str]) -> dict:
    apply = bool(getattr(args, "apply", False))
    warnings = common.apply_guard(apply)
    plan = load_plan(args.plan)
    by_id = {it["id"]: it for it in plan["items"]}
    wanted = list(dict.fromkeys(str(i) for i in (args.ids or [])))
    if not wanted:
        raise CorecleanerError(common.EXIT_USAGE, "no ids given")
    unknown = [i for i in wanted if i not in by_id]
    if unknown:
        raise CorecleanerError(common.EXIT_USAGE, "ids must come from the plan", unknown=[trash._clean(i, 40) for i in unknown[:20]])
    owners = parse_owners(getattr(args, "push_owners", None) or "")
    chosen = [by_id[i] for i in wanted]
    d = check_destination(plan["dest"], sum(i["copy_bytes"] for i in chosen if i["group"] == 2 and not i.get("resume")))
    if d["dev"] != plan["dest_dev"]:
        raise _bad_dest("another disk is mounted at this path than when the plan was made")
    ctx = inventory.default_ctx()
    date = time.strftime("%Y-%m-%d")
    run_id = "%s-%s" % (common.file_stamp(), os.urandom(2).hex()) if apply else None
    items: List[dict] = []
    stop: Optional[Tuple[int, str]] = None
    for item in chosen:
        if stop:
            items.append(_row(item, "skipped", "batch stopped after the first failure"))
            continue
        if item["group"] != 2:
            items.append(_row(item, "deny", "not offered: " + (item.get("deny") or "group 3"), common.EXIT_DENYLISTED))
            continue
        why, code, _newest = _recheck(item, ctx)
        if why:
            items.append(_row(item, "deny", trash._clean(why), code))
            continue
        if not apply:
            items.append(_dry_item(item, owners, date, plan["dest"]))
            continue
        try:
            res, stop = _apply_item(plan, item, run_id or "", owners, trasher, ctx, date)
        except Exception as exc:  # a surprise stops the batch but keeps the run_id and the rows already done
            msg = exc.message if isinstance(exc, CorecleanerError) else "%s: %s" % (type(exc).__name__, trash._clean(exc, 160))
            res, stop = _row(item, "failed", "unexpected error: " + trash._clean(msg), common.EXIT_ERROR), (common.EXIT_ERROR, msg)
        items.append(res)
    result = {"run_id": run_id, "apply": apply, "dest": views._name(plan["dest"]), "items": items,
              "moved_bytes": sum(r["bytes"] for r in items if apply and r["status"] == "ok"),
              "copied_bytes": sum(r["copy_bytes"] for r in items if apply and r["status"] in ("ok", "copied")),
              "push_owners": sorted(owners), "note": NOTE}
    if warnings:
        result["warnings"] = warnings
    if stop:
        raise CorecleanerError(stop[0], "batch stopped: " + trash._clean(stop[1]), **result)
    return result


def run(args: Any, trasher: Optional[Callable[[str], str]] = None) -> dict:
    cmd = getattr(args, "cmd", None)
    if cmd == "migrate-plan":
        plan = build_plan(repos.load(args.repos), args.to)
        return plan_view(plan, write_plan(plan))
    if cmd == "migrate":
        return _run_migrate(args, trasher or trash.send_to_trash)
    raise CorecleanerError(common.EXIT_USAGE, "migrate module serves only 'migrate-plan' and 'migrate'")
