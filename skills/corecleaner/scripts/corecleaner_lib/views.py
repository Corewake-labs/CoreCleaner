"""Agent-safe views of `scan` and `inventory` (SPEC trava 9).

Both commands collect raw file names, and a file name is attacker-controlled text. The full result is
saved to a private file in the state dir (it feeds `report --scan` and `plan --candidates`); stdout
carries only numbers, categories and sanitized, truncated names. `--raw` prints the full result, for a
human at a terminal, never for an agent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from . import common, safety
from .common import CorecleanerError

SCAN_TOP = 20
SCAN_ERRORS = 5
SCAN_HOLDS = 10
NAME_MAX = 120


def save_json(subdir: str, prefix: str, obj: Any) -> Path:
    """<state>/<subdir>/<prefix>-<stamp>.json, exclusive create, mode 0o600, ASCII so odd names survive."""
    folder = common.state_subdir(subdir)
    data = (json.dumps(obj, ensure_ascii=True, default=common._json_default) + "\n").encode("ascii")
    stamp = common.file_stamp()
    for n in range(100):
        target = folder / ("%s-%s%s.json" % (prefix, stamp, "" if n == 0 else "-%d" % n))
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return target
    raise CorecleanerError(common.EXIT_ERROR, "could not create a unique file in the state directory", dir=str(folder))


def _name(value: Any, maxlen: int = NAME_MAX) -> str:
    text = str(value)
    try:
        home = str(Path.home())
        if text == home or text.startswith(home + os.sep):
            text = "~" + text[len(home):]
    except RuntimeError:
        pass
    return safety.sanitize_name(text, maxlen)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _issue(item: Any, key: str) -> str:
    """One line for an error or warning entry: "<path>: <message>" (a plain string passes through)."""
    if isinstance(item, dict):
        return _name("%s: %s" % (item.get("path", ""), item.get(key, "")), 160)
    return _name(item, 160)


def _items(value: Any) -> List[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def scan_view(scan: Dict[str, Any], saved: Path) -> Dict[str, Any]:
    gap = scan.get("gap") if isinstance(scan.get("gap"), dict) else {}
    top: List[dict] = []
    for node in (scan.get("top") if isinstance(scan.get("top"), list) else [])[:SCAN_TOP]:
        if isinstance(node, dict):
            top.append({"path": _name(node.get("path", "")), "bytes": _int(node.get("bytes")), "kind": node.get("kind")})
    errors = scan.get("errors") if isinstance(scan.get("errors"), list) else []
    warnings = scan.get("warnings") if isinstance(scan.get("warnings"), list) else []
    snaps = scan.get("snapshots") if isinstance(scan.get("snapshots"), dict) else {}
    holds = [
        {
            "kind": _name(h.get("kind", ""), 20),
            "bytes": h.get("bytes") if isinstance(h.get("bytes"), int) and not isinstance(h.get("bytes"), bool) else None,
            "in_gap": bool(h.get("in_gap")),
            "note": _name(h.get("note", ""), 200),
        }
        for h in _items(scan.get("system_holds"))[:SCAN_HOLDS]
    ]
    return {
        "scan_file": str(saved),
        "tool": scan.get("tool"),
        "exact": scan.get("exact"),
        "complete": scan.get("complete"),
        "label": _name(scan.get("label", ""), 200),
        "fallback": scan.get("fallback"),
        "ts": scan.get("ts"),
        "roots": [_name(r) for r in (scan.get("roots") if isinstance(scan.get("roots"), list) else [])],
        "dropped_roots": [_name(r) for r in (scan.get("dropped_roots") if isinstance(scan.get("dropped_roots"), list) else [])],
        "unmeasured_roots": [_name(r) for r in (scan.get("unmeasured_roots") if isinstance(scan.get("unmeasured_roots"), list) else [])],
        "read_bytes": _int(scan.get("read_bytes")),
        "gap": {
            "label": _name(gap.get("label", ""), 40),
            "partial": bool(gap.get("partial")),
            "unexplained_bytes": _int(gap.get("unexplained_bytes")),
            "raw_unexplained_bytes": _int(gap.get("raw_unexplained_bytes")),
            "outside_roots_bytes": _int(gap.get("outside_roots_bytes")),
            "outside_roots_complete": bool(gap.get("outside_roots_complete")),
            "outside_roots": [
                {"path": _name(e.get("path") or "", 80), "bytes": _int(e.get("bytes")), "complete": bool(e.get("complete"))}
                for e in _items(gap.get("outside_roots"))[:SCAN_HOLDS]
            ],
            "other_volumes": [
                {"mount": _name(e.get("mount") or "", 80), "fs": _name(e.get("fs") or "", 20)}
                for e in _items(gap.get("other_volumes"))[:SCAN_HOLDS]
            ],
            "outside_roots_notes": [_name(n, 160) for n in (gap.get("outside_roots_notes") if isinstance(gap.get("outside_roots_notes"), list) else [])[:3]],
            "used_bytes": _int(gap.get("used_bytes")),
            "explained_by": [
                {"kind": _name(e.get("kind", ""), 20), "bytes": _int(e.get("bytes"))} for e in _items(gap.get("explained_by"))[:SCAN_HOLDS]
            ],
            "held_elsewhere": [
                {"kind": _name(e.get("kind", ""), 20), "bytes": _int(e.get("bytes")), "path": _name(e.get("path") or "", 80)}
                for e in _items(gap.get("held_elsewhere"))[:SCAN_HOLDS]
            ],
            "note": _name(gap.get("note", ""), 600),
        },
        "system_holds": holds,
        "top": top,
        "errors": {
            "count": _int(scan.get("errors_total")) or len(errors),
            "first": [_issue(e, "error") for e in errors[:SCAN_ERRORS]],
        },
        "warnings": {
            "count": _int(scan.get("warnings_total")) or len(warnings),
            "first": [_issue(w, "warning") for w in warnings[:SCAN_ERRORS]],
        },
        "unreadable_entries": _int(scan.get("unreadable_entries")),
        "seconds": scan.get("seconds") if isinstance(scan.get("seconds"), (int, float)) else None,
        "snapshots": {"count": _int(snaps.get("count")), "note": _name(snaps.get("note", ""), 300)},
        "note": "Names are sanitized. Full result in scan_file: pass it to `report --scan`, do not read it.",
    }


def inventory_view(inv: Dict[str, Any], saved: Path) -> Dict[str, Any]:
    cands = [c for c in (inv.get("candidates") if isinstance(inv.get("candidates"), list) else []) if isinstance(c, dict)]
    cats: Dict[str, Dict[str, Any]] = {}
    for cand in cands:
        row = cats.setdefault(str(cand.get("category", "?"))[:2], {"count": 0, "bytes": 0})
        row["count"] += 1
        ev = cand.get("evidence") if isinstance(cand.get("evidence"), dict) else {}
        ceiling = ev.get("apparent_upper_bound")
        if isinstance(ceiling, dict):
            # APFS clones share blocks and only a restart frees them: the sum is a ceiling, never a gain
            box = row.setdefault("apparent_upper_bound", {"count": 0, "bytes": 0, "clones": 0})
            box["count"] += 1
            box["bytes"] += _int(ceiling.get("bytes"))
            box["clones"] += _int(ceiling.get("clones"))
            row["note"] = _name(ev.get("action") or "reboot frees these", 60)
        else:
            row["bytes"] += _int(cand.get("bytes"))
    warnings = inv.get("warnings") if isinstance(inv.get("warnings"), list) else []
    unverified = inv.get("unverified") if isinstance(inv.get("unverified"), list) else []
    search = inv.get("reference_search") if isinstance(inv.get("reference_search"), dict) else {}
    agents = inv.get("live_agents") if isinstance(inv.get("live_agents"), list) else []
    searched = {
        "status": _name(search.get("status", ""), 40),
        "roots": _int(search.get("roots")),
        "skipped_cloud": _int(search.get("skipped_cloud")),
        "seconds": search.get("seconds") if isinstance(search.get("seconds"), (int, float)) else None,
    }
    if isinstance(search.get("not_searched"), str) and search["not_searched"]:  # what no text search can see
        searched["not_searched"] = _name(search["not_searched"], 400)
    return {
        "inventory_file": str(saved),
        "ts": inv.get("ts"),
        "candidates": len(cands),
        "by_category": dict(sorted(cats.items())),
        "live_agents": len(agents),
        "retention": {
            _name(k, 60): (_name(v, 60) if isinstance(v, str) else v if isinstance(v, (int, float, bool)) else None)
            for k, v in (inv.get("retention") if isinstance(inv.get("retention"), dict) else {}).items()
        },
        "tools": sorted(_name(k, 30) for k in inv["tools"]) if isinstance(inv.get("tools"), dict) else [],
        "warnings": [_name(w, 200) for w in warnings[:10]],
        "unverified": len(unverified),
        "reference_search": searched,
        "scope_note": _name(inv.get("scope_note", ""), 300),
        "note": "Names are not shown here. Next: `plan --candidates <inventory_file>`, then `ask`.",
    }


VIEWS = {"scan": ("scans", "scan", scan_view), "inventory": ("inventories", "inventory", inventory_view)}


def agent_view(cmd: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Save the full result privately and return the sanitized summary for stdout."""
    subdir, prefix, build = VIEWS[cmd]
    if cmd == "inventory":  # `plan --candidates` accepts only a file that carries this signature
        result = dict(result)
        result.pop("mac", None)
        result["mac"] = common.sign(result, "inventory")
    saved = save_json(subdir, prefix, result)
    return build(result, saved)


LONG_TEXT_KEYS = {"gain_note": 600}  # fixed sentences of ours longer than the default cap; still sanitized


def scrub(obj: Any, maxlen: int = 300) -> Any:
    """Every string through sanitize_name: for results that carry a few OS-supplied names (volumes, paths)."""
    if isinstance(obj, str):
        return safety.sanitize_name(obj, maxlen)
    if isinstance(obj, list):
        return [scrub(x, maxlen) for x in obj]
    if isinstance(obj, dict):
        return {
            k: scrub(v, max(maxlen, LONG_TEXT_KEYS.get(k, 0)) if isinstance(v, str) else maxlen) for k, v in obj.items()
        }
    return obj
