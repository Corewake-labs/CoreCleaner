"""report.py: offline HTML treemap. Everything runs on synthetic scans/plans; no real disk is read."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import common, report  # noqa: E402

POSIX = os.name == "posix"
CLI = SCRIPTS / "corecleaner.py"


def node(path, b, children=None, a=None):
    return {"path": path, "bytes": b, "apparent": b if a is None else a, "children": children or []}


def make_scan(tool="dua", **extra):
    tree = node(
        "",
        1000,
        [
            node("/home/u", 700, [node("/home/u/.claude", 400, [node("/home/u/.claude/projects", 300)]), node("/home/u/docs", 300)]),
            node("/opt", 300),
        ],
        a=1200,
    )
    scan = {
        "tool": tool,
        "exact": tool == "dua",
        "label": "exact" if tool == "dua" else "apparent (upper bound)",
        "tree": tree,
        "gap": {"bytes": 500, "free_bytes": 4000, "total_bytes": 9000, "unreadable": 2},
        "top": [{"path": "/home/u/.claude", "bytes": 400}],
        "ts": "2026-10-21T12:00:00Z",
    }
    scan.update(extra)
    return scan


def make_plan(*items):
    return {"version": 1, "items": list(items), "summary": {"expected_gain_note": "Trash first"}, "sha256": "x"}


def item(id_, path, group=1, nbytes=100, deny=None, cat="A", action="trash"):
    return {"id": id_, "group": group, "category": cat, "path": path, "display": path.rsplit("/", 1)[-1],
            "bytes": nbytes, "action": action, "deny": deny}


def blocks(html):
    """(csp, executable script text, style text, data JSON text) of a rendered page."""
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html).group(1)
    scripts = re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S)
    js = [body for attrs, body in scripts if "application/json" not in attrs]
    data = [body for attrs, body in scripts if "application/json" in attrs]
    assert len(js) == 1 and len(data) == 1 and len(scripts) == 2, scripts
    style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    return csp, js[0], style, data[0]


def model_of(html):
    return json.loads(blocks(html)[3])


def sha(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() + "'"


class CspAndNetwork(unittest.TestCase):
    def test_no_external_url_outside_comments(self):
        scan = make_scan()
        # a path segment that looks like a URL must not surface as one in the markup
        scan["tree"]["children"].append(node("/data/https://evil.example/x", 5))
        html = report.render_html(scan, make_plan(item("c001", "/data/http://a.example/b")))
        bare = re.sub(r"<!--.*?-->", "", html, flags=re.S)
        self.assertIsNone(re.search(r"https?://", bare))
        self.assertIsNone(re.search(r"(?:src|href|action)\s*=|@import|url\(", bare))
        self.assertIn("evil.example", html)  # still there, just not as a URL token

    def test_csp_hashes_match_inline_blocks(self):
        html = report.render_html(make_scan(), None)
        csp, js, style, _ = blocks(html)
        directives = dict(part.strip().split(" ", 1) for part in csp.split(";") if part.strip())
        self.assertEqual(directives["default-src"], "'none'")
        self.assertEqual(directives["script-src"], sha(js))
        self.assertEqual(directives["style-src"], sha(style))
        self.assertNotIn("unsafe", csp)
        self.assertIn("base-uri", directives)
        self.assertLess(html.index("Content-Security-Policy"), html.index("<style>"))

    def test_hash_is_for_the_page_script_even_with_hostile_data(self):
        scan = make_scan()
        scan["tree"]["children"][0]["path"] = "/x/</script><script>alert(1)</script>"
        csp, js, _, _ = blocks(report.render_html(scan, None))
        self.assertIn(sha(js), csp)

    def test_script_never_uses_html_sinks(self):
        js = blocks(report.render_html(make_scan(), None))[1]
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
                     "setAttribute('style'", "fetch(", "XMLHttpRequest", "WebSocket", "import(", "sendBeacon"):
            self.assertNotIn(sink, js)
        self.assertNotIn("</", js)  # would end the element early
        self.assertNotIn("<!--", js)
        self.assertIn("JSON.parse", js)
        self.assertIn("textContent", js)

    def test_page_basics(self):
        html = report.render_html(make_scan(), None)
        self.assertIn("prefers-color-scheme:dark", html)
        self.assertIn('name="viewport"', html)
        self.assertIn("<noscript>", html)
        self.assertTrue(html.isascii())
        self.assertNotIn("\r", html)


class HostileNames(unittest.TestCase):
    NAME = "</script><img src=x onerror=alert(1)>"

    def test_script_breakout_name_is_escaped_and_round_trips(self):
        scan = make_scan()
        scan["tree"]["children"][1]["path"] = "/opt/" + self.NAME
        plan = make_plan(item("c001", "/opt/" + self.NAME))
        plan["items"][0]["display"] = self.NAME
        html = report.render_html(scan, plan)
        self.assertNotIn("</script><img", html)
        self.assertNotIn("<img", html)
        self.assertEqual(len(re.findall(r"</script>", html)), 2)  # ours only
        data = blocks(html)[3]
        self.assertNotIn("<", data)
        self.assertNotIn(">", data)
        self.assertIn("\\u003c/script\\u003e\\u003cimg", data)
        m = model_of(html)  # JSON.parse gives the original text back; the page only sets textContent
        self.assertIn("/opt/" + self.NAME, [c["p"] for c in m["tree"]["c"]])
        self.assertEqual(m["plan"]["list"][0]["n"], self.NAME)

    def test_control_surrogate_and_bidi_characters_are_neutralized(self):
        scan = make_scan()
        scan["tree"]["children"][1]["path"] = "/opt/a\x1b[31m\udcff\u202eb\u2028c\x00d"
        html = report.render_html(scan, None)
        self.assertTrue(html.isascii())
        name = [c["n"] for c in model_of(html)["tree"]["c"] if c["p"].startswith("/opt/a")][0]
        self.assertEqual(name, "a\ufffd[31m\ufffd\ufffdb\ufffdc\ufffdd")
        html.encode("utf-8")  # lone surrogate must not reach the file encoder

    def test_long_names_are_truncated(self):
        scan = make_scan()
        scan["tree"]["children"][1]["path"] = "/opt/" + "n" * 5000
        got = [c for c in model_of(report.render_html(scan, None))["tree"]["c"] if c["p"].startswith("/opt/n")][0]
        self.assertLessEqual(len(got["n"]), report.NAME_MAX + 3)
        self.assertLessEqual(len(got["p"]), report.PATH_MAX + 3)


class ModelContent(unittest.TestCase):
    def test_totals_and_gap(self):
        m = model_of(report.render_html(make_scan(), None))
        self.assertEqual(
            m["totals"],
            {"read": 1000, "apparent": 1200, "gap": 500, "free": 4000, "total": 9000, "unreadable": 2},
        )
        self.assertIsNone(m["plan"])
        self.assertEqual([t["p"] for t in m["top"]], ["/home/u/.claude"])

    def test_gap_from_used_bytes_and_missing_gap(self):
        scan = make_scan()
        scan["gap"] = {"used_bytes": 1700}
        self.assertEqual(model_of(report.render_html(scan, None))["totals"]["gap"], 700)
        del scan["gap"]
        t = model_of(report.render_html(scan, None))["totals"]
        self.assertEqual((t["gap"], t["free"]), (0, None))

    def test_gap_reads_the_key_scan_py_emits(self):
        scan = make_scan()
        scan["gap"] = {"label": "unexplained", "unexplained_bytes": 321, "used_bytes": 99999, "read_bytes": 1000}
        self.assertEqual(model_of(report.render_html(scan, None))["totals"]["gap"], 321)

    def test_top_falls_back_to_largest_nodes(self):
        scan = make_scan()
        del scan["top"]
        top = model_of(report.render_html(scan, None))["top"]
        self.assertEqual([t["p"] for t in top][:2], ["/home/u", "/home/u/.claude"])

    def test_basic_mode_banner(self):
        basic = report.render_html(make_scan("basic"), None)
        self.assertIn("apparent (upper bound)", basic)
        self.assertEqual(len(model_of(basic)["meta"]["banners"]), 1 if sys.platform != "win32" else 2)
        self.assertIn("APFS clones may look larger than they are", model_of(basic)["meta"]["banners"][0])
        self.assertFalse(model_of(basic)["meta"]["exact"])
        exact = report.render_html(make_scan("dua"), None)
        self.assertNotIn("Basic mode", exact)
        self.assertTrue(model_of(exact)["meta"]["exact"])

    def test_windows_banner(self):
        with mock.patch.object(report.sys, "platform", "win32"):
            m = model_of(report.render_html(make_scan(), None))
        self.assertIn("BETA", m["meta"]["banners"][0])

    def test_plan_marks_exact_contains_outside_and_denied(self):
        plan = make_plan(
            item("c001", "/home/u/.claude/projects", group=1, nbytes=300),  # exact, depth 3 of the tree
            item("c002", "/opt", group=2, nbytes=300),                        # exact top-level node
            item("c003", "/home/u/docs/deep/x", group=3, nbytes=40),          # below the scanned depth
            item("c004", "/var/outside", group=1, nbytes=7),                  # no node holds it
            item("c005", "/home/u/docs", group=1, nbytes=300, deny="cloud folder"),
        )
        m = model_of(report.render_html(make_scan(), plan))
        home, opt = m["tree"]["c"][0], m["tree"]["c"][1]
        claude = [c for c in home["c"] if c["n"] == ".claude"][0]
        docs = [c for c in home["c"] if c["n"] == "docs"][0]
        projects = claude["c"][0]
        self.assertEqual((projects["k"], projects["i"]["id"]), (1, "c001"))
        self.assertEqual((opt["k"], opt["i"]["id"]), (2, "c002"))
        self.assertNotIn("k", claude)
        self.assertEqual(claude["pb"], [300, 0, 0, 0])
        self.assertEqual(home["pb"], [300, 0, 40, 300])
        self.assertEqual((docs["k"], docs["i"]["deny"]), (4, "cloud folder"))
        self.assertEqual(docs["pb"], [0, 0, 40, 0])
        rows = {r["i"]["id"]: r for r in m["plan"]["list"]}
        self.assertEqual(rows["c003"]["at"], "/home/u/docs")
        self.assertEqual(rows["c004"]["at"], "")
        self.assertEqual([r["i"]["id"] for r in m["plan"]["list"]], ["c001", "c004", "c002", "c003", "c005"])
        self.assertEqual(m["plan"]["sums"]["1"], {"n": 2, "b": 307})
        self.assertEqual(m["plan"]["sums"]["4"], {"n": 1, "b": 300})
        self.assertEqual(m["plan"]["note"], "Trash first")

    def test_plan_prefix_match_is_by_component(self):
        plan = make_plan(item("c001", "/home/u/docs-old", group=1))
        m = model_of(report.render_html(make_scan(), plan))
        docs = [c for c in m["tree"]["c"][0]["c"] if c["n"] == "docs"][0]
        self.assertNotIn("k", docs)
        self.assertNotIn("pb", docs)

    def test_unknown_group_is_not_actionable(self):
        plan = make_plan(item("c001", "/opt", group=7), item("c002", "/home/u", group=True))
        m = model_of(report.render_html(make_scan(), plan))
        self.assertEqual([c["k"] for c in m["tree"]["c"]], [4, 4])

    def test_children_are_capped_and_totals_kept(self):
        kids = [node("/big/d%03d" % i, 1000 - i) for i in range(500)]
        scan = make_scan(tree=node("", 0, [node("/big", sum(k["bytes"] for k in kids), kids)]))
        big = model_of(report.render_html(scan, None))["tree"]["c"][0]
        self.assertEqual(len(big["c"]), report.MAX_CHILDREN + 1)
        more = big["c"][-1]
        self.assertEqual(more["more"], 300)
        self.assertEqual(sum(c["b"] for c in big["c"]), big["b"])
        self.assertEqual([c["b"] for c in big["c"][:-1]], sorted((c["b"] for c in big["c"][:-1]), reverse=True))

    def test_malformed_values_do_not_crash(self):
        scan = make_scan()
        scan["tree"]["children"] += [None, "x", {"path": 5, "bytes": "9"}, {"path": "/n", "bytes": float("nan")},
                                      {"path": "/t", "bytes": True, "children": "oops"}]
        scan["gap"] = "bad"
        report.render_html(scan, {"items": [None, {"path": 3}, {"path": ""}, {"path": "/p", "bytes": -5}]})

    def test_rejects_scan_without_tree(self):
        for bad in ({}, {"tree": []}, []):
            with self.assertRaises(common.CorecleanerError) as cm:
                report.render_html(bad, None)
            self.assertEqual(cm.exception.code, common.EXIT_USAGE)

    def test_deep_tree_is_cut(self):
        tree = node("/d0", 1)
        cur = tree
        for i in range(1, 80):
            nxt = node(cur["path"] + "/d", 1)
            cur["children"].append(nxt)
            cur = nxt
        depth, c = 0, model_of(report.render_html(make_scan(tree=tree), None))["tree"]
        while "c" in c:
            c, depth = c["c"][0], depth + 1
        self.assertLessEqual(depth, report.MAX_DEPTH)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TreemapMath(unittest.TestCase):
    """Run the page's pure squarify/fmt part under node: area, bounds, overlap."""

    HARNESS = r"""
var out = [];
function rnd(seed) { var s = seed; return function () { s = (s * 1664525 + 1013904223) % 4294967296; return s / 4294967296; }; }
for (var t = 0; t < 300; t++) {
  var r = rnd(t + 1), n = 1 + Math.floor(r() * 60), vals = [];
  for (var i = 0; i < n; i++) vals.push(Math.pow(r(), 4) * 1e9 + 1);
  vals.sort(function (a, b) { return b - a; });
  var W = 100 + r() * 900, H = 100 + r() * 600, rects = squarify(vals, 0, 0, W, H), total = 0, area = 0;
  vals.forEach(function (v) { total += v; });
  if (rects.length !== n) throw new Error('missing rects ' + rects.length + '/' + n);
  rects.forEach(function (q, i) {
    if (q.x < -1e-6 || q.y < -1e-6 || q.x + q.w > W + 1e-6 || q.y + q.h > H + 1e-6) throw new Error('out of bounds');
    var want = vals[i] / total * W * H;
    if (Math.abs(q.w * q.h - want) > 1e-6 * W * H) throw new Error('area ' + (q.w * q.h) + ' vs ' + want);
    area += q.w * q.h;
    for (var j = 0; j < i; j++) {
      var p = rects[j], ox = Math.min(p.x + p.w, q.x + q.w) - Math.max(p.x, q.x), oy = Math.min(p.y + p.h, q.y + q.h) - Math.max(p.y, q.y);
      if (ox > 1e-6 && oy > 1e-6) throw new Error('overlap');
    }
  });
  if (Math.abs(area - W * H) > 1e-6 * W * H) throw new Error('coverage');
}
if (squarify([], 0, 0, 10, 10).length !== 0 || squarify([5], 0, 0, 0, 10).length !== 0) throw new Error('degenerate');
var one = squarify([5], 0, 0, 30, 20)[0];
if (one.w !== 30 || one.h !== 20) throw new Error('single');
var f = [fmt(0), fmt(1023), fmt(1024), fmt(1536), fmt(1073741824 * 12.34), fmt(-1), fmt(NaN)].join('|');
if (f !== '0 B|1023 B|1.00 KiB|1.50 KiB|12.3 GiB|?|?') throw new Error('fmt ' + f);
console.log('ok');
"""

    def test_squarify_and_fmt(self):
        js = blocks(report.render_html(make_scan(), None))[1]
        pure = js.split("/* --- pure --- */")[1].split("/* --- end pure --- */")[0]
        proc = subprocess.run(["node", "-"], input=pure + self.HARNESS, capture_output=True, text=True, timeout=60)
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "ok"), proc.stderr)


class RunWritesReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="corecleaner-report-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patcher = mock.patch.dict(os.environ, {common.STATE_ENV: os.path.join(self.tmp, "state")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.scan_file = os.path.join(self.tmp, "scan.json")
        Path(self.scan_file).write_text(json.dumps(make_scan()), encoding="utf-8")

    def args(self, scan=None, plan=None):
        return argparse.Namespace(cmd="report", scan=scan or self.scan_file, plan=plan)

    def test_run_writes_into_state_reports_dir(self):
        res = report.run(self.args())
        path = Path(res["report"])
        self.assertEqual(path.parent, Path(self.tmp, "state", "reports"))
        self.assertRegex(path.name, r"^report-\d{8}T\d{6}Z\.html$")
        self.assertEqual(path.stat().st_size, res["bytes"])
        if POSIX:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("<!doctype html>"))
        self.assertEqual(model_of(text)["totals"]["free"], 4000)  # scan's own number wins

    def test_run_never_overwrites_a_report_from_the_same_second(self):
        with mock.patch.object(report, "file_stamp", return_value="20261021T120000Z"):
            first, second = report.run(self.args())["report"], report.run(self.args())["report"]
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("report-20261021T120000Z.html"))
        self.assertTrue(second.endswith("report-20261021T120000Z-2.html"))
        self.assertTrue(os.path.exists(first) and os.path.exists(second))

    def test_run_fills_free_space_when_scan_has_none(self):
        scan = make_scan()
        scan["gap"] = {"bytes": 1}
        Path(self.scan_file).write_text(json.dumps(scan), encoding="utf-8")
        res = report.run(self.args())
        m = model_of(Path(res["report"]).read_text(encoding="utf-8"))
        self.assertGreater(m["totals"]["free"], 0)
        self.assertEqual(m["meta"]["free_note"], "at report time")

    def test_run_loads_plan_through_load_plan(self):
        plan = make_plan(item("c001", "/opt", group=2, nbytes=300))
        with mock.patch.object(report._plan, "load_plan", return_value=plan) as lp:
            res = report.run(self.args(plan="/some/plan.json"))
        lp.assert_called_once_with("/some/plan.json")
        m = model_of(Path(res["report"]).read_text(encoding="utf-8"))
        self.assertEqual(m["tree"]["c"][1]["i"]["id"], "c001")

    def test_tampered_plan_aborts_before_writing(self):
        boom = common.CorecleanerError(common.EXIT_PLAN_TAMPERED, "plan hash mismatch")
        with mock.patch.object(report._plan, "load_plan", side_effect=boom):
            with self.assertRaises(common.CorecleanerError) as cm:
                report.run(self.args(plan="/p.json"))
        self.assertEqual(cm.exception.code, common.EXIT_PLAN_TAMPERED)
        self.assertFalse(Path(self.tmp, "state", "reports").exists())

    def test_bad_scan_files(self):
        Path(self.tmp, "bad.json").write_text("{not json", encoding="utf-8")
        Path(self.tmp, "list.json").write_text("[]", encoding="utf-8")
        Path(self.tmp, "notree.json").write_text("{}", encoding="utf-8")
        for name in ("missing.json", "bad.json", "list.json", "notree.json"):
            with self.assertRaises(common.CorecleanerError) as cm:
                report.run(self.args(scan=os.path.join(self.tmp, name)))
            self.assertEqual(cm.exception.code, common.EXIT_USAGE, name)

    def test_cli_report_end_to_end(self):
        env = dict(os.environ, **{common.STATE_ENV: os.path.join(self.tmp, "cli-state")})
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(CLI), "report", "--scan", self.scan_file],
            capture_output=True, text=True, timeout=60, env=env, cwd=self.tmp,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out["ok"] and out["cmd"] == "report")
        self.assertTrue(Path(out["report"]).is_file())
        self.assertTrue(out["report"].startswith(os.path.join(self.tmp, "cli-state", "reports")))


if __name__ == "__main__":
    unittest.main()
