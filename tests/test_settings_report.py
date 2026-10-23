"""Onboarding settings (language, dua) and the junk-by-folder report. Temp dirs only."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import ask, bootstrap, common, platform_info, report, settings  # noqa: E402
from tests.test_report import blocks, item, make_plan, make_scan, model_of  # noqa: E402

CLI = SCRIPTS / "corecleaner.py"


class StateCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="corecleaner-settings-")))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.state = self.root / "state"
        patcher = mock.patch.dict(os.environ, {"CORECLEANER_STATE_DIR": str(self.state), "HOME": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("CORECLEANER_LANG", None)


class Settings(StateCase):
    def test_reading_never_creates_the_state_dir_and_check_says_onboarding(self):
        self.assertEqual(common.read_settings(), {})
        self.assertFalse(self.state.exists())
        out = platform_info.check()
        self.assertTrue(out["onboarding"])
        self.assertEqual(out["settings"], {})
        self.assertFalse(self.state.exists())

    def test_write_merges_and_the_file_is_private(self):
        common.write_settings(lang="pt")
        common.write_settings(dua="declined")
        self.assertEqual(common.read_settings(), {"dua": "declined", "lang": "pt"})
        self.assertEqual(common.settings_path().stat().st_mode & 0o777, 0o600)
        common.write_settings(dua=None)
        self.assertEqual(common.read_settings(), {"lang": "pt"})
        self.assertFalse(platform_info.check()["onboarding"])

    def test_language_falls_back_to_the_recorded_one(self):
        self.assertEqual(ask._lang(None), "en")
        common.write_settings(lang="pt")
        self.assertEqual(ask._lang(None), "pt")
        self.assertEqual(ask._lang("en"), "en")
        with mock.patch.dict(os.environ, {"CORECLEANER_LANG": "en"}):
            self.assertEqual(ask._lang(None), "en")

    def test_decline_records_the_no_without_downloading(self):
        with mock.patch.object(bootstrap, "_bootstrap", return_value={"action": "needs_consent", "needs_consent": True, "installed": False, "present": False}) as fake:
            out = bootstrap.bootstrap(False, decline=True)
        self.assertEqual(fake.call_args[0][0], False)  # describe only
        self.assertEqual((out["action"], out["needs_consent"]), ("declined", False))
        self.assertEqual(common.read_settings()["dua"], "declined")

    def test_install_records_the_yes(self):
        with mock.patch.object(bootstrap, "_bootstrap", return_value={"action": "installed", "installed": True, "present": True}):
            bootstrap.bootstrap(True)
        self.assertEqual(common.read_settings()["dua"], "installed")

    def test_settings_command_validates_and_reports(self):
        out = settings.run(types.SimpleNamespace(lang="pt", dua=None))
        self.assertEqual((out["settings"]["lang"], out["changed"]), ("pt", ["lang"]))
        out = settings.run(types.SimpleNamespace(lang=None, dua="ask"))
        self.assertNotIn("dua", out["settings"])
        with self.assertRaises(common.CorecleanerError):
            settings.run(types.SimpleNamespace(lang="xx", dua=None))

    def test_cli_settings_round_trip(self):
        env = dict(os.environ)
        p = subprocess.run([sys.executable, str(CLI), "settings", "--lang", "pt"], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["settings"]["lang"], "pt")
        p = subprocess.run([sys.executable, str(CLI), "check"], capture_output=True, text=True, env=env)
        self.assertEqual(json.loads(p.stdout)["settings"], {"lang": "pt"})


class JunkByFolder(StateCase):
    def plan(self):
        it1 = item("c001", "/home/u/Documents/proj/node_modules", group=2, nbytes=500, cat="E")
        it1["evidence"] = {"project_idle_days": 41, "age_days": 3, "referenced_count": 0, "referenced_by": []}
        it2 = item("c002", "/home/u/Documents/proj/dist", group=1, nbytes=100, cat="D")
        it3 = item("c003", "/home/u/.codex/.tmp/x", group=2, nbytes=50, cat="C", action="archive_then_trash")
        it3["reason"] = "live dependency: cited by 2 file(s)"
        it3["evidence"] = {"age_days": 70, "referenced_count": 2, "referenced_by": ["a.mjs", "b.sh"]}
        it4 = item("c004", "/home/u/Downloads/a.pdf", group=3, nbytes=10, cat="I", deny="protected: deny list")
        return make_plan(it1, it2, it3, it4)

    def test_tree_groups_items_under_their_folders_with_counts(self):
        scan = make_scan(home="/home/u")
        m = model_of(report.render_html(scan, self.plan()))
        j = m["junk"]
        self.assertEqual(j["sums"]["1"], {"n": 1, "b": 100})
        self.assertEqual(j["sums"]["2"], {"n": 2, "b": 550})
        self.assertEqual(j["cats"]["E"], {"n": 1, "b": 500})
        home = j["root"]
        self.assertEqual(home["n"], "~")  # /home/u joined, named ~, and made the root since everything sits under it
        self.assertEqual(home["cnt"], [1, 2, 0, 1])  # a denied item counts as protected (class 4), not "shown only"
        self.assertEqual(home["by"], [100, 550, 0, 10])
        names = {k["n"]: k for k in home["c"]}
        self.assertEqual(set(names), {"Documents/proj", ".codex/.tmp", "Downloads"})  # single-child chains joined
        proj = names["Documents/proj"]
        self.assertEqual([it["id"] for it in proj["it"]], ["c002", "c001"])  # sure junk first, then by size
        self.assertEqual(proj["cnt"], [1, 1, 0, 0])
        nm = proj["it"][1]
        self.assertEqual((nm["age"], nm["cat"], nm["act"]), (41, "E", "trash"))  # project idle time, not the install's
        tmp = names[".codex/.tmp"]["it"][0]
        self.assertEqual((tmp["cited"], tmp["by"], tmp["reason"]), (2, ["a.mjs", "b.sh"], "live dependency: cited by 2 file(s)"))
        self.assertIsNone(model_of(report.render_html(scan, None))["junk"])

    def test_pt_labels_translate_reasons_and_the_page_stays_ascii(self):
        html = report.render_html(make_scan(home="/home/u"), self.plan(), "pt")
        self.assertTrue(html.isascii())
        self.assertIn('lang="pt"', html)
        m = model_of(html)
        self.assertEqual(m["lang"], "pt")
        self.assertEqual(m["L"]["cls1"], "Lixo certo")
        self.assertEqual(m["cats"]["E"], "node_modules parado")
        items = {it["id"]: it for k in m["junk"]["root"]["c"] for it in k["it"]}
        self.assertEqual(items["c003"]["reason"], "dependência viva: citado por 2 arquivo(s)")
        self.assertEqual(items["c004"]["deny"], "protegido: lista de proteção")
        self.assertNotIn("basic", m["L"])  # banner texts are built in Python, never shipped as spare strings
        en = model_of(report.render_html(make_scan("basic"), None, "pt"))
        self.assertIn("Modo básico", en["meta"]["banners"][0])

    def test_page_has_the_junk_view_first_and_the_map_second(self):
        html = report.render_html(make_scan(), self.plan())
        js = blocks(html)[1]
        self.assertIn('id="junk"', html)
        self.assertIn('id="mapv"', html)
        self.assertIn("var view = C ? 'choose' : (J ? 'junk' : 'map')", js)
        self.assertIn('id="choose"', html)
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, js)
        self.assertTrue(html.isascii())

    def test_report_lang_comes_from_settings(self):
        common.write_settings(lang="pt")
        self.state.mkdir(parents=True, exist_ok=True)
        scan_file = self.root / "scan.json"
        scan_file.write_text(json.dumps(make_scan()))
        out = report.run(types.SimpleNamespace(scan=str(scan_file), plan=None, lang=None))
        text = Path(out["report"]).read_text()
        self.assertIn('lang="pt"', text)
        self.assertIn("Mapa do disco", json.dumps(model_of(text)["L"], ensure_ascii=False))


class ChooseAndReply(StateCase):
    def plan(self):
        p = JunkByFolder.plan(self)
        p["sha256"] = "ab12cd34ef56" + "0" * 52
        p["items"][0]["action"] = "trash"
        p["items"][2]["action"] = "archive_then_trash"
        return p

    def test_choose_groups_offered_items_by_plain_section_and_preselects_sure_junk(self):
        m = model_of(report.render_html(make_scan(home="/home/u"), self.plan(), "pt"))
        c = m["choose"]
        self.assertEqual(c["sha"], "ab12cd34ef56")
        self.assertEqual((c["total_n"], c["total_b"]), (3, 650))
        cats = [s["cat"] for s in c["sections"]]
        self.assertEqual(cats[0], "D")  # the section that holds a recommended item comes first
        self.assertEqual(set(cats), {"D", "E", "C"})
        e = [s for s in c["sections"] if s["cat"] == "E"][0]
        self.assertEqual(e["title"], "node_modules de projetos parados")
        it = e["items"][0]
        self.assertEqual((it["n"], it["w"], it["age"], it["rec"]), ("proj/node_modules", "~/Documents/proj", 41, False))
        d = c["sections"][0]["items"][0]
        self.assertTrue(d["rec"])
        self.assertEqual(c["kept"]["n"], 1)
        self.assertEqual(c["kept"]["items"][0]["why"], "protegido: lista de proteção")
        self.assertIsNone(model_of(report.render_html(make_scan(), None))["choose"])

    def test_reply_maps_ids_per_action_and_refuses_the_rest(self):
        plan = self.plan()
        out = ask.read_reply(plan, "CoreCleaner plano ab12cd34ef56\nLixeira: c001 c002, c999\nArquivar e Lixeira: c003 c001\nComando da ferramenta: c004\nfoo")
        self.assertTrue(out["plan_matches"])
        self.assertEqual(out["trash"], ["c001", "c002"])
        self.assertEqual(out["archive_then_trash"], ["c003"])
        self.assertEqual(out["tool_command"], [])
        joined = " | ".join(out["problems"])
        for frag in ("not in this plan: c999", "c001 is trash in the plan, not archive_then_trash", "not offered: c004", "line not understood"):
            self.assertIn(frag, joined)
        other = ask.read_reply(plan, "CoreCleaner plan ffffffffffff\nTrash: c001")
        self.assertFalse(other["plan_matches"])
        self.assertIn("another plan", other["problems"][0])


if __name__ == "__main__":
    unittest.main()
