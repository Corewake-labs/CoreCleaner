"""`ask --lang pt`: the per-category "Lixeira em todos (N)" group question.

BACKLOG "ask monta no grupo 2 um Lixeira em todos (N) que mistura histórico, clones, mídia e caches" was closed on
2026-10-22 by ask._collapsed (one "all N" per category, "One by one" expands one category). test_plan_ask covers it
in English; these tests pin the pt rendering. In-memory plans only, no path is opened.
"""
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import ask as ask_mod  # noqa: E402
from tests.test_plan_ask import item, plan_of  # noqa: E402


class PerCategoryGroupQuestionPtTests(unittest.TestCase):
    def two_categories(self):
        return plan_of([item(i, 2, cat="A", age=50 + i) for i in range(1, 6)]
                       + [item(i, 2, cat="I", age=10) for i in range(6, 12)])

    def test_group_2_asks_one_pt_question_per_category(self):
        out = ask_mod.render(self.two_categories(), "claude", lang="pt")
        groups = [q for q in out["batch_questions"][0] if q["header"].startswith("Grupo")]
        self.assertEqual([q["header"] for q in groups], ["Grupo 2/A", "Grupo 2/I"])
        self.assertEqual(groups[0]["question"],
                         "Grupo 2, Decisão rápida, histórico de agente: 5 itens, 25 MB aparentes, o mais novo parado há 51 dias. O que fazer?")
        self.assertIn("duplicata", groups[1]["question"])
        self.assertIn("6 itens", groups[1]["question"])
        for q in groups:
            self.assertEqual([o["label"] for o in q["options"]][:2], ["Manter todos", "Um a um"])  # safe option first, no recommendation
            self.assertNotIn("Recomendado", json.dumps(q, ensure_ascii=False))
        self.assertEqual(groups[0]["options"][2]["label"], "Lixeira em todos (5)")
        self.assertEqual(groups[1]["options"][2]["label"], "Lixeira em todos (6)")
        self.assertIn("Pergunta sobre cada um dos 5 itens separadamente.", groups[0]["options"][1]["description"])
        by_effect = [{o["effect"]: o for o in m["options"]} for m in out["answer_map"][:2]]
        self.assertEqual(by_effect[0]["trash"]["ids"], ["c%05d" % i for i in range(1, 6)])
        self.assertEqual(by_effect[1]["trash"]["ids"], ["c%05d" % i for i in range(6, 12)])
        self.assertEqual(by_effect[0]["expand"]["expand"], "2/A")
        self.assertEqual(by_effect[1]["expand"]["expand"], "2/I")
        for i in range(1, 12):
            self.assertIn("c%05d" % i, out["text"])  # every id an "all N" covers is in the table

    def test_group_1_pt_recommends_and_dirty_repos_say_they_archive_first(self):
        plan = plan_of([item(i, 1, cat="D") for i in range(1, 7)])
        labels = [o["label"] for o in ask_mod.render(plan, "claude", lang="pt")["batch_questions"][0][0]["options"]]
        self.assertEqual(labels, ["Lixeira em todos (6) (Recomendado)", "Um a um", "Manter todos"])
        dirty = plan_of([item(i, 2, cat="C") for i in range(1, 6)] + [item(6, 2, "archive_then_trash", cat="C")])
        out = ask_mod.render(dirty, "claude", lang="pt")
        self.assertEqual(out["answer_map"][0]["options"][2]["effect"], "archive_then_trash")
        self.assertEqual(out["batch_questions"][0][0]["options"][2]["label"], "Arquivar repos sujos, Lixeira em todos (6)")

    def test_pt_expand_of_one_category_leaves_the_other_grouped(self):
        out = ask_mod.render(self.two_categories(), "claude", lang="pt", expand={"2/A"})
        flat = [q for b in out["batch_questions"] for q in b]
        self.assertEqual([q["header"] for q in flat if q["header"].startswith("Grupo")], ["Grupo 2/I"])
        self.assertEqual(sum(q["header"].startswith("Item") for q in flat), 5)


if __name__ == "__main__":
    unittest.main()
