"""`ask --lang pt`: the plan's fixed `deny` / `reason` strings reach the user in pt-BR, never half in English.

plan.py (and the safety checks it quotes) build those strings in English and the plan keeps them that way (they
are signed). ask.py translates at display time. The drift guard below reads the emitters' source, so a new
`deny` or `reason` added to plan.py or safety.py without a pt text fails here instead of reaching a pt user.
Nothing here touches user data: plans are in-memory dicts and no path is opened.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "corecleaner" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from corecleaner_lib import ask as ask_mod, plan as plan_mod  # noqa: E402
from tests.test_plan_ask import item, plan_of  # noqa: E402

LIB = SCRIPTS / "corecleaner_lib"
PLAN_EMITTERS = {"_safety_deny", "_keep_deny", "protected_inside_reason", "_unproven_deny", "_keeper_of",
                 "_classify", "_dependency_group"}
SAFETY_EMITTERS = {"is_protected", "is_cloud_or_placeholder", "_placeholder_reason", "_reason"}
RULE_SAMPLE = "tree ~/.ssh"


def _leaf_strings(node):
    """String literals a returned or assigned expression can yield (calls and names are not followed)."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str) and node.value:
            yield node.value
    elif isinstance(node, (ast.Tuple, ast.List)):
        for sub in node.elts:
            yield from _leaf_strings(sub)
    elif isinstance(node, ast.BinOp):
        yield from _leaf_strings(node.left)
        if isinstance(node.op, ast.Add):
            yield from _leaf_strings(node.right)
    elif isinstance(node, ast.IfExp):
        yield from _leaf_strings(node.body)
        yield from _leaf_strings(node.orelse)
    elif isinstance(node, ast.BoolOp):
        for sub in node.values:
            yield from _leaf_strings(sub)


def emitted(module, funcs, deny_sinks):
    """Fixed texts `funcs` return (and, when `deny_sinks`, every `deny` assigned, passed or put in a dict)."""
    tree = ast.parse((LIB / module).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in funcs:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    found.update(_leaf_strings(sub.value))
        if not deny_sinks:
            continue
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "deny" for t in node.targets):
            found.update(_leaf_strings(node.value))
        elif isinstance(node, ast.keyword) and node.arg == "deny":
            found.update(_leaf_strings(node.value))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "deny":
                    found.update(_leaf_strings(value))
    # no letters = punctuation glue such as the ")" closing "not a file: shown only (" + facts + ")"
    return {s for s in found if s not in plan_mod.ACTIONS and any(c.isalpha() for c in s)}


def sample(text):
    """A concrete string of the shape the emitter builds from this literal (counts, names, a tail)."""
    out = text.replace("%d", "3").replace("%s", "OSError")
    if out.startswith(" ("):  # safety._reason appends it to "<mode> <pattern>"
        return RULE_SAMPLE + out
    if out.endswith(": "):
        return out + "tail"
    if out.endswith(" ("):
        return out + "kind, name)"
    return out


def known_english():
    """Every fixed reason the code can put in a plan, as a sample string."""
    texts = emitted("plan.py", PLAN_EMITTERS, True) | emitted("safety.py", SAFETY_EMITTERS, False)
    texts |= {plan_mod.REFILL_REASON, "deny list", "synced folder"}  # REFILL_REASON is a Name in the source; two fallbacks
    return sorted({sample(t) for t in texts})


class TranslateTests(unittest.TestCase):
    def test_the_guard_finds_the_emitters(self):
        found = known_english()
        self.assertGreaterEqual(len(found), 35, found)
        for needle in ("symlink: never trashed", "protected: tail", "live dependency: cited by 3 file(s)",
                       "idle less than 3 days (history, worktree or clone: kept)", "volume root (mount point)",
                       "tree ~/.ssh (parent of a protected path)", "cannot lstat (OSError)"):
            self.assertIn(needle, found)

    def test_every_fixed_reason_the_code_emits_has_a_pt_text(self):
        for text in known_english():
            pt = ask_mod.translate_reason(text, "pt")
            self.assertNotEqual(pt, text, "no pt text for: " + text)
            self.assertEqual(ask_mod.translate_reason(text, "en"), text)

    def test_exact_texts_with_counts_and_names(self):
        t = ask_mod.translate_reason
        self.assertEqual(t("idle less than 45 days (history, worktree or clone: kept)", "pt"),
                         "parado há menos de 45 dias (histórico, worktree ou clone: mantido)")
        self.assertEqual(t("live dependency: cited by 2 file(s)", "pt"), "dependência viva: citado por 2 arquivo(s)")
        self.assertEqual(t(plan_mod.REFILL_REASON % 4, "pt"), "citado por 4 arquivo(s); a própria ferramenta o reconstrói")
        self.assertEqual(t("holds 7 file(s) with protected names (keys, .env, credentials): move them out first", "pt"),
                         "tem 7 arquivo(s) com nomes protegidos (chaves, .env, credenciais): tire-os de lá primeiro")
        self.assertEqual(t("protected: tree ~/.ssh", "pt"), "protegido: regra tree ~/.ssh")
        self.assertEqual(t("protected: node ~/Library (parent of a protected path)", "pt"),
                         "protegido: regra node ~/Library (pai de um caminho protegido)")
        self.assertEqual(t("protected: volume root", "pt"), "protegido: raiz de volume")
        self.assertEqual(t("cloud or placeholder: cloud-synced folder: iCloud Drive", "pt"),
                         "nuvem ou placeholder: pasta sincronizada na nuvem: iCloud Drive")
        self.assertEqual(t("cloud or placeholder: dataless placeholder (SF_DATALESS)", "pt"),
                         "nuvem ou placeholder: placeholder sem dados locais (SF_DATALESS)")
        self.assertEqual(t("not a file: shown only (process, node, up 12 min, cwd ~/proj)", "pt"),
                         "não é um arquivo: só mostrado (process, node, ativo há 12 min, pasta de trabalho ~/proj)")

    def test_unknown_text_stays_english_and_names_are_never_reinterpreted(self):
        t = ask_mod.translate_reason
        for text in ("some future reason: 7", "", "protected", "idle less than many days (history, worktree or clone: kept)"):
            self.assertEqual(t(text, "pt"), text)
        self.assertEqual(t("protected: some future rule", "pt"), "protegido: some future rule")
        tricky = r"tree {0} \1 {1}"
        self.assertEqual(t("protected: " + tricky, "pt"), "protegido: regra " + tricky)

    def test_en_and_unknown_languages_are_untouched(self):
        for text in known_english():
            self.assertEqual(ask_mod.translate_reason(text, "en"), text)
            self.assertEqual(ask_mod.translate_reason(text, "xx"), text)


class RenderTests(unittest.TestCase):
    def shown_plan(self, denies):
        return plan_of([item(i, 3, "list_only", deny=d) for i, d in enumerate(denies, 1)])

    def test_no_known_english_reason_reaches_the_pt_text(self):
        texts = known_english()
        for k in range(0, len(texts), 20):  # the shown-only table is cut at 25 rows
            chunk = texts[k:k + 20]
            out = ask_mod.render(self.shown_plan(chunk), "text", lang="pt")
            for english in chunk:
                self.assertNotIn(english, out["text"])
                self.assertIn(ask_mod.translate_reason(english, "pt"), out["text"], "cut or lost: " + english)
            self.assertIn("motivo", out["text"])

    def test_en_text_keeps_the_original_reasons(self):
        texts = known_english()[:20]
        out = ask_mod.render(self.shown_plan(texts), "text", lang="en")
        for english in texts:
            self.assertIn(english, out["text"])
        self.assertNotIn("motivo", out["text"])

    def reasons_plan(self):
        cited = item(1, 2, cat="D")
        cited["reason"] = "live dependency: cited by 2 file(s)"
        cited["evidence"].update(referenced_count=2, referenced_by=["~/a.sh", "~/b.sh"])
        refill = item(2, 1, "tool_command", cat="F", tool="npm cache clean --force")
        refill["reason"] = plan_mod.REFILL_REASON % 2
        refill["evidence"].update(referenced_count=2, referenced_by=["~/c.json"])
        maybe = item(3, 2, cat="D")
        maybe["reason"] = "possibly cited: a file may build this path in code, not proven unused"
        maybe["evidence"].update(referenced_maybe=["~/d.py"], referenced_unverified=True)
        unsure = item(4, 2, cat="D")
        unsure["reason"] = "dependency search incomplete: not proven unused"
        unsure["evidence"].update(referenced_unverified=True)
        return plan_of([cited, refill, maybe, unsure])

    def test_reasons_of_offered_rows_and_every_option_text_are_pt(self):
        out = ask_mod.render(self.reasons_plan(), "claude", lang="pt")
        blob = out["text"] + json.dumps(out["batch_questions"], ensure_ascii=False)
        for english in ("live dependency", "cited by", "rebuilds it", "possibly cited", "may build this path",
                        "dependency search", "not proven", "file(s)"):
            self.assertNotIn(english, blob)
        for pt in ("dependência viva: citado por 2 arquivo(s)", "citado por 2 arquivo(s); a própria ferramenta o reconstrói",
                   "possivelmente citado: um arquivo pode montar este caminho no código, não está provado que não é usado",
                   "busca de dependências incompleta: não está provado que não é usado", "DEPENDÊNCIA VIVA"):
            self.assertIn(pt, blob)

    def test_en_offered_rows_keep_the_original_reasons(self):
        out = ask_mod.render(self.reasons_plan(), "claude", lang="en")
        self.assertIn("trash; live dependency: cited by 2 file(s)", out["text"])
        self.assertIn("tool_command; cited by 2 file(s); its own tool rebuilds it", out["text"])
        self.assertIn("possibly cited: a file may build this path in code, not proven unused", out["text"])

    def test_the_action_column_is_pt_too(self):
        plan = plan_of([item(1, 1, cat="D"), item(2, 2, "archive_then_trash", cat="C"),
                        item(3, 1, "tool_command", cat="F", tool="brew cleanup")])
        text = ask_mod.render(plan, "text", lang="pt")["text"]
        self.assertRegex(text, r"c00001 \| D \| `dir1` \| 5 MB \| Lixeira \| ")
        self.assertRegex(text, r"c00002 \| C \| `dir2` \| 5 MB \| arquivar e Lixeira \| ")
        self.assertRegex(text, r"c00003 \| F \| `dir3` \| 5 MB \| comando da ferramenta \| ")
        for token in ("archive_then_trash", "tool_command"):
            self.assertNotIn(token, text)
        en = ask_mod.render(plan, "text", lang="en")["text"]
        self.assertIn("| archive_then_trash | ", en)


if __name__ == "__main__":
    unittest.main()
