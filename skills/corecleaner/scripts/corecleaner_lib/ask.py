"""Questions for the user, rendered from a plan. (T6; subcommand `ask`)

Read-only. The agent shows these; it never composes its own item descriptions. Names come from
plan items' "display" and always pass through safety.sanitize_name; the path appears only in a
code span, sanitized and with backticks removed.

run(args): args.plan (file), args.format ("claude" | "codex" | "text"), optional args.expand
  ("1,2": groups to ask one by one), args.lang ("en" | "pt"; default env CORECLEANER_LANG or "en").
  plan = plan.load_plan(args.plan) (hash checked, else exit 41). Returns render(...).
  lang "pt" also translates the plan's fixed `deny` and `reason` strings in the tables (PT_REASONS exact,
  PT_FORMATS with a count or a name; translate_reason). A string not in the table stays English.

render(plan, fmt, expand=None, lang="en", plan_file=None) -> dict
  {"format", "text", "questions", "batches", "batch_questions", "answer_map"}
  Batches of at most 4 questions, recommended option first (group 1 only: "(Recommended)").
  Every question has 2-4 options and one "Keep (nothing now)" option; silence or a vague answer
  means no. Inside a group, each CATEGORY with more than 4 plain trashable items becomes ONE group question
  ("Trash all N / One by one / Keep all", naming the category, its bytes and the youngest age) with the
  table in `text`; categories are never mixed in one "all N". "One by one" is re-rendered with expand=[g].
  The table in `text` lists EVERY id a "Trash all N" covers (never cut at TABLE_ROWS); the cut applies
  to item-by-item groups and to the shown-only table.
  Tool-command items are always asked one by one (each command needs its own approval); so is an item
  other files cite (evidence.referenced_count > 0): its option names the first 3 files; so is a repo
  holding ignored data the archive would not carry (evidence.git.ignored_large): its option says how much.
  A clean repo (B, C, D) trashed with no archive says it counts as "published by local refs, not checked against
  the server" (evidence.git.remote_checked is always False: inventory never contacts the network).
  fmt "claude": questions = first batch shaped for AskUserQuestion; batch_questions = all batches.
  fmt "codex"|"text": questions is None; `text` holds every batch as a numbered list answered like
    "1a 2b 3b" ("nothing" stops), each batch ending with an instruction to stop and wait.
  answer_map: [{"n", "group", "options": [{"letter", "label", "effect", "ids", ["expand"]}]}];
    effect in trash | archive_then_trash | tool_command | expand | keep. Only ids that got an
    explicit yes go to `trash --ids`. Group 3 and list_only items are shown, never offered.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import common, plan as plan_mod, safety

FORMATS = ("claude", "codex", "text")
BATCH_SIZE = 4
GROUP_THRESHOLD = 4
HEADER_MAX = 12
TABLE_ROWS = 25
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")

STR: Dict[str, Dict[str, str]] = {
    "en": {
        "rec": "(Recommended)",
        "keep": "Keep (nothing now)",
        "keep_all": "Keep all",
        "keep_desc": "Nothing changes. You can run the tidy again later.",
        "keep_all_desc": "Nothing changes for these {n} items.",
        "trash": "Move to Trash",
        "archive_trash": "Archive and Trash",
        "tool": "Clean with its own tool",
        "trash_all": "Trash all {n}",
        "trash_all_arch": "Archive dirty repos, Trash all {n}",
        "one_by_one": "One by one",
        "one_by_one_desc": "Ask about each of the {n} items separately.",
        "q_item": "Trash {name} in {where} ({cat}, {size} apparent{age})?",
        "q_arch": "Archive and Trash {name} in {where} ({cat}, {size} apparent{age})? It holds work that exists nowhere else.",
        "q_tool": "Clean {name} in {where} ({cat}, {size} apparent) with the tool's own command?",
        "d_keeper": " The copy at {path} stays.",
        "d_brew": " It also removes old versions of installed formulae and other Homebrew leftovers, not only downloads.",
        "d_npx": " `--no-install` downloads nothing: it fails if the tool is not already installed here.",
        "q_group": "Group {g}, {title}, {cat}: {n} items, {size} apparent{age}. What now?",
        "age_min": ", the youngest idle {d} days",
        "age": ", idle {d} days",
        "d_ref": " LIVE DEPENDENCY: cited by {n} file(s){files}. Moving it may break them.",
        "d_refill": " Cited by {n} file(s) as a setting; the next install downloads what it needs again.",
        "d_unv": " The search for files that use it did not finish, so nothing proves it unused.",
        "d_maybe": " A file may build this path in code{files}, so nothing proves it unused.",
        "d_local": " It counts as published by local refs, not checked against the server: a commit the server lost still looks published here.",
        "d_ignored": " IGNORED DATA NOT ARCHIVED: {n} file(s), {size} that git does not track (models, local state) go to the Trash without a copy.",
        "d_trash": (
            "{size} apparent. The real gain is often smaller (APFS clones, hardlinks, snapshots) and "
            "only appears after you empty the Trash. `undo` restores it."
        ),
        "d_arch": (
            "{size} apparent. Unsaved or unpublished work is archived first (git bundle, diff, loose files), "
            "then moved to the Trash. Real gain is apparent minus the archive, after you empty the Trash."
        ),
        "d_tool": (
            "Runs {cmd} only after you approve it separately; CoreCleaner never runs it. "
            "{size} apparent; the real gain is what the tool frees."
        ),
        "d_all": (
            "{size} apparent in total. The real gain is often much smaller (clones, hardlinks, snapshots) "
            "and only appears after you empty the Trash."
        ),
        "hdr_item": "Item",
        "hdr_group": "Group",
        "t1": "Sure junk",
        "t2": "Quick decision",
        "n1": "Mostly caches and clean copies: the real gain is close to the apparent size once the Trash is emptied.",
        "n2": "The apparent size counts every clone and hardlink: the real gain is often much smaller.",
        "overview": "CoreCleaner plan {sha}: {n} items, {size} apparent could be offered.",
        "gain": plan_mod.GAIN_NOTE,
        "group_line": "Group {g}, {title}: {n} items, {size} apparent. {note}",
        "shown_only": "Shown only, never offered for trashing",
        "more": "... and {k} more",
        "rules": (
            "Silence or a vague answer means no. Only ids with an explicit yes go to `trash`: "
            "dry run first, then --apply."
        ),
        "nothing_to_ask": "Nothing to ask: no item can be offered for trashing.",
        "batch": (
            "Batch {i} of {m}. Answer like \"{ex}\" or say \"nothing\" to stop. "
            "STOP here and WAIT for the user's answer before showing the next batch."
        ),
        "table_head": "id | cat | name | size | action | path",
        "reason": "reason",
    },
    "pt": {
        "rec": "(Recomendado)",
        "keep": "Manter (nada agora)",
        "keep_all": "Manter todos",
        "keep_desc": "Nada muda. Dá para rodar a faxina de novo depois.",
        "keep_all_desc": "Nada muda nestes {n} itens.",
        "trash": "Mover para a Lixeira",
        "archive_trash": "Arquivar e Lixeira",
        "tool": "Limpar pela própria ferramenta",
        "trash_all": "Lixeira em todos ({n})",
        "trash_all_arch": "Arquivar repos sujos, Lixeira em todos ({n})",
        "one_by_one": "Um a um",
        "one_by_one_desc": "Pergunta sobre cada um dos {n} itens separadamente.",
        "q_item": "Mover {name}, em {where}, para a Lixeira ({cat}, {size} aparentes{age})?",
        "q_arch": "Arquivar e mover {name}, em {where}, para a Lixeira ({cat}, {size} aparentes{age})? Tem trabalho que não existe em outro lugar.",
        "q_tool": "Limpar {name}, em {where}, ({cat}, {size} aparentes) com o comando da própria ferramenta?",
        "d_keeper": " A cópia em {path} fica.",
        "d_brew": " Também remove versões antigas de fórmulas instaladas e outras sobras do Homebrew, não só downloads.",
        "d_npx": " `--no-install` não baixa nada: falha se a ferramenta ainda não estiver instalada aqui.",
        "q_group": "Grupo {g}, {title}, {cat}: {n} itens, {size} aparentes{age}. O que fazer?",
        "age_min": ", o mais novo parado há {d} dias",
        "age": ", parado há {d} dias",
        "d_ref": " DEPENDÊNCIA VIVA: citado por {n} arquivo(s){files}. Mover pode quebrá-los.",
        "d_refill": " Citado por {n} arquivo(s) como configuração; a próxima instalação baixa de novo o que precisar.",
        "d_unv": " A busca por arquivos que o usam não terminou, então nada prova que não é usado.",
        "d_maybe": " Um arquivo pode montar este caminho no código{files}, então nada prova que não é usado.",
        "d_local": " Conta como publicado pelas refs locais, sem checar no servidor: um commit que o servidor perdeu ainda parece publicado aqui.",
        "d_ignored": " DADOS IGNORADOS SEM ARQUIVO: {n} arquivo(s), {size} que o git não rastreia (modelos, estado local) vão para a Lixeira sem cópia.",
        "d_trash": (
            "{size} aparentes. O ganho real costuma ser menor (clones APFS, hardlinks, snapshots) e só "
            "aparece depois de esvaziar a Lixeira. `undo` restaura."
        ),
        "d_arch": (
            "{size} aparentes. Trabalho não salvo ou não publicado é arquivado antes (git bundle, diff, "
            "arquivos soltos) e só então vai para a Lixeira. Ganho real = aparente menos o arquivo, depois de esvaziar a Lixeira."
        ),
        "d_tool": (
            "Roda {cmd} só depois de você aprovar à parte; o CoreCleaner nunca executa. "
            "{size} aparentes; o ganho real é o que a ferramenta liberar."
        ),
        "d_all": (
            "{size} aparentes no total. O ganho real costuma ser bem menor (clones, hardlinks, snapshots) "
            "e só aparece depois de esvaziar a Lixeira."
        ),
        "hdr_item": "Item",
        "hdr_group": "Grupo",
        "t1": "Lixo certo",
        "t2": "Decisão rápida",
        "n1": "Em geral caches e cópias limpas: o ganho real fica perto do tamanho aparente depois de esvaziar a Lixeira.",
        "n2": "O tamanho aparente conta cada clone e hardlink: o ganho real costuma ser bem menor.",
        "overview": "Plano CoreCleaner {sha}: {n} itens, {size} aparentes podem ser oferecidos.",
        "gain": (
            "Tamanhos APARENTES (teto). Ganho real = espaço livre depois menos antes, quase sempre menor: clones "
            "APFS e hardlinks só liberam quando some a última cópia, snapshots locais seguram o apagado e a "
            "Lixeira não libera nada até ser esvaziada. Comando de ferramenta libera quando a ferramenta roda."
        ),
        "group_line": "Grupo {g}, {title}: {n} itens, {size} aparentes. {note}",
        "shown_only": "Só mostrados, nunca oferecidos para a Lixeira",
        "more": "... e mais {k}",
        "rules": (
            "Silêncio ou resposta vaga é não. Só ids com sim explícito vão para `trash`: "
            "primeiro simulação, depois --apply."
        ),
        "nothing_to_ask": "Nada a perguntar: nenhum item pode ser oferecido para a Lixeira.",
        "batch": (
            "Lote {i} de {m}. Responda como \"{ex}\" ou diga \"nada\" para parar. "
            "PARE aqui e ESPERE a resposta do usuário antes de mostrar o próximo lote."
        ),
        "table_head": "id | cat | nome | tamanho | ação | caminho",
        "reason": "motivo",
        "act_trash": "Lixeira",
        "act_archive_then_trash": "arquivar e Lixeira",
        "act_tool_command": "comando da ferramenta",
    },
}

CATEGORY_NAMES: Dict[str, Dict[str, str]] = {
    "en": {
        "A": "agent history", "B": "worktree", "C": "stray clone", "D": "generated output",
        "E": "idle node_modules", "F": "tool cache", "G": "downloaded model", "H": "raw, already processed",
        "I": "duplicate", "J": "held by the OS", "K": "forgotten process", "L": "other heavy folder",
    },
    "pt": {
        "A": "histórico de agente", "B": "worktree", "C": "clone solto", "D": "saída gerada",
        "E": "node_modules parado", "F": "cache de ferramenta", "G": "modelo baixado", "H": "bruto já processado",
        "I": "duplicata", "J": "retido pelo SO", "K": "processo esquecido", "L": "pasta pesada avulsa",
    },
}

# The plan (signed, hashed) keeps its `deny` and `reason` in English: they are fixed strings built by plan.py and
# by the safety checks it quotes. `ask --lang pt` translates them here, at display time only. Keys are the exact
# strings; a string that is not here (or whose shape changed) shows in English, never guessed.
PT_REASONS: Dict[str, str] = {
    # plan._build_item, _classify, _demote_nested
    "symlink: never trashed": "link simbólico: nunca vai para a Lixeira",
    "arrived less than 1 h ago (live state, outside the plan)": "chegou há menos de 1 h (estado vivo, fora do plano)",
    "kept: a note in the repo says this branch is local-only (never push)": "mantido: uma nota no repo diz que esta branch é só local (nunca sobe)",
    "heavy folder: listed with its size only, never trashed by this tool": "pasta pesada: só listada com o tamanho, esta ferramenta nunca a move",
    "missing": "não existe mais",
    "path contains control characters": "o caminho tem caracteres de controle",
    "tool command rejected (not a command this tool builds for that path)":
        "comando da ferramenta recusado (não é um comando que o CoreCleaner monta para esse caminho)",
    "listed only: inventory found no safe action for it (no cleanup command; pick it by hand)":
        "só listado: o inventário não achou ação segura para ele (sem comando de limpeza; escolha à mão)",
    "forgotten process: list only": "processo esquecido: só listado",
    "unknown category": "categoria desconhecida",
    "held by the OS and no cleanup command is known": "retido pelo SO e sem comando de limpeza conhecido",
    "nested inside another candidate; goes with it": "dentro de outro candidato; vai junto com ele",
    # plan._keep_deny
    "live process uses it (live state, outside the plan)": "um processo vivo o usa (estado vivo, fora do plano)",
    "modified less than 1 h ago (live state, outside the plan)": "modificado há menos de 1 h (estado vivo, fora do plano)",
    "kept by a note in agent memory, CLAUDE.md, skills or settings":
        "mantido por uma nota na memória do agente, no CLAUDE.md, nas skills ou nas configurações",
    "user data: shown only": "dado do usuário: só mostrado",
    # plan.protected_inside_reason, _unproven_deny, _keeper_of
    "too large to scan for protected names (keys, .env): not proven safe":
        "grande demais para varrer atrás de nomes protegidos (chaves, .env): segurança não provada",
    "too large to measure fully: cannot prove it idle": "grande demais para medir por inteiro: não dá para provar que está parado",
    "the search for repos inside it hit its limit: cannot prove it clean":
        "a busca por repositórios dentro dele bateu no limite: não dá para provar que está limpo",
    "could not read the whole tree: cannot prove it idle": "não foi possível ler a árvore toda: não dá para provar que está parado",
    "the copy it duplicates is gone or not a plain file: not safe to remove":
        "a cópia que ele duplica sumiu ou não é um arquivo comum: não é seguro remover",
    # plan._dependency_group (reason)
    "possibly cited: a file may build this path in code, not proven unused":
        "possivelmente citado: um arquivo pode montar este caminho no código, não está provado que não é usado",
    "dependency search incomplete: not proven unused": "busca de dependências incompleta: não está provado que não é usado",
    # safety.is_protected, is_cloud_or_placeholder, _placeholder_reason (the tail after "protected: " / "cloud or placeholder: ")
    "unusable path (empty, NUL byte or not a path)": "caminho inutilizável (vazio, byte NUL ou não é um caminho)",
    "NTFS alternate data stream or invalid name": "fluxo alternativo de dados NTFS ou nome inválido",
    "volume root": "raiz de volume",
    "volume root (mount point)": "raiz de volume (ponto de montagem)",
    "deny list": "lista de proteção",
    "synced folder": "pasta sincronizada",
    "dataless placeholder (SF_DATALESS)": "placeholder sem dados locais (SF_DATALESS)",
    "cloud placeholder (RECALL_ON_OPEN)": "placeholder de nuvem (RECALL_ON_OPEN)",
    "cloud placeholder (RECALL_ON_DATA_ACCESS)": "placeholder de nuvem (RECALL_ON_DATA_ACCESS)",
    "offline file (FILE_ATTRIBUTE_OFFLINE)": "arquivo offline (FILE_ATTRIBUTE_OFFLINE)",
    "allocated blocks far below size (placeholder, sparse or compressed file)":
        "blocos alocados muito abaixo do tamanho (placeholder, arquivo esparso ou comprimido)",
}


def _pt_rule(m: "re.Match[str]") -> str:
    """`tree ~/.ssh` (safety._reason): mode word and pattern come from never-touch.txt, kept as written."""
    return "regra %s %s%s" % (m.group(1), m.group(2), " (pai de um caminho protegido)" if m.group(3) else "")


def _pt_facts(m: "re.Match[str]") -> str:
    """plan._virtual_facts joins kind, name, `up N min`, `cwd PATH` with ", ": translate the two fixed labels."""
    facts = re.sub(r"(?<=, )up (\d+) min(?=, |$)", r"ativo há \1 min", m.group(1))
    return "não é um arquivo: só mostrado (%s)" % re.sub(r"(?<=, )cwd ", "pasta de trabalho ", facts)


def _pt_fmt(template: str, deep: bool = False):
    """Template filled with the captured groups ({0}, {1}); `deep` translates the last group too (a tail)."""

    def build(m: "re.Match[str]") -> str:
        groups = list(m.groups())
        if deep:
            groups[-1] = _to_pt(groups[-1])
        return template.format(*groups)

    return build


# Strings with a count or a name inside: (regex that must match the WHOLE string, builder). Names and counts are
# copied from the original; the first match wins.
PT_FORMATS: List[Any] = [
    (r"idle less than (\d+) days \(history, worktree or clone: kept\)",
     _pt_fmt("parado há menos de {0} dias (histórico, worktree ou clone: mantido)")),
    (r"arrived less than (\d+) days ago \(history, worktree or clone: kept\)",
     _pt_fmt("chegou há menos de {0} dias (histórico, worktree ou clone: mantido)")),
    (r"holds (\d+) file\(s\) with protected names \(keys, \.env, credentials\): move them out first",
     _pt_fmt("tem {0} arquivo(s) com nomes protegidos (chaves, .env, credenciais): tire-os de lá primeiro")),
    (r"cited by (\d+) file\(s\); its own tool rebuilds it", _pt_fmt("citado por {0} arquivo(s); a própria ferramenta o reconstrói")),
    (r"live dependency: cited by (\d+) file\(s\)", _pt_fmt("dependência viva: citado por {0} arquivo(s)")),
    (r"protected: (.*)", _pt_fmt("protegido: {0}", True)),
    (r"cloud or placeholder: (.*)", _pt_fmt("nuvem ou placeholder: {0}", True)),
    (r"safety check failed: (.*)", _pt_fmt("a checagem de segurança falhou: {0}")),
    (r"not a file: shown only \((.*)\)", _pt_facts),
    (r"cannot resolve path \((.*)\)", _pt_fmt("não foi possível resolver o caminho ({0})")),
    (r"cannot lstat \((.*)\)", _pt_fmt("não foi possível ler os metadados ({0})")),
    (r"cloud-synced folder: (.*)", _pt_fmt("pasta sincronizada na nuvem: {0}")),
    (r"(tree|node|name) (.+?)( \(parent of a protected path\))?", _pt_rule),
]
_PT_FORMATS = [(re.compile(rx, re.DOTALL), build) for rx, build in PT_FORMATS]


def _to_pt(text: str) -> str:
    if text in PT_REASONS:
        return PT_REASONS[text]
    for rx, build in _PT_FORMATS:
        m = rx.fullmatch(text)
        if m:
            return build(m)
    return text


def translate_reason(text: Any, lang: str) -> str:
    """A plan `deny` or `reason` in the asked language. English (and any string not in the table) comes back as is."""
    out = str(text)
    return _to_pt(out) if lang == "pt" else out


def _lang(value: Optional[str]) -> str:
    """--lang, else CORECLEANER_LANG, else the language recorded by `settings --lang`, else en."""
    recorded = common.read_settings().get("lang")
    text = (value or os.environ.get("CORECLEANER_LANG") or (recorded if isinstance(recorded, str) else "") or "en").lower()
    return "pt" if text.startswith("pt") else "en"


def _clean(text: Any, maxlen: int) -> str:
    """Sanitized by safety, then forced to one line without backticks (defense in depth)."""
    out = _CTRL.sub(" ", safety.sanitize_name(str(text), maxlen)).replace("`", "'")
    return out.strip() or "?"


def _code(text: str) -> str:
    return "`" + text + "`"


def _size(n: int) -> str:
    return plan_mod.size_text(n)


def _name(item: dict) -> str:
    name = item.get("display") or "?"
    if item.get("category") == "E" and str(name) == "node_modules":  # alone it says nothing: name the project
        name = os.path.basename(os.path.dirname(str(item.get("path") or ""))) + "/" + str(name)
    return _code(_clean(name, 48))


def _where(item: dict) -> str:
    return _code(_clean(plan_mod._tilde(os.path.dirname(str(item.get("path") or ""))) or "?", 80))


def _path(item: dict) -> str:
    return _code(_clean(plan_mod._tilde(item["path"]), 120))


def _age(item: dict, L: Dict[str, str]) -> str:
    ev = item.get("evidence") or {}
    days = ev.get("age_days")
    if item.get("category") == "E" and ev.get("project_idle_days") is not None:
        days = ev.get("project_idle_days")  # the project's idle time, not the install's
    return L["age"].format(d=days) if isinstance(days, int) and days > 0 else ""


def _cited(item: dict) -> int:
    n = (item.get("evidence") or {}).get("referenced_count")
    return n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 0


def _dep_note(item: dict, L: Dict[str, str]) -> str:
    """Why this item is not plain junk: files that cite it (named), or a dependency search that did not finish."""
    ev = item.get("evidence") or {}
    n = _cited(item)
    if n and item.get("reason") == plan_mod.REFILL_REASON % n:
        return L["d_refill"].format(n=n)
    if n:
        names = [x for x in (ev.get("referenced_by") or []) if isinstance(x, str)][:3]
        files = ": " + ", ".join(_code(_clean(x, 70)) for x in names) if names else ""
        return L["d_ref"].format(n=n, files=files)
    maybe = [x for x in (ev.get("referenced_maybe") or []) if isinstance(x, str)][:3]
    if maybe and ev.get("referenced_unverified") and item.get("reason"):
        return L["d_maybe"].format(files=" (" + ", ".join(_code(_clean(x, 70)) for x in maybe) + ")")
    return L["d_unv"] if ev.get("referenced_unverified") and item.get("reason") else ""


def _ignored(item: dict) -> Tuple[int, int]:
    """(files, bytes) of ignored data that moving this repo to the Trash would lose: inventory measured it."""
    git = (item.get("evidence") or {}).get("git")
    big = git.get("ignored_large") if isinstance(git, dict) else None
    count, nbytes = (big.get("count"), big.get("bytes")) if isinstance(big, dict) else (0, 0)
    ok = isinstance(count, int) and not isinstance(count, bool) and count > 0
    return (count, nbytes if isinstance(nbytes, int) and not isinstance(nbytes, bool) else 0) if ok else (0, 0)


def _ignored_note(item: dict, L: Dict[str, str]) -> str:
    count, nbytes = _ignored(item)
    return L["d_ignored"].format(n=count, size=_size(nbytes)) if count else ""


def _local_refs(item: dict) -> bool:
    """A clean repo (worktree, clone, scratch unit) goes to the Trash with no archive because its commits look
    published; inventory read that from local remote-tracking refs only (evidence.git.remote_checked is False)."""
    git = (item.get("evidence") or {}).get("git")
    return (item.get("category") in ("B", "C", "D") and item.get("action") == "trash"
            and isinstance(git, dict) and bool(git.get("is_repo")) and not git.get("remote_checked"))


def _local_note(items: List[dict], L: Dict[str, str]) -> str:
    return L["d_local"] if any(_local_refs(i) for i in items) else ""
def _tool_note(item: dict, L: Dict[str, str]) -> str:
    """What a tool command does beyond "clean the cache", keyed on the command (plan only accepts commands it knows)."""
    cmd = str(item.get("tool_command") or "")
    if cmd.startswith("brew cleanup"):
        return L["d_brew"]
    if cmd.startswith("npx --no-install"):
        return L["d_npx"]
    return ""


def _opt(label: str, desc: str, effect: str, ids: List[str], **extra: Any) -> dict:
    out = {"label": label, "description": desc, "effect": effect, "ids": ids}
    out.update(extra)
    return out


def _item_unit(item: dict, L: Dict[str, str], lang: str) -> dict:
    size = _size(item["bytes"])
    cat = CATEGORY_NAMES[lang].get(item["category"], item["category"])
    fmt = dict(name=_name(item), cat=cat, size=size, age=_age(item, L), where=_where(item))
    ids = [item["id"]]
    if item["action"] == "tool_command":
        cmd = _code(_clean(item.get("tool_command") or "?", 200))
        question = L["q_tool"].format(**fmt)
        yes = _opt(L["tool"], L["d_tool"].format(cmd=cmd, size=size) + _tool_note(item, L), "tool_command", ids)
    elif item["action"] == "archive_then_trash":
        question = L["q_arch"].format(**fmt)
        yes = _opt(L["archive_trash"], L["d_arch"].format(size=size), "archive_then_trash", ids)
    else:
        question = L["q_item"].format(**fmt)
        yes = _opt(L["trash"], L["d_trash"].format(size=size), "trash", ids)
    yes["description"] += _dep_note(item, L) + _ignored_note(item, L) + _local_note([item], L)
    keeper = item.get("keeper")
    if isinstance(keeper, dict) and isinstance(keeper.get("path"), str):  # a duplicate: say which copy stays
        yes["description"] += L["d_keeper"].format(path=_code(_clean(plan_mod._tilde(keeper["path"]), 100)))
    keep = _opt(L["keep"], L["keep_desc"], "keep", [])
    if item["group"] == 1:
        yes["label"] += " " + L["rec"]
        options = [yes, keep]
    else:
        options = [keep, yes]
    return {"kind": "item", "group": item["group"], "header": L["hdr_item"], "question": question, "options": options}


def _by_category(items: List[dict]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    for it in items:
        out.setdefault(it["category"], []).append(it)
    return out


def _collapsed(items: List[dict], group: int, expand: Optional[Set[int]]) -> Dict[str, List[dict]]:
    """Categories of `group` asked as one "all N" question: more than GROUP_THRESHOLD plain items, not expanded."""
    exp = {str(x) for x in (expand or set())}
    if str(group) in exp:
        return {}
    plain = [i for i in items if i["group"] == group and _is_plain(i)]
    return {c: its for c, its in _by_category(plain).items()
            if len(its) > GROUP_THRESHOLD and "%d/%s" % (group, c) not in exp}


def _group_unit(group: int, items: List[dict], L: Dict[str, str], lang: str = "en") -> dict:
    n = len(items)
    category = items[0]["category"]
    ages = [(i.get("evidence") or {}).get("age_days") for i in items]
    ages = [a for a in ages if isinstance(a, int) and not isinstance(a, bool)]
    age = L["age_min"].format(d=min(ages)) if ages else ""
    size = _size(sum(i["bytes"] for i in items))
    risky = any(i["action"] == "archive_then_trash" for i in items)
    ids = [i["id"] for i in items]
    all_label = L["trash_all_arch" if risky else "trash_all"].format(n=n)
    yes = _opt(all_label, L["d_all"].format(size=size) + _local_note(items, L), "archive_then_trash" if risky else "trash", ids)
    one = _opt(L["one_by_one"], L["one_by_one_desc"].format(n=n), "expand", [], expand="%d/%s" % (group, category))
    keep = _opt(L["keep_all"], L["keep_all_desc"].format(n=n), "keep", [])
    if group == 1:
        yes["label"] += " " + L["rec"]
        options = [yes, one, keep]
    else:
        options = [keep, one, yes]
    question = L["q_group"].format(g=group, title=L["t%d" % group], n=n, size=size, age=age,
                                   cat=CATEGORY_NAMES[lang].get(category, category))
    return {"kind": "group", "group": group, "header": L["hdr_group"] + " %d/%s" % (group, category),
            "question": question, "options": options}


def _is_plain(item: dict) -> bool:
    """Can join a "Trash all N" question: no tool command to approve alone, no file citing it, no ignored data lost."""
    return item["action"] != "tool_command" and not _cited(item) and not _ignored(item)[0]


def _build_units(actionable: List[dict], L: Dict[str, str], lang: str, expand: Set[int]) -> List[dict]:
    units: List[dict] = []
    for group in (1, 2):
        mine = [i for i in actionable if i["group"] == group]
        collapsed = _collapsed(mine, group, expand)
        for its in collapsed.values():
            units.append(_group_unit(group, its, L, lang))
        for item in mine:
            if not (item["category"] in collapsed and _is_plain(item)):
                units.append(_item_unit(item, L, lang))
    return units


def _room(maxlen: int, lang: str) -> int:
    return maxlen * 3 // 2 if lang == "pt" else maxlen  # the pt text of the same fixed reason is longer


def _table(items: List[dict], L: Dict[str, str], with_reason: bool, limit: Optional[int] = TABLE_ROWS,
           lang: str = "en") -> List[str]:
    rows = []
    for it in items[:limit]:
        if with_reason:
            last = _clean(translate_reason(it.get("deny") or "", lang), _room(100, lang))
        else:
            last = L.get("act_" + it["action"], it["action"])
            if it.get("reason"):
                last += "; " + _clean(translate_reason(it["reason"], lang), _room(80, lang))
        rows.append(
            "%s | %s | %s | %s | %s | %s"
            % (it["id"], it["category"], _name(it), _size(it["bytes"]), last, _path(it))
        )
    if limit is not None and len(items) > limit:
        rows.append(L["more"].format(k=len(items) - limit))
    return rows


def _overview(
    plan: dict, actionable: List[dict], shown: List[dict], L: Dict[str, str], expand: Optional[Set[int]] = None,
    lang: str = "en",
) -> List[str]:
    total = _size(sum(i["bytes"] for i in actionable))
    lines = [
        L["overview"].format(sha=str(plan.get("sha256", ""))[:12], n=len(actionable), size=total),
        L["gain"],
        "",
    ]
    for group in (1, 2):
        mine = [i for i in actionable if i["group"] == group]
        if not mine:
            continue
        size = _size(sum(i["bytes"] for i in mine))
        lines.append(L["group_line"].format(g=group, title=L["t%d" % group], n=len(mine), size=size, note=L["n%d" % group]))
        lines.append(L["table_head"])
        # "Trash all N" approves every id of the group: the table must list every one of them, so a
        # collapsed group is never cut at TABLE_ROWS. Item by item, each question names its own item.
        collapsed = bool(_collapsed(mine, group, expand))
        lines.extend(_table(mine, L, False, None if collapsed else TABLE_ROWS, lang))
        lines.append("")
    if shown:
        head = L["table_head"].split(" | ")
        lines.append(L["shown_only"])
        lines.append(" | ".join(head[:4] + [L["reason"], head[5]]))
        lines.extend(_table(shown, L, True, TABLE_ROWS, lang))
        lines.append("")
    lines.append(L["rules"])
    return lines


def _letter(i: int) -> str:
    return "abcd"[i]


def _text_batches(batches: List[List[dict]], L: Dict[str, str]) -> List[str]:
    lines: List[str] = []
    for bi, batch in enumerate(batches, 1):
        example = " ".join("%d%s" % (u["n"], _letter((k + 1) % len(u["options"]))) for k, u in enumerate(batch[:3]))
        lines.append("")
        lines.append(L["batch"].format(i=bi, m=len(batches), ex=example))
        for u in batch:
            lines.append("%d. %s" % (u["n"], u["question"]))
            for oi, o in enumerate(u["options"]):
                lines.append("   %s) %s: %s" % (_letter(oi), o["label"], o["description"]))
    return lines


def _claude_question(unit: dict) -> dict:
    return {
        "question": unit["question"],
        "header": ("%s %d" % (unit["header"], unit["n"]) if unit["kind"] == "item" else unit["header"])[:HEADER_MAX],
        "multiSelect": False,
        "options": [{"label": o["label"], "description": o["description"]} for o in unit["options"]],
    }


def render(
    plan: dict,
    fmt: str,
    expand: Optional[Set[int]] = None,
    lang: str = "en",
    plan_file: Optional[str] = None,
) -> dict:
    if fmt not in FORMATS:
        raise common.CorecleanerError(common.EXIT_USAGE, "format must be one of: " + ", ".join(FORMATS))
    lang = _lang(lang)
    L = STR[lang]
    items = plan.get("items", [])
    actionable = [i for i in items if i["group"] in (1, 2) and i["action"] != "list_only"]
    offered = {i["id"] for i in actionable}
    shown = [i for i in items if i["id"] not in offered]
    units = _build_units(actionable, L, lang, set(expand or ()))
    for n, unit in enumerate(units, 1):
        unit["n"] = n
    batches = [units[k : k + BATCH_SIZE] for k in range(0, len(units), BATCH_SIZE)]
    lines = _overview(plan, actionable, shown, L, set(expand or ()), lang)
    if not units:
        lines.append(L["nothing_to_ask"])
    if fmt != "claude":
        lines.extend(_text_batches(batches, L))
    answer_map = [
        {
            "n": u["n"],
            "group": u["group"],
            "options": [
                {"letter": _letter(i), **{k: v for k, v in o.items() if k != "description"}}
                for i, o in enumerate(u["options"])
            ],
        }
        for u in units
    ]
    batch_questions = [[_claude_question(u) for u in b] for b in batches] if fmt == "claude" else None
    return {
        "format": fmt,
        "text": "\n".join(lines),
        "questions": (batch_questions[0] if batch_questions else []) if fmt == "claude" else None,
        "batches": len(batches),
        "batch_questions": batch_questions,
        "answer_map": answer_map,
        "plan_file": plan_file,
    }


def _parse_expand(value: Any) -> Set[str]:
    """`1`, `2` (a whole group) or `2/I` (one category of one group), comma-separated."""
    if value is None:
        return set()
    parts = value if isinstance(value, (list, tuple, set)) else str(value).split(",")
    out: Set[str] = set()
    for part in parts:
        text = str(part).strip()
        if text in ("1", "2") or re.fullmatch(r"[12]/[A-L]", text):
            out.add(text)
        elif text:
            raise common.CorecleanerError(common.EXIT_USAGE, "expand takes group numbers 1 and/or 2, or group/category like 2/I")
    return out


def run(args) -> dict:
    plan = plan_mod.load_plan(args.plan)
    reply = getattr(args, "reply", None)
    if reply is not None:  # the text the user pasted from the report: map it to ids, never act on it here
        return {"reply": read_reply(plan, reply), "plan_file": str(args.plan)}
    return render(
        plan,
        getattr(args, "format", None) or "text",
        expand=_parse_expand(getattr(args, "expand", None)),
        lang=_lang(getattr(args, "lang", None)),
        plan_file=args.plan,
    )


# ---------------------------------------------------------------- the reply pasted from the report

_REPLY_LABELS = {
    "trash": ("trash", "lixeira"),
    "archive_then_trash": ("archive and trash", "arquivar e lixeira"),
    "tool_command": ("tool command", "comando da ferramenta"),
}
_REPLY_HEAD = re.compile(r"^\s*corecleaner\s+(?:plan|plano)\s+([0-9a-f]{6,64})\s*$", re.I)
_ID = re.compile(r"^c[0-9a-z]{3,20}$")


def read_reply(plan: dict, text: str) -> dict:
    """The text the report's "Copy reply" button builds, checked against the plan.

    Returns {"plan_matches", "trash", "archive_then_trash", "tool_command", "problems"}. An id lands in a list only
    when the plan has it in group 1 or 2 with that same action; anything else is a problem, never a guess."""
    out: Dict[str, Any] = {"plan_matches": False, "trash": [], "archive_then_trash": [], "tool_command": [], "problems": []}
    by_id = {it.get("id"): it for it in plan.get("items", []) if isinstance(it, dict)}
    sha = str(plan.get("sha256", ""))
    for raw in str(text).splitlines():
        line = raw.strip()
        if not line:
            continue
        head = _REPLY_HEAD.match(line)
        if head:
            out["plan_matches"] = sha.startswith(head.group(1).lower())
            continue
        label, _, rest = line.partition(":")
        action = next((a for a, names in _REPLY_LABELS.items() if label.strip().lower() in names), None)
        if action is None:
            out["problems"].append("line not understood: " + _clean(line, 80))
            continue
        for tok in rest.replace(",", " ").split():
            it = by_id.get(tok)
            if not _ID.match(tok) or it is None:
                out["problems"].append("not in this plan: " + _clean(tok, 40))
            elif it.get("group") not in (1, 2) or it.get("deny"):
                out["problems"].append("not offered: " + _clean(tok, 40))
            elif it.get("action") != action:
                out["problems"].append("%s is %s in the plan, not %s" % (tok, it.get("action"), action))
            elif tok not in out[action]:
                out[action].append(tok)
    if not out["plan_matches"]:
        out["problems"].insert(0, "the reply names another plan (or none): build ids from this plan only")
    return out
