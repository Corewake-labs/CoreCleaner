"""Offline HTML report: the plan's junk by folder, plus the disk treemap. (T9; subcommand `report`)

Writes only state_subdir("reports")/report-<file_stamp>.html (mode 0o600, never overwrites). One
self-contained page: squarified treemap in vanilla JS, zero network (no external script, font,
image or fetch), CSP by hash (`default-src 'none'`), all dynamic text via textContent, never
innerHTML. Works from 360 px up; dark/light by prefers-color-scheme.

run(args): args.scan (file with a saved `scan` JSON result), args.plan (file | None, checked by
  plan.load_plan). Returns {"report": str (path), "bytes": int}.

render_html(scan, plan, lang) -> str     (pure: no file or network access; lang en|pt picks the L strings)
  scan keys read: tree (required), gap, top, tool, exact, label, ts, free_bytes, total_bytes.
  gap keys read (all optional): bytes | unexplained_bytes | used_bytes (gap = used - tree), free_bytes, total_bytes,
  unreadable (count). Plan items are matched to tree nodes by realpath: an exact match colours the
  block by plan group (1 sure junk, 2 decision, 3 user data, protected/denied = system); a
  folder that merely contains plan items gets a ring. Plan items deeper than the scan depth, or
  outside the scanned roots, are reachable from the "Plan" list.
  Names/paths are DATA: the JSON is embedded in <script type="application/json"> with `<`, `>`,
  `&` and `://` escaped, and the page only ever sets textContent, so a hostile file name stays text.
  Basic-mode scans (tool "basic" or exact false) carry the "apparent (upper bound)" banner.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import ask as _ask
from . import plan as _plan
from .common import (
    EXIT_ERROR,
    EXIT_USAGE,
    CorecleanerError,
    file_stamp,
    log,
    now_iso,
    state_subdir,
)

MAX_CHILDREN = 200  # per folder; the rest becomes one "(N smaller items)" block
MAX_DEPTH = 32
NAME_MAX = 160
PATH_MAX = 2048

# Class codes shared with the page script: 0 not in plan, 1 sure junk, 2 decision, 3 user data,
# 4 system / protected / not actionable.
CLASS_SYS = 4

CATEGORIES = _ask.CATEGORY_NAMES["en"]  # per-language names come from ask.CATEGORY_NAMES
JUNK_EXPAND_LIMIT = 200  # the page opens every folder up to this many visible items

BASIC_BANNER = (
    "Basic mode (dua not installed): sizes are apparent (upper bound). "
    "APFS clones may look larger than they are, so the space you get back can be lower."
)
WINDOWS_BANNER = "Windows support is BETA and untested."

# Bidi controls and line/paragraph separators let a file name impersonate another one.
_SPOOF = frozenset(
    [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF] + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
)

SECTIONS: Dict[str, Dict[str, Any]] = {'en': {'F': ('Tool caches', 'Downloads that npm, Go, Homebrew and others keep to go faster.', 'The tool downloads again whatever it needs.'), 'E': ('node_modules of idle projects', 'Installed dependencies of projects with no edit for 30 days or more.', 'When you come back to the project, npm ci or bun install puts them back.'), 'C': ('Forgotten clones', 'Repositories an agent cloned to look at and left behind.', 'Unsaved work is archived before the folder goes.'), 'B': ('Agent worktrees', 'Working copies of a repo made for one task.', 'Unsaved work is archived before the folder goes.'), 'D': ('Agent scratch', 'Temporary folders of sessions that are over.', 'The scratch goes; no project changes.'), 'G': ('Downloaded models', 'AI models downloaded by a tool.', 'The tool downloads the model again when it needs it.'), 'I': ('Repeated files in Downloads', 'Identical copies of a file that stays.', 'The other copy stays.'), 'A': ('Old agent conversations', 'Claude and Codex session history idle for 45 days or more.', "That conversation's history goes; your projects do not change.")}, 'pt': {'F': ('Caches de ferramentas', 'Downloads que npm, Go, Homebrew e afins guardam para ir mais rápido.', 'A ferramenta baixa de novo o que precisar.'), 'E': ('node_modules de projetos parados', 'Dependências instaladas em projetos sem edição há 30 dias ou mais.', 'Quando voltar ao projeto, um npm ci ou bun install reinstala.'), 'C': ('Clones esquecidos', 'Repositórios que um agente clonou para consulta e ficaram para trás.', 'Trabalho não salvo é arquivado antes de a pasta sair.'), 'B': ('Worktrees de agentes', 'Cópias de trabalho de um repositório feitas para uma tarefa.', 'Trabalho não salvo é arquivado antes de a pasta sair.'), 'D': ('Rascunhos de agentes', 'Pastas temporárias de sessões que já acabaram.', 'Sai o rascunho; nenhum projeto muda.'), 'G': ('Modelos baixados', 'Modelos de IA que uma ferramenta baixou.', 'A ferramenta baixa o modelo de novo quando precisar.'), 'I': ('Arquivos repetidos em Downloads', 'Cópias idênticas de um arquivo que continua lá.', 'A outra cópia fica.'), 'A': ('Conversas antigas de agentes', 'Histórico de sessões do Claude e do Codex paradas há 45 dias ou mais.', 'Some o histórico daquela conversa; seus projetos não mudam.')}}

STRINGS: Dict[str, Dict[str, str]] = {  # every page text; pt keeps its diacritics (the data block is ASCII-escaped)
    'en': {
        'tab_choose': 'Choose what to clean',
        'tab_junk': 'By folder',
        'hero': 'You can free up to {size} ({n} items)',
        'hero_sub': 'Tick what may go, then copy the reply and paste it to the agent. Nothing moves until you paste it and confirm the dry run. What goes to the Trash can be undone until you empty it.',
        'rec': 'Recommended',
        'sel_rec': 'Only the recommended',
        'sel_none': 'Untick all',
        'sel_all_sec': 'Tick all',
        'selected': '{n} selected · {size}',
        'nothing_sel': 'Nothing ticked yet',
        'copy_reply': 'Copy reply',
        'copied_reply': "Copied: paste it in the agent's chat",
        'paste_hint': 'Paste this text in the chat. The agent first shows a dry run of exactly these ids; nothing moves before your OK.',
        'reply_head': 'CoreCleaner plan {sha}',
        'r_trash': 'Trash',
        'r_arch': 'Archive and Trash',
        'r_tool': 'Tool command',
        'sec_sum': '{n} · {size}',
        'show_more': 'Show {n} more',
        'in_folder': 'in {w}',
        'a_arch': 'has unsaved work: a copy is archived first',
        'a_tool': "cleaned by the tool's own command (no Trash, no undo)",
        'keeps': 'the copy in {p} stays',
        'kept_head': 'Left alone: {n} items ({size})',
        'kept_sub': 'Protected, in use right now, or your data. They stay where they are.',
        'title': 'CoreCleaner: where the junk is',
        'sub': 'Scan {ts} with {tool} ({exact}). Generated {gen}. Offline: nothing leaves this file.',
        'exact': 'exact sizes',
        'upper': 'upper-bound sizes',
        'lead_junk': "Every item the plan found, under the folder that holds it. Open a folder to walk down; open an item for its path, id and reason. Nothing moves without your yes: answer the agent's questions by id.",
        'lead_map': 'Where the space went. No plan was loaded, so no item is marked as junk yet.',
        'tab_junk': 'Junk by folder',
        'tab_map': 'Disk map',
        'cls0': 'Not in the plan',
        'cls1': 'Sure junk',
        'cls2': 'Needs a decision',
        'cls3': 'Shown only: your data',
        'cls4': 'Shown only: protected or live',
        'act_trash': 'Trash',
        'act_archive': 'Archive, then Trash',
        'act_tool': "The tool's own command",
        'act_list': 'List only',
        'free': 'Free',
        'of_total': 'of {t}',
        'read': 'Read (real)',
        'apparent': 'Apparent',
        'real_pct': 'real is {p}% of apparent',
        'sum_sizes': 'sum of file sizes',
        'gap': 'GAP',
        'gap_sub': 'not explained',
        'unreadable': '{n} unreadable paths',
        'show': 'Show:',
        'categories': 'Categories:',
        'search': 'Search by path',
        'expand': 'Expand all',
        'collapse': 'Collapse all',
        'item': 'item',
        'items': 'items',
        'apparent_note': 'apparent (upper bound)',
        'none': 'No item matches the filters.',
        'age': 'idle {d} days',
        'age_k': 'Age',
        'cited': 'cited by {n} file(s)',
        'cited_by': 'Cited by',
        'path': 'Path',
        'id': 'Id',
        'group': 'Group',
        'category': 'Category',
        'action': 'Action',
        'why': 'Why',
        'copy': 'Copy path',
        'copied': 'Copied',
        'ring': '(a ring marks a folder that contains plan items)',
        'no_plan': 'Folders and files (no plan loaded)',
        'gap_legend': 'GAP: space the scan cannot explain',
        'gap_block': 'GAP (not explained)',
        'trash_note': 'Moving to the Trash frees no space until the Trash is emptied.',
        'all_roots': 'All roots',
        'nothing_draw': 'Nothing to draw here.',
        'nothing_here': 'Nothing here.',
        'more_not_listed': '{n} more not listed.',
        't_folder': 'This folder',
        't_top': 'Largest',
        't_plan': 'Plan',
        'size': 'Size',
        'what': 'What',
        'size_disk': 'Size on disk',
        'of_parent': '{p}% of the parent',
        'plan': 'Plan',
        'contains': 'Contains',
        'items_k': 'Items',
        'open_folder': 'Open folder',
        'what_gap': 'Used space of the volume minus everything the scan could read: local snapshots, purgeable space, swap, other users, unreadable folders. macOS manages snapshots and purgeable space on its own and frees them when space is needed. Never hidden, never removed by this tool.',
        'what_more': 'Many small items grouped together.',
        'basic': 'Basic mode (dua not installed): sizes are apparent (upper bound). APFS clones may look larger than they are, so the space you get back can be lower.',
        'windows': 'Windows support is BETA and untested.',
        'at_report': 'at report time',
        'shown': 'Shown only',
    },
    'pt': {
        'tab_choose': 'Escolher o que limpar',
        'tab_junk': 'Por pasta',
        'hero': 'Dá para liberar até {size} ({n} itens)',
        'hero_sub': 'Marque o que pode sair, copie a resposta e cole no chat do agente. Nada sai do lugar até você colar e confirmar a simulação. O que vai para a Lixeira volta enquanto ela não for esvaziada.',
        'rec': 'Recomendado',
        'sel_rec': 'Só os recomendados',
        'sel_none': 'Desmarcar tudo',
        'sel_all_sec': 'Marcar todos',
        'selected': '{n} marcados · {size}',
        'nothing_sel': 'Nada marcado ainda',
        'copy_reply': 'Copiar resposta',
        'copied_reply': 'Copiado: cole no chat do agente',
        'paste_hint': 'Cole este texto no chat. O agente primeiro mostra a simulação só destes ids; nada sai antes do seu OK.',
        'reply_head': 'CoreCleaner plano {sha}',
        'r_trash': 'Lixeira',
        'r_arch': 'Arquivar e Lixeira',
        'r_tool': 'Comando da ferramenta',
        'sec_sum': '{n} · {size}',
        'show_more': 'Mostrar mais {n}',
        'in_folder': 'em {w}',
        'a_arch': 'tem trabalho não salvo: guardamos uma cópia antes',
        'a_tool': 'limpo pelo comando da própria ferramenta (não passa pela Lixeira, não volta)',
        'keeps': 'fica a cópia em {p}',
        'kept_head': 'Não vamos mexer: {n} itens ({size})',
        'kept_sub': 'Protegidos, em uso agora ou dados seus. Ficam onde estão.',
        'title': 'CoreCleaner: onde está o lixo',
        'sub': 'Scan {ts} com {tool} ({exact}). Gerado {gen}. Offline: nada sai deste arquivo.',
        'exact': 'tamanhos exatos',
        'upper': 'tamanhos de teto',
        'lead_junk': 'Cada item que o plano achou, dentro da pasta que o guarda. Abra uma pasta para descer; abra um item para ver caminho, id e motivo. Nada sai sem o seu sim: responda às perguntas do agente pelo id.',
        'lead_map': 'Onde foi o espaço. Nenhum plano foi carregado, então nenhum item está marcado como lixo ainda.',
        'tab_junk': 'Lixo por pasta',
        'tab_map': 'Mapa do disco',
        'cls0': 'Fora do plano',
        'cls1': 'Lixo certo',
        'cls2': 'Decisão rápida',
        'cls3': 'Só mostrado: dado seu',
        'cls4': 'Só mostrado: protegido ou vivo',
        'act_trash': 'Lixeira',
        'act_archive': 'Arquivar e Lixeira',
        'act_tool': 'Comando da própria ferramenta',
        'act_list': 'Só listar',
        'free': 'Livre',
        'of_total': 'de {t}',
        'read': 'Lido (real)',
        'apparent': 'Aparente',
        'real_pct': 'real é {p}% do aparente',
        'sum_sizes': 'soma dos tamanhos',
        'gap': 'LACUNA',
        'gap_sub': 'não explicado',
        'unreadable': '{n} caminhos ilegíveis',
        'show': 'Mostrar:',
        'categories': 'Categorias:',
        'search': 'Buscar no caminho',
        'expand': 'Expandir tudo',
        'collapse': 'Recolher tudo',
        'item': 'item',
        'items': 'itens',
        'apparent_note': 'aparentes (teto)',
        'none': 'Nenhum item passa nos filtros.',
        'age': 'parado há {d} dias',
        'age_k': 'Idade',
        'cited': 'citado por {n} arquivo(s)',
        'cited_by': 'Citado por',
        'path': 'Caminho',
        'id': 'Id',
        'group': 'Grupo',
        'category': 'Categoria',
        'action': 'Ação',
        'why': 'Por quê',
        'copy': 'Copiar caminho',
        'copied': 'Copiado',
        'ring': '(um anel marca uma pasta que contém itens do plano)',
        'no_plan': 'Pastas e arquivos (sem plano carregado)',
        'gap_legend': 'LACUNA: espaço que o scan não explica',
        'gap_block': 'LACUNA (não explicado)',
        'trash_note': 'Mover para a Lixeira não libera espaço até ela ser esvaziada.',
        'all_roots': 'Todas as raízes',
        'nothing_draw': 'Nada para desenhar aqui.',
        'nothing_here': 'Nada aqui.',
        'more_not_listed': 'Mais {n} não listados.',
        't_folder': 'Esta pasta',
        't_top': 'Maiores',
        't_plan': 'Plano',
        'size': 'Tamanho',
        'what': 'O que é',
        'size_disk': 'Tamanho em disco',
        'of_parent': '{p}% do pai',
        'plan': 'Plano',
        'contains': 'Contém',
        'items_k': 'Itens',
        'open_folder': 'Abrir pasta',
        'what_gap': 'Espaço usado do volume menos tudo que o scan conseguiu ler: snapshots locais, espaço purgável, swap, outros usuários, pastas ilegíveis. O macOS cuida sozinho dos snapshots e do espaço purgável e os libera quando falta espaço. Nunca escondido, nunca removido por esta ferramenta.',
        'what_more': 'Muitos itens pequenos agrupados.',
        'basic': 'Modo básico (dua não instalado): os tamanhos são aparentes (teto). Clones APFS podem parecer maiores do que são, então o espaço recuperado pode ser menor.',
        'windows': 'Suporte a Windows é BETA e não testado.',
        'at_report': 'na hora do relatório',
        'shown': 'Só mostrado',
    },
}


_CSS = r"""[hidden]{display:none!important}
.hero{margin:12px 0 4px;padding:14px 16px;background:var(--card);border:1px solid var(--line);border-radius:10px}
.hero .big{font-size:22px;font-weight:700;text-wrap:balance}
.hero p{margin:6px 0 0;color:var(--mut);text-wrap:pretty}
.secs{display:grid;gap:12px;margin:12px 0 140px}
.sec{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.sech{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:2px 10px;align-items:start}
.sech h3{margin:0;font-size:16px}
.sech .ss{font-weight:650;white-space:nowrap}
.sech .sd{grid-column:2/-1;color:var(--mut);font-size:13px;text-wrap:pretty}
.sech .se{grid-column:2/-1;font-size:13px;text-wrap:pretty}
.crows{list-style:none;margin:8px 0 0;padding:0;display:grid;gap:2px}
.crow{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:0 10px;align-items:center;padding:6px 6px;border-radius:6px;cursor:pointer}
.crow:hover{background:var(--soft)}
.crow .cn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.crow .cw{grid-column:2/3;color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.crow .cz{white-space:nowrap;font-variant-numeric:tabular-nums}
.crow .cx{grid-column:2/-1;font-size:12px;color:var(--mut)}
.rec{display:inline-block;margin-left:6px;padding:0 6px;border-radius:999px;background:var(--c1);color:#fff;font-size:11px;vertical-align:1px}
.warn{color:var(--c2)}
input[type=checkbox]{width:18px;height:18px;margin:0;accent-color:var(--c1)}
.more2{margin-top:6px;background:none;border:0;color:var(--mut);cursor:pointer;text-decoration:underline;padding:2px 0}
details.kept{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
details.kept summary{cursor:pointer;font-weight:650}
details.kept ul{list-style:none;margin:8px 0 0;padding:0;display:grid;gap:4px;font-size:13px}
details.kept li{color:var(--mut);overflow-wrap:anywhere}
.pick{position:fixed;left:0;right:0;bottom:0;background:var(--card);border-top:1px solid var(--line);box-shadow:0 -4px 16px rgba(0,0,0,.12);z-index:5}
.pick .in2w{max-width:1200px;margin:0 auto;padding:10px 16px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 12px;align-items:center}
.pick .pt{font-weight:700}
.pick .pb{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.pick .go{padding:7px 14px;border-radius:6px;border:0;background:var(--c1);color:#fff;font-weight:650;cursor:pointer}
.pick .go[disabled]{opacity:.5;cursor:default}
.pick textarea{grid-column:1/-1;width:100%;font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px;resize:vertical}
.pick .pm{grid-column:1/-1;color:var(--mut);font-size:12px;margin:0}
@media (max-width:640px){.pick .in2w{grid-template-columns:minmax(0,1fr)}.pick .pb{justify-content:flex-start}}

:root{color-scheme:light dark;--bg:#f3f5f8;--fg:#161a20;--mut:#566070;--card:#fff;--line:#d3d9e1;
--c1:#217a50;--c2:#8f5c06;--c3:#2f64b8;--cs:#596373;--cn:#e4e8ee;--gapa:#cfd5de;--gapb:#e9edf2;--soft:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e8ecf1;--mut:#9aa5b4;--card:#171c23;
--line:#2b333e;--cn:#222a34;--gapa:#2a323d;--gapb:#1d242d;--soft:#1d242d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:12px 16px 32px}
h1{font-size:18px;margin:0 0 2px;text-wrap:balance}
h2{font-size:15px;margin:0 0 6px;overflow-wrap:anywhere}
.sub{color:var(--mut);margin:0 0 8px;overflow-wrap:anywhere;text-wrap:pretty}
.banner{margin:6px 0;padding:8px 10px;border:1px solid var(--c2);border-left-width:4px;border-radius:6px;background:var(--card)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:10px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;min-width:0;border-top-width:3px}
.card.k1{border-top-color:var(--c1)}.card.k2{border-top-color:var(--c2)}.card.k3{border-top-color:var(--cs)}
.card .k{color:var(--mut);font-size:12px}
.card .v{font-size:18px;font-weight:650}
.card .s{color:var(--mut);font-size:12px;overflow-wrap:anywhere}
button{font:inherit;color:inherit}
.tabs{display:flex;gap:4px;margin:10px 0 8px;flex-wrap:wrap}
.tab{padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card);cursor:pointer}
.tab[aria-pressed=true]{background:var(--fg);color:var(--bg)}
.note{color:var(--mut);font-size:12px;margin:8px 0;text-wrap:pretty}
.lead{margin:4px 0 10px;text-wrap:pretty}
.fgroup{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0}
.fl{color:var(--mut);font-size:12px;margin-right:2px}
.chipb{padding:3px 9px;border:1px solid var(--line);border-radius:999px;background:var(--card);cursor:pointer;color:var(--mut);font-size:12px}
.chipb.on{color:var(--fg);border-color:var(--fg)}
.chipb.on.g1{background:var(--c1);color:#fff;border-color:var(--c1)}
.chipb.on.g2{background:var(--c2);color:#fff;border-color:var(--c2)}
.chipb.on.g3,.chipb.on.gs{background:var(--cs);color:#fff;border-color:var(--cs)}
.srch{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:5px 8px;min-width:220px;flex:1 1 220px}
.act{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);cursor:pointer}
#jsum{font-weight:650;margin:10px 0 4px}
#tree,#tree ul{list-style:none;margin:0;padding:0}
#tree ul.kids{margin-left:18px;border-left:1px solid var(--line);padding-left:6px}
.frow,.irow{width:100%;display:grid;align-items:center;gap:2px 8px;text-align:left;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);cursor:pointer;position:relative;overflow:hidden;margin:3px 0}
.frow{grid-template-columns:14px minmax(0,1fr) auto auto}
.irow{grid-template-columns:12px minmax(0,1fr) auto auto}
.frow:hover,.irow:hover{background:var(--soft)}
.car{color:var(--mut);font-size:12px}
.fn{font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fs{display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end}
.bd{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;color:#fff;white-space:nowrap}
.bd.g1{background:var(--c1)}.bd.g2{background:var(--c2)}.bd.g3,.bd.gs{background:var(--cs)}
.fb,.ib{color:var(--mut);white-space:nowrap;font-variant-numeric:tabular-nums}
.bar{grid-column:1/-1;height:3px;background:var(--cs);border-radius:2px;opacity:.45}
.in{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ic{color:var(--mut);font-size:12px;white-space:nowrap}
.im{grid-column:2/-1;color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip{display:inline-block;width:12px;height:12px;border-radius:3px;flex:none;border:1px solid var(--line)}
.chip.gap{background:repeating-linear-gradient(45deg,var(--gapa),var(--gapa) 3px,var(--gapb) 3px,var(--gapb) 6px)}
.idet{margin:0 0 6px 20px;padding:8px 10px;background:var(--soft);border:1px solid var(--line);border-radius:6px}
dl{margin:0;display:grid;grid-template-columns:max-content minmax(0,1fr);gap:2px 10px}
dt{color:var(--mut)}
dd{margin:0;overflow-wrap:anywhere}
code{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.empty{padding:16px;color:var(--mut)}
@media (max-width:640px){.frow{grid-template-columns:14px minmax(0,1fr) auto}.fs{grid-column:2/-1;justify-content:flex-start}.irow{grid-template-columns:12px minmax(0,1fr) auto}.ic{grid-column:2/-1}}
nav ol{list-style:none;margin:8px 0;padding:0;display:flex;flex-wrap:nowrap;overflow-x:auto;gap:0}
nav li{flex:none;display:flex;align-items:center}
nav li+li::before{content:"/";color:var(--mut);padding:0 2px}
.crumb{background:none;border:0;padding:4px 6px;border-radius:6px;cursor:pointer;max-width:16em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-decoration:underline}
.crumb[aria-current]{text-decoration:none;font-weight:650;cursor:default}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:16px;align-items:start}
@media (max-width:860px){.layout{grid-template-columns:minmax(0,1fr)}}
.map{position:relative;width:100%;aspect-ratio:3/2;min-height:260px;max-height:72vh;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.map:focus{outline:none}
.blk{position:absolute;margin:0;padding:4px 6px;border:1px solid var(--bg);border-radius:0;font-size:12px;line-height:1.25;text-align:left;overflow:hidden;cursor:pointer;display:flex;flex-direction:column;align-items:flex-start;justify-content:flex-start}
.blk:hover{filter:brightness(1.1)}
.blk:focus-visible,.blk.sel{outline:3px solid var(--fg);outline-offset:-3px;z-index:2}
.blk .nm{font-weight:600;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.blk .sz{opacity:.85;white-space:nowrap}
.g0{background:var(--cn);color:var(--fg)}
.g1{background:var(--c1);color:#fff}
.g2{background:var(--c2);color:#fff}
.g3{background:var(--c3);color:#fff}
.gs{background:var(--cs);color:#fff}
.in1{box-shadow:inset 0 0 0 3px var(--c1)}
.in2{box-shadow:inset 0 0 0 3px var(--c2)}
.in3{box-shadow:inset 0 0 0 3px var(--c3)}
.in4{box-shadow:inset 0 0 0 3px var(--cs)}
.blk.gap{cursor:default;background:repeating-linear-gradient(45deg,var(--gapa),var(--gapa) 6px,var(--gapb) 6px,var(--gapb) 12px);color:var(--fg)}
.blk.gap .nm{background:var(--card);padding:0 4px;border-radius:3px}
.blk.more{cursor:default;background:var(--cn);color:var(--mut)}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;margin:8px 0;padding:0;list-style:none;color:var(--mut);font-size:12px}
.legend li{display:flex;align-items:center;gap:6px}
#det{margin-top:12px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;min-width:0}
#list{list-style:none;margin:0;padding:0;display:grid;gap:4px}
.row{width:100%;display:grid;grid-template-columns:12px minmax(0,1fr) auto;gap:2px 8px;align-items:center;text-align:left;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);cursor:pointer;position:relative;overflow:hidden}
.row .rn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .rs{color:var(--mut);white-space:nowrap}
.row .rm{grid-column:2/4;color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .bar{grid-column:1/4}
"""

# Pure helpers (fmt, squarify) sit between the markers so the tests can run them under node.
_JS = r"""'use strict';
/* --- pure --- */
var UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
function fmt(n) {
  if (typeof n !== 'number' || !isFinite(n) || n < 0) return '?';
  var i = 0;
  while (n >= 1024 && i < UNITS.length - 1) { n /= 1024; i++; }
  if (i === 0) return Math.round(n) + ' B';
  return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + ' ' + UNITS[i];
}
function worst(areas, from, to, sum, side) {
  var mx = areas[from], mn = areas[to - 1], s2 = side * side, r2 = sum * sum;
  return Math.max(s2 * mx / r2, r2 / (s2 * mn));
}
function squarify(vals, x, y, w, h) {
  var n = vals.length, out = [], total = 0, areas = [], i, j, p, rw, rh;
  for (i = 0; i < n; i++) total += vals[i];
  if (!(total > 0) || !(w > 0) || !(h > 0)) return out;
  for (i = 0; i < n; i++) areas.push(vals[i] * (w * h) / total);
  i = 0;
  while (i < n) {
    if (w < 1e-9 || h < 1e-9) break;
    var side = Math.min(w, h), end = i + 1, sum = areas[i], best = worst(areas, i, end, sum, side);
    while (end < n) {
      var cand = worst(areas, i, end + 1, sum + areas[end], side);
      if (cand > best) break;
      sum += areas[end]; end++; best = cand;
    }
    var rest = end >= n, cum = 0, q;
    if (w >= h) {
      rw = rest ? w : sum / h; p = y;
      for (j = i; j < end; j++) {
        cum += areas[j]; q = j === end - 1 ? y + h : y + h * cum / sum;
        out[j] = {x: x, y: p, w: rw, h: q - p}; p = q;
      }
      x += rw; w -= rw;
    } else {
      rh = rest ? h : sum / w; p = x;
      for (j = i; j < end; j++) {
        cum += areas[j]; q = j === end - 1 ? x + w : x + w * cum / sum;
        out[j] = {x: p, y: y, w: q - p, h: rh}; p = q;
      }
      y += rh; h -= rh;
    }
    i = end;
  }
  return out;
}
/* --- end pure --- */
(function () {
  var D = JSON.parse(document.getElementById('cdata').textContent);
  var T = D.totals, M = D.meta, L = D.L, J = D.junk;
  var CLS = ['g0', 'g1', 'g2', 'g3', 'gs'];
  var CLSNAME = [L.cls0, L.cls1, L.cls2, L.cls3, L.cls4];
  var ACT = {trash: L.act_trash, archive_then_trash: L.act_archive, tool_command: L.act_tool, list_only: L.act_list};
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function btn(cls, text, fn) {
    var b = el('button', cls, text);
    b.type = 'button';
    b.addEventListener('click', fn);
    return b;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
  function pct(a, b) { return b > 0 ? Math.round(a * 100 / b) : 0; }
  function tpl(s, vars) { return s.replace(/\{(\w+)\}/g, function (m, k) { return k in vars ? String(vars[k]) : m; }); }
  function catName(c) { return D.cats[c] ? D.cats[c] : c; }
  function kvInto(dl, k, v, mono) {
    dl.appendChild(el('dt', null, k));
    var dd = el('dd');
    dd.appendChild(mono ? el('code', null, v) : document.createTextNode(String(v)));
    dl.appendChild(dd);
  }

  /* ---------------- junk by folder ---------------- */
  var show = {1: true, 2: true, 3: false, 4: false};
  var cats = {}, query = '', open = {}, openItem = null, expandAll = null;
  if (J) Object.keys(J.cats).forEach(function (c) { cats[c] = true; });

  function itemOk(it) {
    if (!show[it.k] || cats[it.cat] === false) return false;
    if (query && it.p.toLowerCase().indexOf(query) < 0 && it.n.toLowerCase().indexOf(query) < 0) return false;
    return true;
  }
  function tally(node) {
    var t = {n: 0, b: 0, cnt: [0, 0, 0, 0]};
    node.it.forEach(function (it) { if (itemOk(it)) { t.n++; t.b += it.b; t.cnt[it.k - 1]++; } });
    node.c.forEach(function (k) {
      var s = tally(k);
      t.n += s.n; t.b += s.b;
      for (var i = 0; i < 4; i++) t.cnt[i] += s.cnt[i];
    });
    node.t = t;
    return t;
  }
  function isOpen(node, depth) {
    if (Object.prototype.hasOwnProperty.call(open, node.p)) return open[node.p];
    if (expandAll !== null) return expandAll;
    return J.root.t.n <= 200 || depth < 2;
  }
  function folderRow(node, depth, max) {
    var t = node.t, li = el('li', 'fold'), on = isOpen(node, depth);
    var b = btn('frow', null, function () { open[node.p] = !isOpen(node, depth); drawTree(); });
    b.setAttribute('aria-expanded', String(on));
    b.title = node.p;
    b.appendChild(el('span', 'car', on ? '\u25BE' : '\u25B8'));
    b.appendChild(el('span', 'fn', node.n));
    var sum = el('span', 'fs');
    for (var k = 1; k <= 4; k++) if (t.cnt[k - 1]) sum.appendChild(el('span', 'bd ' + CLS[k], t.cnt[k - 1] + ' ' + CLSNAME[k]));
    b.appendChild(sum);
    b.appendChild(el('span', 'fb', fmt(t.b)));
    var bar = el('span', 'bar');
    bar.style.width = (max > 0 ? Math.max(1, Math.round(t.b * 100 / max)) : 0) + '%';
    b.appendChild(bar);
    li.appendChild(b);
    if (on) {
      var ul = el('ul', 'kids');
      node.c.forEach(function (k) { if (k.t.n) ul.appendChild(folderRow(k, depth + 1, max)); });
      node.it.forEach(function (it) { if (itemOk(it)) ul.appendChild(itemRow(it)); });
      li.appendChild(ul);
    }
    return li;
  }
  function itemRow(it) {
    var li = el('li', 'item');
    var b = btn('irow', null, function () { openItem = openItem === it ? null : it; drawTree(); });
    b.setAttribute('aria-expanded', String(openItem === it));
    b.title = it.p;
    b.appendChild(el('span', 'chip ' + CLS[it.k]));
    b.appendChild(el('span', 'in', it.n));
    b.appendChild(el('span', 'ic', catName(it.cat)));
    b.appendChild(el('span', 'ib', fmt(it.b)));
    var meta = [CLSNAME[it.k]];
    if (it.age) meta.push(tpl(L.age, {d: it.age}));
    if (it.deny) meta.push(it.deny); else if (it.reason) meta.push(it.reason); else if (it.cited) meta.push(tpl(L.cited, {n: it.cited}));
    b.appendChild(el('span', 'im', meta.join(' \u00B7 ')));
    li.appendChild(b);
    if (openItem === it) li.appendChild(itemDetail(it));
    return li;
  }
  function itemDetail(it) {
    var d = el('div', 'idet'), dl = el('dl');
    kvInto(dl, L.path, it.p, true);
    kvInto(dl, L.id, it.id, true);
    kvInto(dl, L.group, CLSNAME[it.k]);
    kvInto(dl, L.category, it.cat + ': ' + catName(it.cat));
    kvInto(dl, L.action, ACT[it.act] || it.act);
    if (it.deny) kvInto(dl, L.why, it.deny);
    if (it.reason) kvInto(dl, L.why, it.reason);
    if (it.age) kvInto(dl, L.age_k, tpl(L.age, {d: it.age}));
    if (it.by && it.by.length) kvInto(dl, L.cited_by, it.by.join(', '));
    d.appendChild(dl);
    var code = dl.querySelector('code');
    var cp = btn('act', L.copy, function () {
      function select() {
        var r = document.createRange();
        r.selectNodeContents(code);
        var s = window.getSelection();
        s.removeAllRanges();
        s.addRange(r);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(it.p).then(function () { cp.textContent = L.copied; }, select);
      } else select();
    });
    d.appendChild(cp);
    return d;
  }
  function drawFilters() {
    var f = $('filters');
    clear(f);
    var g = el('div', 'fgroup');
    g.appendChild(el('span', 'fl', L.show));
    for (var k = 1; k <= 4; k++) (function (k) {
      var s = J.sums[k];
      if (!s.n) return;
      var b = btn('chipb' + (show[k] ? ' on ' + CLS[k] : ''), CLSNAME[k] + ' (' + s.n + ', ' + fmt(s.b) + ')', function () { show[k] = !show[k]; drawJunk(); });
      b.setAttribute('aria-pressed', String(show[k]));
      g.appendChild(b);
    })(k);
    f.appendChild(g);
    var c = el('div', 'fgroup');
    c.appendChild(el('span', 'fl', L.categories));
    Object.keys(J.cats).sort().forEach(function (cat) {
      var s = J.cats[cat], on = cats[cat] !== false;
      var b = btn('chipb' + (on ? ' on' : ''), catName(cat) + ' (' + s.n + ')', function () { cats[cat] = !on; drawJunk(); });
      b.setAttribute('aria-pressed', String(on));
      c.appendChild(b);
    });
    f.appendChild(c);
    var r = el('div', 'fgroup');
    var inp = el('input', 'srch');
    inp.type = 'search';
    inp.placeholder = L.search;
    inp.value = query;
    inp.setAttribute('aria-label', L.search);
    inp.addEventListener('input', function () { query = inp.value.toLowerCase(); drawTree(); });
    r.appendChild(inp);
    r.appendChild(btn('act', L.expand, function () { expandAll = true; open = {}; drawTree(); }));
    r.appendChild(btn('act', L.collapse, function () { expandAll = false; open = {}; drawTree(); }));
    f.appendChild(r);
  }
  function drawTree() {
    var ul = $('tree');
    clear(ul);
    var t = tally(J.root);
    $('jsum').textContent = t.n + ' ' + (t.n === 1 ? L.item : L.items) + ' \u00B7 ' + fmt(t.b) + ' ' + L.apparent_note;
    if (!t.n) { ul.appendChild(el('li', 'empty', L.none)); return; }
    var max = 0;
    J.root.c.forEach(function (k) { if (k.t.b > max) max = k.t.b; });
    J.root.it.forEach(function (it) { if (itemOk(it) && it.b > max) max = it.b; });
    J.root.c.forEach(function (k) { if (k.t.n) ul.appendChild(folderRow(k, 0, max)); });
    J.root.it.forEach(function (it) { if (itemOk(it)) ul.appendChild(itemRow(it)); });
  }
  function drawJunk() { drawFilters(); drawTree(); }

  /* ---------------- disk map ---------------- */
  var byPath = Object.create(null);
  function index(n, up) {
    n.up = up;
    if (n.p) byPath[n.p] = n;
    var c = n.c || [];
    for (var i = 0; i < c.length; i++) index(c[i], n);
  }
  index(D.tree, null);

  var cur = D.tree, sel = null, hov = null, mode = 'folder';
  var map = $('map');

  function drawTotals() {
    var t = $('totals');
    function card(k, v, s, cls) {
      var c = el('div', 'card' + (cls ? ' ' + cls : ''));
      c.appendChild(el('div', 'k', k));
      c.appendChild(el('div', 'v', v));
      if (s) c.appendChild(el('div', 's', s));
      t.appendChild(c);
    }
    if (T.free !== null) card(L.free, fmt(T.free), (T.total ? tpl(L.of_total, {t: fmt(T.total)}) : '') + (M.free_note ? ' (' + M.free_note + ')' : ''));
    if (D.plan) {
      var s1 = D.plan.sums[1], s2 = D.plan.sums[2], s3 = D.plan.sums[3], s4 = D.plan.sums[4];
      card(L.cls1, fmt(s1.b), s1.n + ' ' + (s1.n === 1 ? L.item : L.items), 'k1');
      card(L.cls2, fmt(s2.b), s2.n + ' ' + (s2.n === 1 ? L.item : L.items), 'k2');
      card(L.shown, fmt(s3.b + s4.b), (s3.n + s4.n) + ' ' + ((s3.n + s4.n) === 1 ? L.item : L.items), 'k3');
    } else {
      card(L.read, fmt(T.read), M.label);
      card(L.apparent, fmt(T.apparent), T.apparent > 0 ? tpl(L.real_pct, {p: pct(T.read, T.apparent)}) : L.sum_sizes);
    }
    card(L.gap, fmt(T.gap), L.gap_sub + (T.unreadable ? ' (' + tpl(L.unreadable, {n: T.unreadable}) + ')' : ''));
  }

  function drawLegend() {
    var ul = $('legend');
    function item(chipCls, text) {
      var li = el('li');
      li.appendChild(el('span', 'chip ' + chipCls));
      li.appendChild(el('span', null, text));
      ul.appendChild(li);
    }
    if (D.plan) {
      for (var k = 1; k <= 4; k++) {
        var s = D.plan.sums[k];
        if (s.n) item(CLS[k], CLSNAME[k] + ': ' + fmt(s.b) + ' (' + s.n + ')');
      }
      item(CLS[0], CLSNAME[0] + ' ' + L.ring);
      $('pnote').textContent = L.trash_note + (D.plan.note ? ' ' + D.plan.note : '');
    } else {
      item(CLS[0], L.no_plan);
    }
    item('gap', L.gap_legend);
  }

  function drawBanners() {
    var b = $('banners');
    for (var i = 0; i < M.banners.length; i++) b.appendChild(el('p', 'banner', M.banners[i]));
    $('sub').textContent = tpl(L.sub, {ts: M.ts || '?', tool: M.tool, exact: M.exact ? L.exact : L.upper, gen: M.generated});
  }

  function drawCrumbs() {
    var ol = $('crumbs').firstChild;
    clear(ol);
    var chain = [];
    for (var n = cur; n; n = n.up) chain.unshift(n);
    chain.forEach(function (n, i) {
      var li = el('li');
      var b = btn('crumb', n === D.tree ? L.all_roots : n.n, function () { go(n); });
      if (i === chain.length - 1) b.setAttribute('aria-current', 'page');
      li.appendChild(b);
      ol.appendChild(li);
    });
    ol.scrollLeft = ol.scrollWidth;
  }

  function blockClass(n) {
    if (n.gap) return 'gap';
    if (n.more) return 'more';
    var c = CLS[n.k || 0];
    if (!n.k && n.pb) {
      var best = 0, at = 0;
      for (var i = 0; i < 4; i++) if (n.pb[i] > best) { best = n.pb[i]; at = i + 1; }
      if (at) c += ' in' + at;
    }
    return c;
  }

  function drawMap() {
    clear(map);
    var list = (cur.c || []).filter(function (k) { return k.b > 0; });
    if (cur === D.tree && T.gap > 0) {
      list.push({gap: true, n: L.gap_block, b: T.gap});
      list.sort(function (a, b) { return b.b - a.b; });
    }
    if (!list.length) { map.appendChild(el('p', 'empty', L.nothing_draw)); return; }
    var rects = squarify(list.map(function (n) { return n.b; }), 0, 0, map.clientWidth, map.clientHeight);
    list.forEach(function (n, i) {
      var r = rects[i];
      if (!r || r.w < 2 || r.h < 2) return;
      var b = btn('blk ' + blockClass(n) + (n === sel ? ' sel' : ''), null, function () {
        if (n.c && n.c.length) go(n); else { sel = n; hov = null; drawDetails(); drawMap(); }
      });
      b.style.left = r.x + 'px';
      b.style.top = r.y + 'px';
      b.style.width = r.w + 'px';
      b.style.height = r.h + 'px';
      b.title = n.n + ' - ' + fmt(n.b) + ' (' + pct(n.b, cur.b || T.read) + '%)';
      if (r.w >= 44 && r.h >= 18) b.appendChild(el('span', 'nm', n.n));
      if (r.w >= 70 && r.h >= 34) b.appendChild(el('span', 'sz', fmt(n.b)));
      b.addEventListener('mouseenter', function () { hov = n; drawDetails(); });
      b.addEventListener('focus', function () { hov = n; drawDetails(); });
      b.addEventListener('mouseleave', function () { hov = null; drawDetails(); });
      b.addEventListener('blur', function () { hov = null; drawDetails(); });
      map.appendChild(b);
    });
  }

  function drawTabs() {
    var t = $('tabs');
    clear(t);
    var defs = [['folder', L.t_folder], ['top', L.t_top]];
    if (D.plan) defs.push(['plan', L.t_plan]);
    defs.forEach(function (d) {
      var b = btn('tab', d[1], function () { mode = d[0]; drawTabs(); drawList(); });
      b.setAttribute('aria-pressed', String(mode === d[0]));
      t.appendChild(b);
    });
  }

  function drawList() {
    var ul = $('list');
    clear(ul);
    var items;
    if (mode === 'plan' && D.plan) items = D.plan.list;
    else if (mode === 'top') items = D.top.map(function (t) { return byPath[t.p] || t; });
    else items = cur.c || [];
    var shown = items.slice(0, 120), max = 0;
    shown.forEach(function (it) { if (it.b > max) max = it.b; });
    shown.forEach(function (it) {
      var li = el('li');
      var b = btn('row', null, function () { pick(it); });
      b.appendChild(el('span', 'chip ' + (it.more ? 'g0' : CLS[it.k || 0])));
      b.appendChild(el('span', 'rn', it.n));
      b.appendChild(el('span', 'rs', fmt(it.b)));
      if (mode === 'plan' && it.i) b.appendChild(el('span', 'rm', it.i.id + ' - ' + catName(it.i.cat) + ' - ' + (ACT[it.i.act] || it.i.act)));
      var bar = el('span', 'bar');
      bar.style.width = (max > 0 ? Math.max(1, Math.round(it.b * 100 / max)) : 0) + '%';
      b.appendChild(bar);
      li.appendChild(b);
      ul.appendChild(li);
    });
    if (!shown.length) ul.appendChild(el('li', 'empty', L.nothing_here));
    if (items.length > shown.length) ul.appendChild(el('li', 'note', tpl(L.more_not_listed, {n: items.length - shown.length})));
  }

  function drawDetails() {
    var n = hov || sel || cur, d = $('det');
    clear(d);
    d.appendChild(el('h2', null, n === D.tree ? L.all_roots : n.n));
    var dl = el('dl');
    function kv(k, v, mono) { kvInto(dl, k, v, mono); }
    if (n.gap) {
      kv(L.size, fmt(n.b));
      kv(L.what, L.what_gap);
    } else if (n.more) {
      kv(L.size, fmt(n.b));
      kv(L.what, L.what_more);
    } else {
      if (n.p) kv(L.path, n.p, true);
      kv(L.size_disk, fmt(n.b) + (n.up && n.up.b > 0 ? ' (' + tpl(L.of_parent, {p: pct(n.b, n.up.b)}) + ')' : ''));
      if (typeof n.a === 'number' && n.a !== n.b) kv(L.apparent, fmt(n.a));
      if (n.i) {
        kv(L.plan, n.i.id + ' - ' + CLSNAME[n.k]);
        kv(L.category, n.i.cat + ': ' + catName(n.i.cat));
        kv(L.action, ACT[n.i.act] || n.i.act);
        if (n.i.deny) kv(L.why, n.i.deny);
      } else if (D.plan) {
        kv(L.plan, CLSNAME[n.k || 0]);
      }
      if (n.pb) {
        var parts = [];
        for (var k = 0; k < 4; k++) if (n.pb[k] > 0) parts.push(CLSNAME[k + 1] + ' ' + fmt(n.pb[k]));
        kv(L.contains, parts.join('; '));
      }
      if (n.c && n.c.length) kv(L.items_k, n.c.length);
    }
    d.appendChild(dl);
    if (n.c && n.c.length && n !== cur) d.appendChild(btn('act', L.open_folder, function () { go(n); }));
  }

  function renderMap() {
    drawCrumbs(); drawMap(); drawTabs(); drawList(); drawDetails();
  }
  function go(n) {
    cur = n; sel = null; hov = null;
    renderMap();
    map.focus({preventScroll: true});
  }
  function pick(it) {
    var n = it.gap || it.more ? it : byPath[it.p];
    if (n && n === D.tree) return go(n);
    if (n && n.up) {
      var moved = cur !== n.up;
      cur = n.up; sel = n; hov = null;
      if (moved) { drawCrumbs(); drawList(); }
      drawMap(); drawDetails();
    } else {
      var a = byPath[it.at];
      if (a && a !== cur) { cur = a; drawCrumbs(); drawList(); }
      sel = it; hov = null;
      drawMap(); drawDetails();
    }
  }

  /* ---------------- choose ---------------- */
  var C = D.choose, picked = Object.create(null), openSec = Object.create(null);
  var SHOW_FIRST = 8;
  function selectRecommended() {
    picked = Object.create(null);
    if (!C) return;
    C.sections.forEach(function (s) { s.items.forEach(function (it) { if (it.rec) picked[it.id] = true; }); });
  }
  selectRecommended();
  function chosen() {
    var out = [];
    C.sections.forEach(function (s) { s.items.forEach(function (it) { if (picked[it.id]) out.push(it); }); });
    return out;
  }
  function replyText(list) {
    var by = {trash: [], archive_then_trash: [], tool_command: []};
    list.forEach(function (it) { (by[it.act] || by.trash).push(it.id); });
    var lines = [tpl(L.reply_head, {sha: C.sha})];
    if (by.trash.length) lines.push(L.r_trash + ': ' + by.trash.join(' '));
    if (by.archive_then_trash.length) lines.push(L.r_arch + ': ' + by.archive_then_trash.join(' '));
    if (by.tool_command.length) lines.push(L.r_tool + ': ' + by.tool_command.join(' '));
    return lines.join('\n');
  }
  function drawPick() {
    var list = chosen(), b = 0;
    list.forEach(function (it) { b += it.b; });
    $('ptitle').textContent = list.length ? tpl(L.selected, {n: list.length, size: fmt(b)}) : L.nothing_sel;
    var ta = $('preply');
    ta.value = list.length ? replyText(list) : '';
    $('pcopy').disabled = !list.length;
    $('pcopy').textContent = L.copy_reply;
  }
  function crow(it) {
    var li = el('li');
    var lab = el('label', 'crow');
    lab.title = it.p;
    var box = el('input');
    box.type = 'checkbox';
    box.checked = !!picked[it.id];
    box.addEventListener('change', function () { if (box.checked) picked[it.id] = true; else delete picked[it.id]; drawPick(); });
    lab.appendChild(box);
    var name = el('span', 'cn', it.n);
    if (it.rec) name.appendChild(el('span', 'rec', L.rec));
    lab.appendChild(name);
    lab.appendChild(el('span', 'cz', fmt(it.b)));
    lab.appendChild(el('span', 'cw', tpl(L.in_folder, {w: it.w})));
    var notes = [];
    if (it.age) notes.push(tpl(L.age, {d: it.age}));
    if (it.act === 'archive_then_trash') notes.push(L.a_arch);
    if (it.act === 'tool_command') notes.push(L.a_tool);
    if (it.keep) notes.push(tpl(L.keeps, {p: it.keep}));
    if (notes.length) lab.appendChild(el('span', 'cx', notes.join(' \u00B7 ')));
    if (it.note) lab.appendChild(el('span', 'cx warn', it.note));
    li.appendChild(lab);
    return li;
  }
  function section(s) {
    var box = el('section', 'sec'), head = el('div', 'sech');
    var all = el('input');
    all.type = 'checkbox';
    var on = s.items.filter(function (it) { return picked[it.id]; }).length;
    all.checked = on === s.items.length;
    all.indeterminate = on > 0 && on < s.items.length;
    all.setAttribute('aria-label', L.sel_all_sec + ': ' + s.title);
    all.addEventListener('change', function () {
      s.items.forEach(function (it) { if (all.checked) picked[it.id] = true; else delete picked[it.id]; });
      drawChoose();
    });
    head.appendChild(all);
    head.appendChild(el('h3', null, s.title));
    head.appendChild(el('span', 'ss', tpl(L.sec_sum, {n: s.items.length, size: fmt(s.b)})));
    head.appendChild(el('span', 'sd', s.what));
    head.appendChild(el('span', 'se', s.after));
    box.appendChild(head);
    var ul = el('ul', 'crows'), full = openSec[s.cat] || s.items.length <= SHOW_FIRST;
    (full ? s.items : s.items.slice(0, SHOW_FIRST)).forEach(function (it) { ul.appendChild(crow(it)); });
    box.appendChild(ul);
    if (!full) box.appendChild(btn('more2', tpl(L.show_more, {n: s.items.length - SHOW_FIRST}), function () { openSec[s.cat] = true; drawChoose(); }));
    return box;
  }
  function drawChoose() {
    var root = $('secs');
    clear(root);
    C.sections.forEach(function (s) { root.appendChild(section(s)); });
    if (C.kept.n) {
      var d = el('details', 'kept');
      d.appendChild(el('summary', null, tpl(L.kept_head, {n: C.kept.n, size: fmt(C.kept.b)})));
      d.appendChild(el('p', 'note', L.kept_sub));
      var ul = el('ul');
      C.kept.items.forEach(function (it) { ul.appendChild(el('li', null, it.n + ' (' + fmt(it.b) + ') \u00B7 ' + it.why)); });
      d.appendChild(ul);
      root.appendChild(d);
    }
    drawPick();
  }
  function drawHero() {
    var h = $('hero');
    clear(h);
    h.appendChild(el('div', 'big', tpl(L.hero, {size: fmt(C.total_b), n: C.total_n})));
    h.appendChild(el('p', null, L.hero_sub));
    $('psel').textContent = L.sel_rec;
    $('pnone').textContent = L.sel_none;
    $('pmsg').textContent = L.paste_hint;
  }
  if (C) {
    $('psel').addEventListener('click', function () { selectRecommended(); drawChoose(); });
    $('pnone').addEventListener('click', function () { picked = Object.create(null); drawChoose(); });
    $('pcopy').addEventListener('click', function () {
      var ta = $('preply'), b = $('pcopy');
      function done() { b.textContent = L.copied_reply; }
      function fallback() { ta.focus(); ta.select(); try { if (document.execCommand('copy')) done(); } catch (e) { /* the text stays selected */ } }
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(ta.value).then(done, fallback);
      else fallback();
    });
  }

  /* ---------------- views ---------------- */
  var view = C ? 'choose' : (J ? 'junk' : 'map');
  function drawViews() {
    var v = $('views');
    clear(v);
    [['choose', L.tab_choose], ['junk', L.tab_junk], ['map', L.tab_map]].forEach(function (d) {
      if ((d[0] === 'junk' && !J) || (d[0] === 'choose' && !C)) return;
      var b = btn('tab', d[1], function () { view = d[0]; drawViews(); });
      b.setAttribute('aria-pressed', String(view === d[0]));
      v.appendChild(b);
    });
    $('choose').hidden = view !== 'choose';
    $('totals').hidden = view === 'choose';
    $('lead').hidden = view === 'choose';
    $('lead').textContent = view === 'junk' ? L.lead_junk : L.lead_map;
    $('junk').hidden = view !== 'junk';
    $('mapv').hidden = view !== 'map';
    if (view === 'map') drawMap();
  }

  document.addEventListener('keydown', function (e) {
    if (e.altKey || e.ctrlKey || e.metaKey || view !== 'map') return;
    if ((e.key === 'Escape' || e.key === 'Backspace') && cur.up && document.activeElement && document.activeElement.tagName !== 'INPUT') { e.preventDefault(); go(cur.up); }
  });
  var raf = 0;
  window.addEventListener('resize', function () {
    if (raf) return;
    raf = window.requestAnimationFrame(function () { raf = 0; if (view === 'map') drawMap(); });
  });

  document.title = L.title;
  $('h1').textContent = L.title;
  $('lead').textContent = J ? L.lead_junk : L.lead_map;
  drawBanners(); drawTotals(); drawLegend();
  if (J) drawJunk();
  if (C) { drawHero(); drawChoose(); }
  renderMap();
  drawViews();
})();
"""

_PAGE = """<!doctype html>
<html lang="@@LANG@@">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="@@CSP@@">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>CoreCleaner</title>
<style>@@STYLE@@</style>
</head>
<body>
<div class="wrap">
<header>
<h1 id="h1">CoreCleaner</h1>
<p class="sub" id="sub"></p>
<div id="banners"></div>
</header>
<section class="cards" id="totals" aria-label="Totals"></section>
<p class="lead" id="lead"></p>
<div class="tabs" id="views" role="tablist"></div>
<section id="choose" aria-label="Choose">
<div class="hero" id="hero"></div>
<div class="secs" id="secs"></div>
<div class="pick" id="pick">
<div class="in2w">
<span class="pt" id="ptitle"></span>
<span class="pb"><button type="button" class="act" id="psel"></button><button type="button" class="act" id="pnone"></button><button type="button" class="go" id="pcopy"></button></span>
<textarea id="preply" rows="3" readonly aria-label="Reply"></textarea>
<p class="pm" id="pmsg"></p>
</div>
</div>
</section>
<section id="junk" aria-label="Junk by folder">
<div id="filters"></div>
<p id="jsum"></p>
<ul id="tree"></ul>
</section>
<section id="mapv" aria-label="Disk map">
<nav id="crumbs" aria-label="Folder path"><ol></ol></nav>
<div class="layout">
<main>
<div class="map" id="map" tabindex="-1"></div>
<ul class="legend" id="legend"></ul>
<p class="note" id="pnote"></p>
<section id="det" aria-live="polite" aria-label="Details"></section>
</main>
<aside aria-label="Items">
<div class="tabs" id="tabs"></div>
<ul id="list"></ul>
</aside>
</div>
</section>
<noscript><p class="banner">This report needs JavaScript. It is fully offline: no data leaves this file.</p></noscript>
</div>
<script type="application/json" id="cdata">@@DATA@@</script>
<script>@@SCRIPT@@</script>
</body>
</html>
"""


def _hash_token(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def _csp() -> str:
    return "; ".join(
        [
            "default-src 'none'",
            "script-src " + _hash_token(_JS),
            "style-src " + _hash_token(_CSS),
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )


def _clean(value: Any, maxlen: int) -> str:
    """Display-safe text: control, surrogate and spoofing characters become U+FFFD, then truncated."""
    text = value if isinstance(value, str) else ""
    out = [
        "\ufffd" if (unicodedata.category(ch) in ("Cc", "Cs") or ord(ch) in _SPOOF) else ch
        for ch in text[:maxlen]
    ]
    return "".join(out) + ("..." if len(text) > maxlen else "")


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if value != value or value in (float("inf"), float("-inf")):
        return 0
    return max(0, int(value))


def _opt_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return _int(value)


def _key(path: str) -> str:
    """Comparison form of a path for tree/plan matching (both come from realpath already)."""
    if sys.platform == "win32":
        path = path.replace("\\", "/").casefold()
    return path.rstrip("/")


def _inside(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def _basename(path: str) -> str:
    base = os.path.basename(path.rstrip("/\\"))
    return base or path


def _plan_class(item: dict) -> int:
    if item.get("deny"):
        return CLASS_SYS
    group = item.get("group")
    return group if type(group) is int and group in (1, 2, 3) else CLASS_SYS


def _plan_entries(plan: Optional[dict], lang: str = "en") -> List[dict]:
    entries: List[dict] = []
    items = plan.get("items") if isinstance(plan, dict) else None
    for raw in items if isinstance(items, list) else []:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
            continue
        path = raw["path"]
        deny = raw.get("deny")
        reason = raw.get("reason")
        ev = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
        age = ev.get("project_idle_days") if raw.get("category") == "E" and _opt_int(ev.get("project_idle_days")) else ev.get("age_days")
        by = [_clean(x, 120) for x in (ev.get("referenced_by") or []) if isinstance(x, str)][:3]
        entries.append(
            {
                "key": _key(path),
                "cls": _plan_class(raw),
                "view": {
                    "n": _clean(raw.get("display") or _basename(path), NAME_MAX),
                    "p": _clean(path, PATH_MAX),
                    "b": _int(raw.get("bytes")),
                    "k": _plan_class(raw),
                    "id": _clean(str(raw.get("id", "")), 40),
                    "cat": _clean(str(raw.get("category", "")), 4),
                    "act": _clean(str(raw.get("action", "")), 40),
                    "deny": _clean(_ask.translate_reason(deny, lang), 200) if isinstance(deny, str) and deny else None,
                    "reason": _clean(_ask.translate_reason(reason, lang), 200) if isinstance(reason, str) and reason else None,
                    "age": _int(age),
                    "cited": _int(ev.get("referenced_count")),
                    "by": by,
                    "i": {
                        "id": _clean(str(raw.get("id", "")), 40),
                        "cat": _clean(str(raw.get("category", "")), 4),
                        "act": _clean(str(raw.get("action", "")), 40),
                        "deny": _clean(deny, 200) if isinstance(deny, str) and deny else None,
                    },
                },
            }
        )
    return entries


def _node(raw: Any, depth: int, entries: List[dict]) -> dict:
    """Normalize a scan node into the compact view node; match plan entries by path."""
    raw = raw if isinstance(raw, dict) else {}
    path = raw.get("path") if isinstance(raw.get("path"), str) else ""
    b = _int(raw.get("bytes"))
    a = _opt_int(raw.get("apparent"))
    node: Dict[str, Any] = {
        "n": _clean(_basename(path), NAME_MAX) if path else "?",
        "p": _clean(path, PATH_MAX),
        "b": b,
        "a": b if a is None else a,
    }
    mine = entries
    if depth > 0:
        key = _key(path)
        mine = [e for e in entries if _inside(e["key"], key)]
        exact = [e for e in mine if e["key"] == key]
        if exact:
            top = max(exact, key=lambda e: (e["cls"], e["view"]["b"]))
            node["k"] = top["cls"]
            node["i"] = top["view"]["i"]
        inner = [0, 0, 0, 0]
        for e in mine:
            if e["key"] != key:
                inner[e["cls"] - 1] += e["view"]["b"]
        if any(inner):
            node["pb"] = inner
        for e in mine:
            e["at"] = node["p"]  # parents run first, so the last write is the deepest node
    kids = [c for c in (raw.get("children") or []) if isinstance(c, dict)] if depth < MAX_DEPTH else []
    kids.sort(key=lambda c: (-_int(c.get("bytes")), str(c.get("path", ""))))
    out = [_node(c, depth + 1, mine) for c in kids[:MAX_CHILDREN]]
    rest = kids[MAX_CHILDREN:]
    if rest:
        rb = sum(_int(c.get("bytes")) for c in rest)
        ra = sum(_opt_int(c.get("apparent")) or _int(c.get("bytes")) for c in rest)
        out.append({"n": "(%d smaller items)" % len(rest), "p": "", "b": rb, "a": ra, "more": len(rest)})
    if out:
        node["c"] = out
    return node


def _junk_tree(entries: List[dict], home: str) -> Optional[dict]:
    """Plan items under the folders that hold them: {root, sums, cats}. Folders with one child and no item are
    joined ("a/b/c"); the home folder shows as "~". Counts and bytes per folder cover every class; the page
    recomputes them for the active filters."""
    if not entries:
        return None
    home_key = _key(home) if home else ""

    def new(name: str, path: str) -> dict:
        return {"n": name, "p": path, "kids": {}, "it": []}

    root = new("", "")
    for e in entries:
        parts = [x for x in e["key"].split("/") if x]
        node, sofar = root, ""
        for part in parts[:-1]:
            sofar += "/" + part
            node = node["kids"].setdefault(part, new(part, sofar))
        node["it"].append(e["view"])

    def finish(node: dict, top: bool) -> dict:
        # join single-child chains, but never across the home folder (it stays one node named ~)
        while not top and len(node["kids"]) == 1 and not node["it"] and node["p"] != home_key:
            child = next(iter(node["kids"].values()))
            node = {"n": node["n"] + "/" + child["n"], "p": child["p"], "kids": child["kids"], "it": child["it"]}
        if node["p"] == home_key and home_key:
            node["n"] = "~"
        kids = [finish(k, False) for k in node["kids"].values()]
        cnt, by = [0, 0, 0, 0], [0, 0, 0, 0]
        for it in node["it"]:
            cnt[it["k"] - 1] += 1
            by[it["k"] - 1] += it["b"]
        for k in kids:
            for i in range(4):
                cnt[i] += k["cnt"][i]
                by[i] += k["by"][i]
        kids.sort(key=lambda k: (-sum(k["by"]), k["n"]))
        items = sorted(node["it"], key=lambda it: (it["k"], -it["b"], it["n"]))
        return {"n": _clean(node["n"], NAME_MAX), "p": _clean(node["p"], PATH_MAX), "c": kids, "it": items, "cnt": cnt, "by": by}

    tree = finish(root, True)
    if len(tree["c"]) == 1 and not tree["it"]:  # everything under one folder (usually ~): start there
        tree = tree["c"][0]
    sums = {k: {"n": 0, "b": 0} for k in range(1, 5)}
    cats: Dict[str, Dict[str, int]] = {}
    for e in entries:
        v = e["view"]
        sums[v["k"]]["n"] += 1
        sums[v["k"]]["b"] += v["b"]
        c = cats.setdefault(v["cat"], {"n": 0, "b": 0})
        c["n"] += 1
        c["b"] += v["b"]
    return {"root": tree, "sums": sums, "cats": cats, "expand_limit": JUNK_EXPAND_LIMIT}


def _short(path: str, home: str) -> str:
    if home and (path == home or path.startswith(home.rstrip("/") + "/")):
        return "~" + path[len(home.rstrip("/")):]
    return path


def _choice_name(raw: dict, path: str) -> str:
    """What a person recognizes: the project for node_modules, the session for an agent conversation."""
    base = _basename(path)
    if raw.get("category") == "E" and base == "node_modules":
        return _basename(os.path.dirname(path)) + "/node_modules"
    if raw.get("category") == "A":
        stem = base[:-6] if base.endswith(".jsonl") else base
        return stem[:8] + (" (.jsonl)" if base.endswith(".jsonl") else "")
    return raw.get("display") if isinstance(raw.get("display"), str) and raw.get("display") else base


def _choices(plan: Optional[dict], lang: str, home: str) -> Optional[dict]:
    """The 'choose' view: groups 1 and 2 by plain-language section, group 3 as one 'left alone' list."""
    if not isinstance(plan, dict):
        return None
    secs: Dict[str, Dict[str, Any]] = {}
    kept: List[dict] = []
    kept_b = 0
    names = SECTIONS.get(lang, SECTIONS["en"])
    for raw in plan.get("items") if isinstance(plan.get("items"), list) else []:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
            continue
        path, cls = raw["path"], _plan_class(raw)
        b = _int(raw.get("bytes"))
        if cls not in (1, 2):
            why = raw.get("deny") if isinstance(raw.get("deny"), str) else ""
            kept.append({"n": _clean(_short(path, home), 200), "b": b, "why": _clean(_ask.translate_reason(why, lang), 200)})
            kept_b += b
            continue
        cat = str(raw.get("category", "?"))
        ev = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
        age = ev.get("project_idle_days") if cat == "E" and _opt_int(ev.get("project_idle_days")) else ev.get("age_days")
        reason = raw.get("reason") if isinstance(raw.get("reason"), str) else ""
        keeper = raw.get("keeper") if isinstance(raw.get("keeper"), dict) else {}
        title, what, after = names.get(cat, (_ask.CATEGORY_NAMES[lang].get(cat, cat), "", ""))
        sec = secs.setdefault(cat, {"cat": cat, "title": title, "what": what, "after": after, "items": [], "b": 0})
        sec["items"].append({
            "id": _clean(str(raw.get("id", "")), 40),
            "n": _clean(_choice_name(raw, path), NAME_MAX),
            "w": _clean(_short(os.path.dirname(path), home), PATH_MAX),
            "p": _clean(_short(path, home), PATH_MAX),
            "b": b,
            "rec": cls == 1,
            "act": _clean(str(raw.get("action", "trash")), 40),
            "age": _int(age),
            "note": _clean(_ask.translate_reason(reason, lang), 200) if reason else "",
            "keep": _clean(_short(keeper["path"], home), PATH_MAX) if isinstance(keeper.get("path"), str) else "",
        })
        sec["b"] += b
    order = list(names) + sorted(c for c in secs if c not in names)
    sections = [secs[c] for c in order if c in secs]
    for s in sections:
        s["items"].sort(key=lambda it: (not it["rec"], -it["b"], it["n"]))
    sections.sort(key=lambda s: (not any(it["rec"] for it in s["items"]), -s["b"]))
    kept.sort(key=lambda it: -it["b"])
    sha = plan.get("sha256") if isinstance(plan.get("sha256"), str) else ""
    return {
        "sha": _clean(sha[:12], 12),
        "sections": sections,
        "total_n": sum(len(s["items"]) for s in sections),
        "total_b": sum(s["b"] for s in sections),
        "kept": {"n": len(kept), "b": kept_b, "items": kept},
    }


def _flatten(node: dict, acc: List[dict]) -> List[dict]:
    for c in node.get("c", []):
        if not c.get("more"):
            acc.append({"n": c["n"], "p": c["p"], "b": c["b"]})
            _flatten(c, acc)
    return acc


def _top(scan: dict, tree: dict) -> List[dict]:
    given = scan.get("top")
    rows: List[dict] = []
    for raw in given if isinstance(given, list) else []:
        if isinstance(raw, dict) and isinstance(raw.get("path"), str) and raw["path"]:
            rows.append(
                {"n": _clean(_basename(raw["path"]), NAME_MAX), "p": _clean(raw["path"], PATH_MAX), "b": _int(raw.get("bytes"))}
            )
    if not rows:
        rows = sorted(_flatten(tree, []), key=lambda r: -r["b"])
    return rows[:20]


def _gap_info(scan: dict, read: int) -> Dict[str, Any]:
    gap = scan.get("gap")
    gap = gap if isinstance(gap, dict) else {}
    value = _opt_int(gap.get("bytes"))
    if value is None:
        value = _opt_int(gap.get("unexplained_bytes"))  # what scan.py emits
    if value is None:
        used = _opt_int(gap.get("used_bytes"))
        value = max(0, used - read) if used is not None else _opt_int(scan.get("gap")) or 0
    free = _opt_int(gap.get("free_bytes"))
    total = _opt_int(gap.get("total_bytes"))
    return {
        "gap": value,
        "free": free if free is not None else _opt_int(scan.get("free_bytes")),
        "total": total if total is not None else _opt_int(scan.get("total_bytes")),
        "unreadable": _opt_int(gap.get("unreadable")) or 0,
    }


def _plan_view(entries: List[dict], plan: Optional[dict]) -> Optional[dict]:
    if plan is None:
        return None
    sums = {k: {"n": 0, "b": 0} for k in range(1, 5)}
    rows = []
    for e in sorted(entries, key=lambda e: (e["cls"], -e["view"]["b"])):
        sums[e["cls"]]["n"] += 1
        sums[e["cls"]]["b"] += e["view"]["b"]
        row = dict(e["view"])
        row["at"] = e.get("at", "")
        rows.append(row)
    note = plan.get("summary", {}).get("expected_gain_note") if isinstance(plan.get("summary"), dict) else None
    return {"list": rows, "sums": sums, "note": _clean(note, 400) if isinstance(note, str) else None}


def build_model(scan: dict, plan: Optional[dict], lang: str = "en") -> dict:
    """The JSON document the page reads (also what the tests inspect)."""
    if not isinstance(scan, dict) or not isinstance(scan.get("tree"), dict):
        raise CorecleanerError(EXIT_USAGE, "scan JSON has no 'tree' object; pass the output of `scan`")
    lang = lang if lang in STRINGS else "en"
    L = STRINGS[lang]
    page_L = {k: v for k, v in L.items() if k not in ("basic", "windows")}  # banners are built here, not on the page
    entries = _plan_entries(plan, lang)
    tree = _node(scan["tree"], 0, entries)
    info = _gap_info(scan, tree["b"])
    basic = scan.get("tool") == "basic" or scan.get("exact") is False
    banners = ([L["basic"]] if basic else []) + ([L["windows"]] if sys.platform == "win32" else [])
    label = scan.get("label")
    note = scan.get("free_note")
    home = scan.get("home") if isinstance(scan.get("home"), str) else str(Path.home())
    return {
        "v": 2,
        "lang": lang,
        "L": page_L,
        "meta": {
            "tool": _clean(scan.get("tool") if isinstance(scan.get("tool"), str) else "unknown", 20),
            "exact": not basic,
            "label": _clean(label, 120) if isinstance(label, str) and label else ("apparent (upper bound)" if basic else "exact"),
            "ts": _clean(scan.get("ts"), 40),
            "generated": now_iso(),
            "banners": banners,
            "free_note": (L["at_report"] if note == "at report time" else _clean(note, 60)) if isinstance(note, str) and note else "",
        },
        "totals": {
            "read": tree["b"],
            "apparent": tree["a"],
            "gap": info["gap"],
            "free": info["free"],
            "total": info["total"],
            "unreadable": info["unreadable"],
        },
        "cats": _ask.CATEGORY_NAMES[lang],
        "tree": tree,
        "top": _top(scan, tree),
        "plan": _plan_view(entries, plan),
        "junk": _junk_tree(entries, home) if plan is not None else None,
        "choose": _choices(plan, lang, home),
    }


def _embed(model: dict) -> str:
    # ensure_ascii keeps lone surrogates legal; the replaces keep the data block from ending the
    # script element or reading as a URL.
    text = json.dumps(model, ensure_ascii=True, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("://", ":\\/\\/")
    )


def render_html(scan: dict, plan: Optional[dict], lang: str = "en") -> str:
    model = build_model(scan, plan, lang)
    data = _embed(model)
    return (
        _PAGE.replace("@@LANG@@", model["lang"])
        .replace("@@CSP@@", _csp())
        .replace("@@STYLE@@", _CSS)
        .replace("@@SCRIPT@@", _JS)
        .replace("@@DATA@@", data)  # last: the data is never rescanned for placeholders
    )


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise CorecleanerError(EXIT_USAGE, "cannot read scan file as JSON: " + str(exc), path=str(path))


def _write_report(text: str) -> Path:
    base = state_subdir("reports")
    stamp = file_stamp()
    data = text.encode("utf-8")
    for n in range(1, 100):
        target = base / ("report-%s%s.html" % (stamp, "" if n == 1 else "-%d" % n))
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return target
    raise CorecleanerError(EXIT_ERROR, "could not pick a free report file name", dir=str(base))


def run(args) -> dict:
    scan = _read_json(args.scan)
    if not isinstance(scan, dict):
        raise CorecleanerError(EXIT_USAGE, "scan file must hold a JSON object", path=str(args.scan))
    plan_file = getattr(args, "plan", None)
    plan = _plan.load_plan(plan_file) if plan_file else None
    if _gap_info(scan, 0)["free"] is None:
        try:
            scan = dict(scan, free_bytes=shutil.disk_usage(str(Path.home())).free, free_note="at report time")
        except OSError as exc:
            log("free space unavailable for the report: " + str(exc))
    target = _write_report(render_html(scan, plan, _ask._lang(getattr(args, "lang", None))))
    return {"report": str(target), "bytes": target.stat().st_size}
