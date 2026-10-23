# CoreCleaner: spec e plano de tarefas
<!-- teto: isento (spec de build + fila de tarefas; encolhe conforme fecha) -->

Base: um plano de pesquisa local (pesquisa, júri, fontes), fora do repo. Este arquivo só registra o que mudou e as tarefas.

## Decisões do dono (2026-10-21)
- Repo `corewake-labs/CoreCleaner` (org a criar pelo dono no navegador), MIT, skill `corecleaner` (spec exige `[a-z0-9-]` e pasta == name).
- Núcleo: Python único, stdlib, 3.9+. Um arquivo de lista negra, uma implementação.
- Mapa: `report.html` offline (treemap em JS puro, sem rede, CSP por hash, `textContent`).
- Windows: código pronto, rotulado **beta, não testado** no README e na saída.
- Analisador: dua-cli v2.46.0 primário (`--deduplicate-apfs-clones` no macOS); sem dua = modo básico (os.scandir + st_blocks/inode), rotulado "aparente (teto)".

## Layout
```
README.md  LICENSE  NOTICE  .github/workflows/ci.yml
skills/corecleaner/SKILL.md
skills/corecleaner/scripts/corecleaner.py          entrada única (subcomandos)
skills/corecleaner/scripts/corecleaner_lib/*.py    módulos
skills/corecleaner/references/never-touch.txt  pins.tsv  categorias.md
tests/  (unittest, stdlib)
```

## Contrato da CLI (`python3 corecleaner.py <cmd>`; toda saída JSON em stdout, log em stderr)
| cmd | efeito | escreve? |
|---|---|---|
| `check` | SO, arch, python, Lixeira disponível, dua (versão), git, volumes | não |
| `free [--path P]` | bytes livres do volume (shutil.disk_usage) | não |
| `bootstrap [--yes]` | baixa dua pinado, confere sha256, instala em dir do usuário, autoteste | sim (só dir próprio) |
| `scan [--roots ...] [--raw]` | mapa do disco (dua ou básico), árvore + LACUNA salvos em `scans/`; stdout = resumo sanitizado (`--raw` = tudo, só para humano). LACUNA = usado do volume menos lido; rótulo "outside the scanned roots" quando nenhuma raiz é o volume inteiro (ou há outro volume APFS no contêiner), com `outside_roots` medido em até 20 s (`CORECLEANER_SCAN_OUTSIDE_SECONDS`, 0 pula) e `other_volumes` listados sem tamanho; "unexplained" só em scan de volume inteiro | só estado |
| `inventory [--raw]` | candidatos A-L com evidência (git, idade, processo vivo, dependência viva) salvos em `inventories/`; stdout = contagem por categoria, sem nomes | só estado |
| `plan [--candidates F]` | gera `plan-<ts>.json` com id, realpath, bytes, inode, mtime, hash do plano; item virtual (snapshot, processo) entra como `virtual`, grupo 3, só listar | só estado |
| `ask --plan F --format claude\|codex\|text [--expand 1,2] [--lang pt]` | perguntas em lotes, nomes sanitizados | não |
| `trash --plan F --ids ... [--apply]` | dry-run padrão; reconfere; arquiva repo sujo; Lixeira; manifesto. `--apply` com stdout fora de terminal põe em `warnings` "no proof a person answered"; `CORECLEANER_REQUIRE_TTY_APPLY=1` recusa (exit 2) | sim |
| `undo --run R` | restaura pelo manifesto (cada linha assinada por HMAC, propósito `manifest`; linha sem assinatura válida é ignorada e listada; só aceita destino dentro da Lixeira DESTE usuário e o mesmo inode/dispositivo registrado) | sim |
| `report --scan F [--plan F]` | gera `report.html` offline | só estado |

## Travas obrigatórias (código, não instrução)
1. Lista negra normalizada (casefold onde FS é insensível, NFC, realpath, 8.3 e `\\?\` no Windows) recusa o protegido e qualquer PAI dele. Inclui `~/corecleaner-archive` (pode ser a única cópia de um repo) e o diretório de estado.
2. `trash` só aceita ids de plano com hash íntegro E assinatura HMAC (chave `mac.key` no estado); `id` e `display` derivam do caminho; `plan --candidates` só aceita o arquivo que `inventory` salvou (assinado); `tool_command` só se for um que o `inventory` monta para aquele caminho; nunca caminho livre; sem `--force`. Prazo de 12 h (`plan.MAX_AGE_HOURS`): inventário velho é recusado em `plan --candidates` e plano velho em `trash --apply`, exit 42 "re-run inventory" (data ausente, ilegível ou no futuro também); o dry-run só avisa em `warnings`.
3. Reconferência antes de agir: existe, realpath igual, inode igual, mtime não mais novo (maior mtime da ÁRVORE, não só o da pasta), não symlink/junction, nome sem controle. Fluxo único em `trash.py`; `plan.recheck_item` faz a medida. Árvore não lida até o fim (cap/erro) = ociosidade não provada = nega. Depois de arquivar, confere de novo (impressão da árvore sem `.git` + vivo); mudou = não move. Duplicata exige o keeper intacto.
4. Nunca `os.remove`/`rmtree` em alvo do usuário; só Lixeira do SO; sem Lixeira no volume = recusa. Única remoção em `trash.py`: o `info/<nome>.trashinfo` da Lixeira XDG (Linux) do item que o `undo` acabou de restaurar (arquivo de controle da própria Lixeira, regular, `[Trash Info]`, `Path=` igual ao original). Windows: item maior que a Lixeira ou com caminho >= 240 caracteres = recusa antes (o Shell apagaria de vez).
5. Pasta sincronizada (iCloud, OneDrive, Dropbox, Google Drive) e placeholder (SF_DATALESS, RECALL_ON_OPEN, blocos≪tamanho) = só listar.
6. Repo git sujo/não publicado/stash = bundle + diff + verify antes (também repos aninhados em pasta de scratch; `.env`/chaves ignorados vão para `ignored-protected.tar.gz`; árvore ignorada grande demais para varrer, ou mais de 20 achados = a varredura não terminou: o repo, sujo ou limpo, é pulado com "too big to scan", e `archive_repo` devolve o aviso em `incomplete`); sem espaço para o arquivo = pula o item; clone raso (`rev-parse --is-shallow-repository`): commit na borda do corte (`.git/shallow`, com pais ausentes) veio de um remoto e não conta como "sem remoto"; raso limpo não precisa de arquivo; raso com trabalho vira `shallow-repo.tar.gz` do repo inteiro (com `.git`, lido até o fim, exige `.git/HEAD` e `.git/shallow`) no lugar do bundle, que não se clona de volta; raso com `.git` arquivo (worktree/submódulo) = recusa; `~/corecleaner-archive` tem teto de 20 GiB no total (`CORECLEANER_ARCHIVE_CAP_GIB`): arquivo que o estouraria pula o item com exit 44 (também no dry-run) e nada é criado; o resultado de `trash` traz `archive_store` (tamanho, teto, arquivos parados há 90 dias ou mais e um comando para o DONO rodar), e nenhum arquivo é apagado pela ferramenta; submódulo/worktree ligado com trabalho fora do arquivo = recusa, e também repo dentro de pasta ignorada de outro repo (até 6 níveis; fora de `node_modules`, `site-packages`) com trabalho, porque o git o ignora e nem bundle nem tar o guardam (busca cortada ou ilegível = recusa); repo aninhado em pasta de scratch (qualquer profundidade até 6) é arquivado à parte antes de a pasta mover; config do repo que roda programa (filter, gpg, diff/merge driver) = não lê, não arquiva, não move.
7. Processo vivo (cwd, claude/codex rodando, mtime < 1 h) = estado vivo, fora do plano. Cwd conta dentro do item e também no PROJETO dele: `node_modules` (E), unidade de scratch (D) e cache dentro de um repo (F) ficam vivos se um processo trabalha na pasta do projeto ou abaixo dela (motivo "a process works in the project"); projeto = HOME ou acima não vale. D: todas as unidades do projeto onde roda um claude/codex, não só a mais nova. Chegada também conta: a RAIZ do candidato com birthtime ou ctime < 1 h (árvore restaurada por `cp -a`, `rsync -a`, unzip, Time Machine, que mantém mtimes antigos) é estado vivo (`plan._stat_times`; só a raiz, sem varrer a árvore). O piso de 45 dias de A, B e C usa birthtime, nunca ctime (xattr do Spotlight sobe o ctime).
8. Recusa rodar como root/admin; zero sudo (só imprime comando).
9. Nomes vão ao agente só sanitizados e truncados; saída de git/rg passa por filtro. Em código: `scan` e `inventory` gravam o resultado cheio em arquivo 0600 e imprimem resumo (`views.py`); `check`, `undo` e `trash` passam por `views.scrub`; em QUALQUER comando, `error.message` e `error_details` passam por `views.scrub` e cada linha de stderr (`common.log`, inclusive o traceback) por `safety.sanitize_name` (300 caracteres); stderr do git e texto de erro de FS nunca entram em mensagem (só no manifesto).
10. Ganho = livre depois menos livre antes; Lixeira não esvaziada é dita.

## Tarefas (cada uma com aceite)
| # | Tarefa | Aceite |
|---|---|---|
| T1 | `platform.py` + `free` + `check` | teste unitário; `check` roda no mac |
| T2 | `safety.py` lista negra + normalização + sanitização | testes por variação (caixa, NFD, pai, symlink p/ ~/.ssh) |
| T3 | `trash.py` Lixeira mac/linux/win + manifesto + undo | fixture: move e restaura; recusa volume sem Lixeira |
| T4 | `scan.py` dua + básico | fixture APFS: dua exato; básico rotulado teto |
| T5 | `inventory.py` categorias A-L Claude+Codex por SO (L = pastas pesadas, só listadas) | lista candidatos reais no mac sem escrever nada |
| T6 | `plan.py` + `ask.py` | hash adulterado = recusa; formatos claude/codex/text |
| T7 | `archive.py` git bundle + verify | repo sujo arquivado e clonado do bundle |
| T8 | `bootstrap.py` + `pins.tsv` | hash errado = exit 20, nada executa |
| T9 | `report.py` treemap HTML | abre offline, zero request externo, CSP |
| T10 | SKILL.md, README (EN), NOTICE, categorias.md, CI 3 SOs | `claude plugin validate` não se aplica; frontmatter só 6 chaves |
| T11 | Revisão adversarial do diff (lente: apagar o que não devia) | zero achado com cenário concreto aberto |
