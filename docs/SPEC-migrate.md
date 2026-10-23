# CoreCleaner bônus: auditoria de repos e migração para disco externo
<!-- teto: isento (spec de build + fila de tarefas; encolhe conforme fecha) -->

Origem: pedido do dono em 2026-10-21. A prática manual de 24/09 está em `/Volumes/<disco>/Repos-arquivados/INDEX.md`: sem `node_modules`, tag `arquivo-AAAA-MM-DD/*` no GitHub e uma tabela "Onde mais existe".

## Decisões do dono
- **Depois da cópia conferida byte a byte**, o repo do Mac vai para a Lixeira (trava 4: nunca `rm`). Esvaziar a Lixeira é decisão do usuário. Sem symlink de volta.
- **Antes de mover**, publica o que não está no remoto como tag `arquivo-AAAA-MM-DD/<branch>`. Só vale para remoto cujo dono está numa lista de permitidos passada pelo usuário (`--push-owners a,b`); sem a lista, nada sobe. Nunca sobem:
  - branch citada numa nota "never push / nunca sobe / local-only" (keep_note);
  - branch `sec/*`;
  - repo sem remoto.
- **Oferecido para migrar:** só repo parado há 45 dias ou mais, contando o maior mtime da árvore fora de `node_modules`, contando só arquivos (mtime de pasta muda quando o Finder grava `.DS_Store`), ignorando arquivos do Finder e o interior do `.git` (só HEAD, ORIG_HEAD, logs/HEAD contam), e o último commit. Repo mais novo aparece na lista, mas não é oferecido. Ordem: maiores primeiro.
- **INDEX.md** na raiz do destino, criado ou atualizado com merge por linha. Colunas: Repo (caminho relativo), MB, Origem (`~/...`), Onde mais existe, Data, Manifesto.
  - Valores de "Onde mais existe": "enviado e conferido" (tags conferidas com `ls-remote`), "limpo no GitHub" (nada a enviar), "só no HD (sem remoto)", "pendência não enviada: <motivo>".
  - Uma linha existente com o mesmo Repo é substituída; o resto do arquivo fica intacto.
  - Gravação atômica: arquivo temporário e depois rename.

## CLI nova
| cmd | efeito | escreve? |
|---|---|---|
| `repos [--roots ...] [--min-days 45]` | Audita os repos git do HOME. Por repo: bytes (dua ou básico), bytes de `node_modules`, idade, sujo, stash, branches sem upstream ou à frente, remoto (host/dono), worktrees ligados, submódulos, nuvem, citações (mesma busca de dependência do inventory). Salva `repos/repos-<ts>.json` assinado (HMAC); stdout = resumo sanitizado. | só estado |
| `migrate-plan --repos F --to DIR` | Valida o destino e gera `plans/migrate-<ts>.json` assinado, com id, realpath, inode, mtime, bytes a copiar e `rel` do destino. Grupo 2: oferecido (parado 45+ dias). Grupo 3: só mostra, com motivo. | só estado |
| `migrate --plan F --ids ... [--apply] [--push-owners a,b]` | Dry-run por padrão. No `--apply`, por id: reconfere, publica as tags, copia, confere, grava o manifesto, atualiza o INDEX e manda para a Lixeira. Mesma regra do `trash`: `--apply` fora de terminal traz o aviso "no proof a person answered" em `warnings`; `CORECLEANER_REQUIRE_TTY_APPLY=1` recusa (exit 2). | sim |
| `undo --run R` | Já existe: restaura da Lixeira. A cópia externa fica. | sim |

## Travas (código)
1. **Destino:**
   - montado e em outro device (`st_dev`) que o HOME;
   - não pode ser filho de HOME, de pasta sincronizada nem da lista negra;
   - FS = APFS, HFS+ ou ext4/NTFS. FAT32 é recusado; exFAT também (sem symlink nem permissão, e o FAT32 ainda tem limite de 4 GB);
   - espaço livre ≥ bytes × 1,1 + 1 GiB;
   - colisão de caixa: o `rel` já existe com outra caixa = recusa;
   - `rel` já existe = recusa, salvo se o manifesto mostrar a mesma cópia já conferida (retomada idempotente).
2. **Repo recusado (grupo 3):**
   - processo vivo com cwd dentro;
   - mtime < 1 h;
   - worktree ligado fora da árvore (mover quebraria esse worktree);
   - submódulo com gitdir fora;
   - config de git que roda programa (gitguard);
   - repo em pasta de nuvem;
   - repo dentro da lista negra;
   - caminho com caractere de controle.
3. **Cópia:**
   - tudo menos `node_modules` que uma instalação refaz (`package.json` ao lado, lockfile ali ou acima, nenhum link saindo do repo), em qualquer nível; outro `node_modules` é conteúdo do projeto e vai junto; preserva symlink como symlink, modo, mtime e xattr (`ditto`/`cp -a` no mac; caminho Python portável);
   - nunca segue symlink para fora da árvore; arquivo especial (socket, fifo) é listado e não copiado.
4. **Conferência (antes de qualquer Lixeira):**
   - mesmo conjunto de caminhos (fora o `node_modules` deixado de lado);
   - mesmo tamanho e sha256 de cada arquivo regular;
   - mesmo alvo de cada symlink;
   - `git fsck --no-dangling` e `git status --porcelain` na cópia iguais ao original;
   - qualquer diferença = não move, apaga só a cópia parcial que ESTE run criou e relata.
5. **Releitura do original logo antes da Lixeira** (impressão: lista, tamanho, mtime fora `node_modules`). Mudou = não move. A cópia fica e o manifesto marca `stale`.
6. **Publicação:**
   - só `git push <remote> refs/heads/<b>:refs/tags/arquivo-<data>/<b>` e só para remoto com dono na lista;
   - conferida por `git ls-remote` (hash igual);
   - falha de push = item continua só com a cópia, e "Onde mais existe" registra a pendência;
   - stderr nunca vai ao agente.
7. **Manifesto por repo** em `<destino>/<rel>/.corecleaner-migrated.json`: origem, data, contagem, bytes, sha256 de uma lista ordenada (raiz Merkle simples), tags publicadas e versão do CoreCleaner.
8. A saída que vai ao agente é sanitizada (views.scrub). Não roda como root. Windows: beta, não testado.

## Tarefas
| # | Tarefa | Aceite |
|---|---|---|
| M1 | `repos.py` (auditoria) reusando `find_repos`, gitguard e a busca de dependência | fixture: 3 repos (velho grande, novo, worktree fora); ordem por bytes; idade certa; JSON assinado |
| M2 | `migrate_plan` (destino + grupos) | FAT32/exFAT/mesmo device/pouco espaço/colisão de caixa = recusa com motivo; teste por caso |
| M3 | cópia + conferência | fixture com symlink, arquivo executável, xattr (mac), node_modules: cópia sem node_modules, conferência ok; arquivo corrompido injetado = não move |
| M4 | publicação com allowlist | remoto bare local fazendo papel do GitHub: tag criada e conferida; dono fora da lista, `sec/*` e keep_note = nada sobe |
| M5 | INDEX.md merge atômico + manifesto | linha substituída, resto intacto; formato da tabela de 24/09 |
| M6 | Lixeira + reconferência + undo | original mudado entre conferência e Lixeira = não move |
| M7 | SKILL.md (seção "Bônus: migrar repos"), README, categorias | fluxo com perguntas em lotes, push só com a lista do usuário |
| M8 | revisão adversarial (lente: perder dado; lente: subir o que não devia) | zero achado com cenário concreto aberto |
