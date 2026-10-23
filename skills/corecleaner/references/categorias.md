# CoreCleaner categories A-L
<!-- teto: isento (registry: tabela por categoria e SO; o tamanho e o dado) -->

Source of truth is `scripts/corecleaner_lib/inventory.py`; this file is the map. `inventory` is read-only: it lists, it never decides. `action` on a candidate is a hint (`trash`, `tool_command`, `archive_then_trash`, `list_only`); `plan` decides. Windows rows are BETA, untested.

## Rules that hold for every category
- Size: `st_blocks*512` (Windows `st_size`), hardlinks counted once, symlinks never followed. On macOS it is an upper bound (APFS clones share blocks): `evidence.size.upper_bound`. The gain is `free_after - free_before`, never this number.
- Age: days since the newest mtime INSIDE the candidate. Exception E: days since the newest edit of the PROJECT outside `node_modules`/`.git` (plus `.git` HEAD, ORIG_HEAD, logs/HEAD) or its last commit. Only files and links count as edits: a folder's mtime moves when Finder writes a `.DS_Store` in it, and Finder and Explorer files (`.DS_Store`, `.localized`, `Thumbs.db`, `desktop.ini`, `._*`) never count anywhere (`inventory.is_noise`).
- Arrival (`plan`, not `inventory`): a candidate ROOT whose birthtime or ctime is under 1 h old is live state too (group 3, deny "arrived less than 1 h ago"), because `cp -a`, `rsync -a`, unzip and Time Machine restore keep old mtimes on a new inode. Only the root is stat'ed. ctime moves with chmod, xattrs and renames, so it can only hold an item back for an hour. The 45-day floor of A, B, C also waits from the root's birthtime, never from ctime. macOS rewinds a birthtime when a tool sets an older mtime, so after `cp -a` only ctime still shows the arrival (the 1 h rule); the birthtime floor is a weaker, extra check. Tests patch `plan._stat_times`.
- Live state, any hit = `live_process` and `action=list_only`: mtime < 1 h; a process whose cwd is inside the path (`lsof -d cwd`; Linux fallback `/proc/*/cwd`); A and D: the newest transcript/scratch unit of a project folder where a `claude`/`codex` process runs.
- Live state, any hit = `live_process` and `action=list_only`: mtime < 1 h; a process whose cwd is inside the path (`lsof -d cwd`; Linux fallback `/proc/*/cwd`); E, D, F: also a process whose cwd is the project of the candidate or below it, reason "a process works in the project" (E: git root above the `node_modules`, else its folder; D: the Claude project dir of the unit, compared by encoded cwd; F: the git repo the cache sits in; HOME or above is never a project; `trash` applies the same rule, exit 43); A: the newest transcript of a project folder where a `claude`/`codex` process runs; D: every scratch unit of that project folder (an older session may be the one still open).
- Dependency: ONE `rg -F -f` (limit 150 s, `-i` where the volume ignores case) for every candidate path. Result: `referenced_by` (<= 10 files, sanitized), `referenced_by_total`, `keep_note` (a referencing line says manter/keep/do not delete). A hit is a live dependency: plan puts the item in group 2 (never 1) with `reason` "live dependency: cited by N file(s)". Hits inside the candidate itself do not count.
  - Read: agent instructions, settings, memories, skills, hooks; shell start-up files (`.zshrc`, `.bashrc`, `.profile`, `.gitconfig` ...), `~/.config`, `~/bin`, `~/.local/bin`, `~/Library/LaunchAgents`; the WHOLE tree of every visible folder of HOME (a link to another volume is followed), session folders and the owners of the node_modules found; `crontab -l`; a walk for symlinks that point into a candidate (node_modules two levels deep).
  - Not read of HOME: Library, Applications, Movies, Music, Pictures, Public, Downloads, go, snap, `~/.cache`.
  - Files: text up to 2 MB. Skipped FOLDERS (a FILE named build or dist is read): node_modules, dist, build, target, vendor, .next, worktrees, browser-profile caches, `.git/{objects,logs,lfs,refs}`; `.git/config`, hooks and FETCH_HEAD are read. Skipped files: `*.jsonl`, `*.lock`, `*.sqlite*`, binaries, `*.min.js`, `*.map`.
  - Patterns, each in NFC and NFD, JSON-escaped (`\/`), space-escaped and percent-encoded: absolute, every other name the path has under a linked ancestor, `~/`, `$HOME/`, `${HOME}/`, `"$HOME"/`, relative to HOME (two or more segments), `$XDG_CACHE_HOME/`, `$TMPDIR/`, `$CLAUDE_CODE_TMPDIR/` ... (and `${VAR:-x}/rel`), `/tmp` for `/private/tmp`, `%USERPROFILE%` and `%TEMP%` on Windows. A hit on a longer path (a file INSIDE the candidate) counts; a longer name (`lib-b`, `lib.bak`) does not.
  - Assembled paths (`path.join(home, ".cache", "x", "lib")`, `cd parent && ./lib`) cannot be proven by text: for categories B, C, D, F, G the likely forms (last two names as separate strings, a standalone parent folder, `a/b`) add `evidence.unverified` "referenced_by: possibly cited ..." with the files. The guess is narrow: the candidate's own folder name must have 6 or more characters and not be a generic word (`inventory.REF_WEAK_STOP_NAMES`: `mine`, `theirs`, `repo`, `tmp`, `clone` ...), and a `*.log` (or `*.log.N`) never produces one (a log names temp folders all day); the whole-path search still reads logs.
  - Unfinished: no `rg`, deadline, rg error, a cloud-synced folder left unread or a symlink walk past its budget = `evidence.unverified` "referenced_by: ..." and `meta.reference_search.status`; plan then keeps every would-be group 1 item (C, D, empty, tool-command caches) in group 2.
  - Invisible (`meta.reference_search.not_searched`): files outside HOME (/opt, other volumes unless HOME links to them), the unread folders and files above, files over 2 MB, a path built from an unknown variable or assembled in code in a form the patterns do not guess.
- Git (repos, worktrees, clones): `status --porcelain --untracked-files=normal`, `log --branches --not --remotes`, `log HEAD --not --remotes` (detached HEAD), `stash list`, `remote`, `config remote.origin.url` (credentials stripped), `log -1`. Always `--no-optional-locks`, `core.fsmonitor=false`. Any failure (no git, timeout, foreign owner, orphan gitdir) = `dirty=true` with `error`: cannot prove clean.
  - "Published" (`unpushed` 0, `head_on_remote`) is read from LOCAL remote-tracking refs; the server is never contacted, so a branch deleted there still counts. `git.remote_checked` is therefore always `false` (kept by `plan`), and `ask` adds "published by local refs, not checked against the server" to the question of a clean B, C or D item that goes to the Trash without an archive.
  - `git.ignored_large` = `{count, bytes}` (+ `approx` when the sizing hit its budget): files inside ignored paths of 10 MiB or more (`archive.IGNORED_MIN_BYTES`; `status --porcelain -z --ignored`, a fully ignored folder is one entry, apparent bytes), the same data `archive` lists as "ignored large, NOT archived". A `node_modules` an install rebuilds (`package.json` beside it and a lockfile) is not counted. If that status fails, `unverified` says so and the count stays 0.
- Candidate inside another candidate is merged into the outer one (risk OR-ed, `evidence.contains`).
- Protected (deny list) or cloud/placeholder: still listed, `protected`/`cloud` true, `list_only`; cloud trees are not walked (`bytes=0`).
- Virtual items (`virtual=true`: `tmutil:<date>`, `journal:disk-usage`, `process:<pid>`) are not paths: never realpath, stat or trash them.
- Never listed: credentials, `auth.json`, `settings*.json`, `CLAUDE.md`, `AGENTS.md`, agent memories (`projects/*/memory`, `memory/`, `memories/`), browser profiles, installed apps.

## Thresholds
| Category | Default | Const |
|---|---|---|
| A history | idle >= 45 d (plan floor) | `AGE_HISTORY_DAYS` |
| B user worktree (outside agent dirs) | idle >= 45 d, or prunable/gitdir missing; agent worktrees listed, offered only at 45 d | `AGE_USER_WORKTREE_DAYS` |
| D scratch unit | idle >= 7 d | `AGE_SCRATCH_DAYS` |
| E node_modules | project idle >= 30 d + `package.json` + lockfile | `AGE_NODE_MODULES_DAYS` |
| L project folders (`.wrangler`, `.venv`, `dist` ...) | project idle >= 30 d (same `_idle_days`) + no change to a tracked file | `AGE_NODE_MODULES_DAYS`, `L_PROJECT_SECONDS` |
| I duplicates | file >= 1 MiB | `MIN_DUP_BYTES` |

## A. Agent history
| kind | path (same on every OS; Windows `%USERPROFILE%\.claude`, `.codex`) | action |
|---|---|---|
| claude.transcript | `$CLAUDE_CONFIG_DIR or ~/.claude` `/projects/<cwd-encoded>/<uuid>.jsonl` | trash |
| claude.session_dir | `projects/<cwd-encoded>/<uuid>/` (subagents, tool-results) | trash |
| claude.file_history | `file-history/<uuid>/` | trash |
| claude.debug | `debug/*` (symlinks such as `latest` skipped) | trash |
| claude.shell_snapshot | `shell-snapshots/*` | trash |
| claude.todos | `todos/*` | trash |
| claude.plan | `plans/*` | trash |
| codex.session | `$CODEX_HOME or ~/.codex` `/sessions/YYYY/MM/DD/rollout-*.jsonl` | trash |
| codex.archived_session | `archived_sessions/*.jsonl` | trash |
| codex.log | `log/*` | trash |
| codex.history | `history.jsonl`, always listed | list_only (retention is `[history] max_bytes`) |
| codex.logs_db | `logs_*.sqlite` | list_only (state database) |

Retention is read, never changed: `meta.retention` = Claude `cleanupPeriodDays` (settings.json), Codex `[history] max_bytes`, `persistence`.

## B. Worktrees
| kind | where | notes |
|---|---|---|
| worktree | `<repo>/.claude/worktrees/*` for every known repo | owner claude; known repos = cwd of recent Claude transcripts + stray clones |
| worktree | `git worktree list --porcelain` of each known repo (non-main entries) | owner claude / codex by path, else user (age gate) |
| worktree | `$CODEX_HOME/worktrees/<id>[/<name>]` (dir holding `.git`) | owner codex |

Evidence: `gitdir_missing` (`.git` file points nowhere), `prunable`, `main_repo`, `followup_command` (`git -C <main> worktree prune`, printed, not run), `git.head_on_remote`. Dirty, unpushed, stash or unreadable git = `archive_then_trash`. A branch kept local on purpose is the owner's word, not git's: `repos.never_push` reads the worktree and its main repo (README/NOTES/CLAUDE/docs lines such as "never push", "nunca sobe", "local-only", committed at the tip too, and `branch.<b>.description`); a line that names this branch, or no branch at all, sets `keep_note` and `local_only_note`, and `plan` shows the worktree in group 3 ("kept: a note in the repo says this branch is local-only (never push)"). Notes it could not read to the end keep it too. Not run for a live or unreadable (`git.error`) worktree.

## C. Stray clones (`.git` anywhere under these roots, not inside a repo, node_modules or a tool cache)
| root | depth | owner |
|---|---|---|
| `~/.cache` (skips uv, pip, npm, pnpm, bun, yarn, go-build, Homebrew, ms-playwright, puppeteer, huggingface, torch, whisper, venvs) | 6 | unknown |
| `$CODEX_HOME/{cache,tmp,.tmp}` | 6 | codex (the app may re-create what it manages here) |
| OS temp bases (macOS `/private/tmp`, `/tmp`, `$TMPDIR`; Linux `/tmp`; Windows `%TEMP%`) | 3 | unknown |

kind `scratch.clone`, no age gate at inventory (age is evidence; `plan` keeps a 45-day floor for A, B, C). Clean + pushed = `trash`; otherwise `archive_then_trash`. A clean, pushed clone (or a D unit holding one) that has ignored data the archive does not carry (models, `.wrangler/state`; `evidence.git.ignored_large`) is NOT group 1: `plan` puts it in group 2 with `reason` "ignored data not archived: N file(s), X", and `ask` names it in the question and asks it alone.

## D. Agent scratch
| OS | root |
|---|---|
| macOS | `/private/tmp/claude-<uid>` (also under `$TMPDIR`), `$CLAUDE_CODE_TMPDIR[/claude-<uid>]` |
| Linux | `/tmp/claude-<uid>`, `$CLAUDE_CODE_TMPDIR[/claude-<uid>]` |
| Windows | `%TEMP%\claude`, `%CLAUDE_CODE_TMPDIR%` |

Only `claude-<uid>` (or the folder `$CLAUDE_CODE_TMPDIR` names) is a root; the other folders of a shared temp dir (`$TMPDIR/tmp.*` from `mktemp -d`, other tools) are never scratch. A `$CLAUDE_CODE_TMPDIR` that is itself a shared dir (`/tmp`, `/private/tmp`, `$TMPDIR`, `$TMP`, `$TEMP`) or HOME and has no `claude-<uid>` inside is refused as a root.

Units: `<root>/-<project>/<session-uuid>/` is one unit; any other direct child of the root is its own unit. kind `claude.scratch`, idle >= 7 d. A unit carries the aggregated git evidence of every repo inside it (`evidence.repos`); those repos are not listed twice.

## E. Idle node_modules
Found under HOME (depth 7), skipping hidden dirs, `Library`, `Applications`, `Movies`, `Music`, `Pictures`, `venv`, `site-packages`, `target`, `vendor`, agent dirs and synced folders. Needs `package.json` beside it and a lockfile beside it or up to the project root (nearest `.git`). `evidence.reinstall`: bun.lock/bun.lockb `bun install`, pnpm-lock.yaml `pnpm install`, yarn.lock `yarn install`, package-lock.json/npm-shrinkwrap.json `npm ci`. Project too large to prove idle = `list_only`.

## F. Tool caches: own command or nothing (`action=tool_command`, never Trash)
Path order: env var, then the tool's own answer (`dir_cmd`), then the default. No command available on this machine = `list_only`. Self-refilling caches (group 1 even when cited): uv, pip, npm, pnpm, bun, go modules (`plan.SELF_REFILLING`); everything else with a command is group 2. `npx` looks in `./node_modules/.bin` first and downloads what it cannot find, so its commands carry `--no-install` and run from `~` (SKILL step 11).
| kind | env | macOS | Linux | Windows | command |
|---|---|---|---|---|---|
| cache.uv | UV_CACHE_DIR | `~/.cache/uv` | `$XDG_CACHE_HOME/uv` | `%LOCALAPPDATA%\uv\cache` | `uv cache clean` (`uv cache dir`) |
| cache.pip | PIP_CACHE_DIR | `~/Library/Caches/pip` | `~/.cache/pip` | `%LOCALAPPDATA%\pip\Cache` | `pip cache purge` (`pip3` if that is all there is) |
| cache.npm | npm_config_cache | `~/.npm` | `~/.npm` | `%LOCALAPPDATA%\npm-cache` | `npm cache clean --force` (`npm config get cache`) |
| cache.pnpm_store | npm_config_store_dir | `~/Library/pnpm/store` | `$XDG_DATA_HOME/pnpm/store` | `%LOCALAPPDATA%\pnpm\store` | `pnpm store prune` (`pnpm store path`); hardlinked into projects, real gain is smaller |
| cache.bun | BUN_INSTALL_CACHE_DIR | `~/.bun/install/cache` | same | same | `bun pm cache rm` |
| cache.yarn | YARN_CACHE_FOLDER | `~/Library/Caches/Yarn` | `~/.cache/yarn` | `%LOCALAPPDATA%\Yarn\Cache` | `yarn cache clean` |
| cache.cargo_registry, cache.cargo_git | none | `$CARGO_HOME or ~/.cargo` `/registry`, `/git` | same | same | `cargo cache --autoclean` only when the `cargo-cache` plugin exists; cargo has no built-in command, else `list_only` |
| cache.go_build | GOCACHE | `~/Library/Caches/go-build` | `~/.cache/go-build` | `%LOCALAPPDATA%\go-build` | `go clean -cache` (`go env GOCACHE`) |
| cache.go_mod | GOMODCACHE | `$GOPATH or ~/go` `/pkg/mod` | same | same | `go clean -modcache` |
| cache.homebrew | HOMEBREW_CACHE | `~/Library/Caches/Homebrew` | `~/.cache/Homebrew` | n/a | `brew cleanup --prune=all` (`brew --cache`); it also removes old versions of installed formulae and other Homebrew leftovers, not only downloads (`brew cleanup --help`), so it is never self-refilling: group 2 with a warning in the question |
| cache.playwright | PLAYWRIGHT_BROWSERS_PATH | `~/Library/Caches/ms-playwright` | `~/.cache/ms-playwright` | `%LOCALAPPDATA%\ms-playwright` | `npx --no-install playwright uninstall --all` (downloads nothing; fails if playwright is not already installed) |
| cache.puppeteer | PUPPETEER_CACHE_DIR | `~/.cache/puppeteer` | same | `%USERPROFILE%\.cache\puppeteer` | `npx --no-install @puppeteer/browsers clear --path <dir>` (downloads nothing; asks yes/No on stdin) |
| cache.scoop | none | n/a | n/a | `%USERPROFILE%\scoop\cache` | `scoop cache rm *` |
Not covered: Windows winget, pipx. Docker, Gradle, Maven and Xcode build output are category L (listed only).

## G. Downloaded models: always `list_only`; the user picks which model goes
| kind | path | hint |
|---|---|---|
| model.huggingface | one item per `$HF_HUB_CACHE or $HF_HOME/hub or ~/.cache/huggingface/hub` `/{models,datasets,spaces}--*` | `hf cache ls; hf cache rm <repo>` |
| model.ollama | `$OLLAMA_MODELS or ~/.ollama/models` | `ollama list; ollama rm <model>` |
| model.torch | `$TORCH_HOME or ~/.cache/torch` | delete a checkpoint by hand |
| model.whisper | `~/.cache/whisper` | delete a model file by hand |
| model.lmstudio | `~/.lmstudio/models`, `$XDG_CACHE_HOME or ~/.cache` `/lm-studio/models` | LM Studio "My Models", or delete a model folder by hand |
| model.llamacpp | `$LLAMA_CACHE`, else `$XDG_CACHE_HOME or ~/.cache` `/llama.cpp` and `~/Library/Caches/llama.cpp` | delete a `.gguf` file by hand |

## H. Raw already transformed: NOT detected
Needs a per-item match by identifier between the raw file and its derivative (transcript, summary, sidecar, database). The agent does it, one item at a time, then adds the confirmed raws to the plan. A raw without a derivative stays.

## I. Duplicates
`~/Downloads` (depth 6), files >= 1 MiB: same size, then sha256 of head+tail, then sha256 of the whole file. Hardlinks are one file. Keeper = not named like a copy (`(1)`, `copy`, `cópia`), then oldest mtime, then shortest path; the other copies are candidates (`evidence.keeper`, `duplicate_key`). Synced Downloads and dataless files (`st_blocks=0`) are never read. On APFS a copy may be a clone: the gain is unknown. Desktop and media folders are not scanned yet.

## J. What the OS holds (always `list_only`)
| kind | macOS | Linux | Windows |
|---|---|---|---|
| os.code_sign_clone | `$(dirname "$(getconf DARWIN_USER_TEMP_DIR)")/X/*code_sign_clone`; only a reboot frees it (`recommend=reboot`); `gain_unknown` (clones) | n/a | n/a |
| os.tm_snapshot (virtual) | `tmutil listlocalsnapshots /`; one item per date, size unknown; macOS deletes them on its own (about 24 h, or sooner when space is needed); `manual_command=tmutil deletelocalsnapshots <date>` (no admin) printed, never run | n/a | n/a |
| os.journal (virtual) | n/a | `journalctl --disk-usage`; `manual_command=sudo journalctl --vacuum-time=30d` printed | n/a |
| os.trash | `~/.Trash` | `$XDG_DATA_HOME/Trash` | not listed (needs admin) |
| os.temp | n/a | n/a | `%TEMP%` size |
Not covered: Linux snap old revisions, Windows shadow storage (`vssadmin`, admin).

## K. Forgotten processes (virtual, `list_only`, never killed)
`ps -axww -o pid=,etime=,rss=,command=` (Windows `tasklist`). Listed: executables `ffmpeg soffice inkscape mitmdump mitmproxy mitmweb cloudflared ocrmypdf tesseract vhs auto-editor magick vips chrome-headless-shell headless_shell`, and command lines with `--headless`, `--remote-debugging-port`, `http.server`, `php -S`, or a dev server (`vite astro next wrangler webpack-dev-server nodemon live-server` with `dev`/`serve`). Browser helpers (`--type=`) and `claude`/`codex` themselves are skipped. Evidence: `pid`, `name`, `rss_bytes`, `running_for_s`, `cwd`; the command line is never forwarded (it may hold tokens).

## L. Other heavy folders: always `list_only`, size only, never in the Trash group
Found on the author's Mac on 2026-10-22 and seen by no other category (`.wrangler` 6.3 GB, `.build` 1.3 GB, `.venv`, `dist`, `.next`, DerivedData). `plan` forces group 3 for L whatever the candidate says; the user clears them by hand. Owner `user` for project folders, `tool` for the rest.

Per-project regenerables (kind `project.<name>`) are found on the same HOME walk as E (no second walk; same depth, budget, prune list and synced-folder skip) and listed only when ALL hold:
- the folder sits inside a git repo (nearest `.git` below HOME) that is not in a synced folder;
- the project is idle >= 30 d by `_idle_days` (the rule of E: newest file edit outside `node_modules`/`.git`, or last commit; unproven = not listed and counted in `meta.warnings`);
- no change to a tracked file (`status --porcelain --untracked-files=no`; repo config that runs programs, git failure or no git = not clean = not listed);
- the name is proof enough: `.wrangler`, `.build`, `.next`, `.nuxt`, `.astro`, `.turbo`, `.parcel-cache`, `.gradle`, `.terraform`; `.venv` and `venv` also need `pyvenv.cfg` inside; `dist`, `build`, `target`, `coverage`, `Pods` also need the repo's own `.gitignore` to cover them (`git check-ignore`), because they can be source or vendored code;
- a folder inside another folder found here is part of it (one item).
An active project keeps its folders and lists nothing: the 41 GB found inside repos on 2026-10-22 were 0.6 GB for idle projects. The probes of idle time and `git status` stop at `L_PROJECT_SECONDS` (120 s); the rest is "not proven". `evidence`: `project`, `project_idle_days`, `regenerable`; a process whose cwd is in the project makes it live (see Live state).

Outside projects (always listed when the folder exists; `reason` is a fixed label):
| kind | macOS | Linux | Windows |
|---|---|---|---|
| dev.xcode_derived_data | `~/Library/Developer/Xcode/DerivedData` | n/a | n/a |
| dev.xcode_device_support | `~/Library/Developer/Xcode/{iOS,watchOS,tvOS,visionOS} DeviceSupport` (one item each) | n/a | n/a |
| dev.core_simulator | `~/Library/Developer/CoreSimulator/Devices` (apps and data of simulators: `xcrun simctl delete unavailable` is the safe subset) | n/a | n/a |
| dev.gradle | `$GRADLE_USER_HOME or ~/.gradle` `/caches` | same | same |
| dev.maven | `~/.m2/repository` | same | same |
| app.electron_cache | `~/Library/Application Support/<app>/{Cache,Code Cache,GPUCache,DawnCache,GrShaderCache,ShaderCache,CachedData,Service Worker/CacheStorage}` | `$XDG_CONFIG_HOME or ~/.config` `/<app>/...` | `%APPDATA%\<app>\...` |
| agent.backup | `$CLAUDE_CONFIG_DIR or ~/.claude` `/*.bak*` (top level only; deny-listed ones come with `protected`) | same | same |
| dev.docker (virtual, `docker:system-df`) | `docker system df --format '{{json .}}'` when the daemon answers in 5 s; size = sum of the reported sizes, `evidence.docker` = per type size and reclaimable, `manual_command` `docker system prune` printed, never run; no answer = `meta.unverified` | same | same |
`app.electron_cache` counts only an app folder that holds a `Code Cache`, `GPUCache` or `Local Storage` (direct children of the app-data folder; Chromium browsers nested under a vendor folder are not walked). Models of LM Studio and llama.cpp are G.

## Bonus R. Big idle repos (`repos`, `migrate-plan`, `migrate`)
| Rule | Value | Const |
|---|---|---|
| offered for the external disk | idle >= 45 d (newest FILE mtime outside `node_modules`, Finder files and `.git` internals other than HEAD, ORIG_HEAD, logs/HEAD; or last commit) | `repos.MIN_IDLE_DAYS` |
| copy | everything except a `node_modules` an install rebuilds (`package.json` beside it, lockfile there or above, no link leaving the repo), at any level | `migrate_copy.SKIP_NAMES`, `migrate_copy.regenerable_node_modules` |
| destination space | free >= bytes x 1.1 + 1 GiB | `migrate.SPACE_FACTOR`, `migrate.GIB` |
| destination filesystem | APFS, HFS+, ext4, NTFS (FAT32 and exFAT refused) | `migrate.ALLOWED_FS` |
| tag name | `arquivo-YYYY-MM-DD/<branch>` | `migrate.TAG_PREFIX` |
Shown only (group 3): live, linked worktree outside the tree, submodule gitdir outside, alternates, `core.worktree`, repo config that runs programs, cloud folder, deny list, control characters, case clash or occupied folder on the disk.
