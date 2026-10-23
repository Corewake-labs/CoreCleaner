# Problems and resolutions

Pitfall log. One entry per problem met while building or dogfooding CoreCleaner: symptom, cause, fix, how it was measured.

## 2026-10-22 Finder's `.DS_Store` made every repo "idle 0 days"

- Symptom: first dogfood on the author's Mac, `repos` listed 98 repos, 37 GB of `node_modules`, and the top 50 all had `idle_days: 0`; `inventory` found zero category E (idle `node_modules`) candidates.
- Cause: Finder rewrote `.DS_Store` in dozens of repo folders the same morning (10:07). `repos.walk_sizes` and `inventory.newest_mtime` / `measure` took that mtime as an edit of the project. `repos` also counted every file under `.git` except `objects`, so a fetch or a `git status` index refresh read as an edit; `inventory._idle_days` counted `FETCH_HEAD`.
- Measurement: newest file outside `node_modules` per repo, with and without `.DS_Store` (scratch script over the sanitized `repos` JSON): with it, 48 of 50 repos "idle 0"; without, the newest entry was `.git` itself (a mass operation on 2026-09-24) and real idle times were 8 to 28 days.
- Fix: `inventory.is_noise` (`.DS_Store`, `.localized`, `Thumbs.db`, `desktop.ini`, `._*`) excluded from every newest-mtime in `inventory` and `repos`; only files and links count (a folder's mtime moves when Finder creates a `.DS_Store` inside it: measured, a project subfolder and the repo root bumped 4.8 days ago with no edit); inside `.git` only `HEAD`, `ORIG_HEAD`, `logs/HEAD` count in both modules; `FETCH_HEAD` (auto-fetch) and `index` (`git status` refresh: one repo read 27.9 days idle for an 86-day-old tree) dropped. Tests: `test_repos.AuditFixture` (noise and a browsed subfolder today) and `test_inventory.test_idle_projects_only`.
- Effect measured here: category E went from 0 to 2 to 14 candidates (611 MB); `repos` offered 14, then 22, then 36 of 100.

## 2026-10-22 Migrate code was hardened after its tests and docs were written

- Symptom: 6 failures in `tests/test_migrate.py` and `tests/test_repos.py` on an uncommitted tree.
- Cause: the final rules (a `node_modules` is left out only with `package.json` beside it and a lockfile; a path remote must be allowed as `local/<folder>`; a note naming no current branch holds every branch) were written after the fixtures, README, SPEC and categorias.
- Fix: fixtures and the four docs aligned with the code (`98eed93`); `test_migrate_review.py` already tested the final rules.

## 2026-10-22 Lens review (5 lentes + refutação, 33 agentes) and fresh-operator dogfood: 25 findings, 21 fixed in `test_dogfood_fixes.py`

- plan dropped inventory's `list_only` hint: Ollama/HF models, Codex history/logs, E unproven and F without a command came out group 2 `trash` (reproduced with real detectors). Fix: `plan._build_item` denies them (group 3).
- `find_repos` pruned dirs by NAME before looking for `.git` (a clone called `whisper`, `bun`, `uv` was invisible) and `_walk` emptied `dirnames` at the depth limit before yielding (a repo at depth 6 was never found; depth cut was not reported). A scratch unit with such a repo and an ignored `.env` was "sure junk" with no archive. Fix: `_walk` yields the full list and flags the depth cut; `prune` keeps a named dir that holds `.git`.
- Worktree candidates trusted `git worktree list`: a stale or forged entry made any idle folder a group 2 item. Fix: a folder without a `.git` file is shown only.
- Submodule configs were read with `--file ... --includes` from the outer repo, so an `includeIf "gitdir:"` there was judged in the wrong context and its filter ran during `git status`. Fix: any `[includeIf` in a module config is unsafe (`gitguard.CONDITIONAL`); the "git 2.26" label was misleading on git 2.54 and is now "could not be read in full".
- `git bundle create --all` lost `stash@{1..n}`; `--reflog` carries them (measured: present in the clone). Partial clones lazy-fetched during the bundle and ran `core.sshCommand`: `GIT_NO_LAZY_FETCH=1`.
- `needs_archive` missed commits reachable only from local tags; `incomplete` missed gitlinks without `.gitmodules` and `assume-unchanged`/`skip-worktree` edits.
- `find_protected_inside` returned `truncated=False` at its 20-hit cap: keys 21+ of an ignored `certs/` went to the Trash unarchived.
- Deny list lacked `.dev.vars`, `.envrc`, `*.tfstate`, `*.tfvars`, `credentials.json`, `service-account*.json`, `.pgpass`, `.htpasswd` and browser profile files (`Login Data`, `Cookies`, `Local State`, `key4.db`, `logins.json`).
- Duplicates (I) walked `~/Downloads` with no prune: a copy inside `node_modules` or a `.app` was offered. Fix: bundles and package trees are skipped.
- `claude_tmp_roots` followed a symlink at `<tmp>/claude-<uid>`: a planted link made every idle child of its target "scratch". Fix: symlinked roots are refused.
- No re-check between `_evaluate` and the move when nothing is archived (minutes of `needs_archive`): `_apply_item` now re-checks inode, realpath, mtime and live process right before the move.
- `/usr/bin/trash` without `-s` exits 0 on a refusal; its message was dropped. Fix: `-s -v`, message kept.
- `--raw` on `scan`/`inventory` was gated only by a SKILL sentence: refused off a terminal unless `CORECLEANER_ALLOW_RAW=1`.
- Playwright/Puppeteer downloads (not refilled by an install) were group 1 like package caches: now group 2.
- `free --path *` was pre-approved in `allowed-tools` and never used by the flow: removed.
- UX (fresh operators, 54 confusions logged in `~/.cache/claude-trabalho/corecleaner/2026-10-22/ux/`): questions name the folder of the item and, for duplicates, the copy that stays; "all N" never mixes categories and "One by one" expands one category (`--expand 2/I`); `node_modules` questions name the project and its idle time; `repos` prints offered rows first (20 of 22 were hidden behind `more`); migrate questions put Keep first and name the folder; the dry run says where the copy goes; SKILL step 11 runs tool commands from `~`; docs contradictions (eleven categories, "no rm", retention edit, Chrome restart, exit 44, two R2 rounds) fixed.
- Measured on this Mac after the fixes: category E went from 0 to 14 candidates (611 MB), `repos` offered 14 then 36 repos; the ground-truth sweep found 41 GB of regenerable folders inside repos, of which only 0.6 GB belongs to projects idle 30 days or more (the rest is active work and stays, by design).

## 2026-10-22 Backlog round: 8 Sonnet agents, one worktree each, 26 lines closed

- Merged in order trash, plan-refs, detectors, archive, scan-cli, ask-pt, arrival-tools, tests-hygiene (`--no-ff`, suite after each). Conflicts were all "both added" (prose paragraphs in SKILL/SPEC/README/categorias, code blocks in trash.py, plan.py, ask.py, tests/__init__.py): resolved by keeping both sides, prose at sentence level.
- Cross-branch breakage found only by the merged suite: hand-built plans in new tests lacked `created` once the plan-age check landed (trash, archive-quota); new fixed reasons from three branches lacked a pt text once the ask-pt drift guard landed; two new temp-dir prefixes failed the hygiene lint. All fixed in the merge commits.
- Suite: 836 tests before the round, 1156 after.
- Still deferred: Windows real run, dua real output, CI on three OSes, the Claude Code allowed-tools matcher.

## 2026-10-22 Report answered "where did the space go", not "where is the junk"; onboarding never asked about dua

- Symptom (owner, first real use): the HTML was a disk treemap the user had to drill folder by folder to find the candidates; the scan ran in basic mode because nobody asked whether to install dua, although SKILL step 3 says to ask.
- Fix: `report` opens on "Junk by folder" (every plan item under the folder that holds it, counts and bytes per folder, filters by group and category, search, id, action, reason, copy-path), the treemap is the second tab, texts in `settings.lang` (pt or en, reasons translated through `ask.translate_reason`); SKILL step 0 (onboarding) with `check.onboarding`, `bootstrap --decline`, `settings --lang`, all recorded in `~/.corecleaner/settings.json` so nothing is asked twice. `read_settings` never creates the state dir (`check` stays read-only, test caught it).
- Measured in chrome-devtools on the real page: 37 folders and 45 items rendered for groups 1 and 2, 0 console errors, map tab draws 5 blocks; the Write tool turned `\u25BE` into the glyph and broke `html.isascii()`, so the JS now carries the escapes.

## 2026-10-22 The pre-move recheck still counted Finder noise: 3 idle `node_modules` refused as "modified after the plan"

- Symptom (owner's first pasted reply, 39 ids): dry run `not_ok: 3`, the three biggest `node_modules` (499 MB) denied `changed since the plan: modified after the plan`.
- Cause: the 2026-10-22 `.DS_Store` fix covered `inventory` and `repos`, not `plan.measure`, which `recheck_item` uses: it took every folder's mtime and every `.DS_Store`. Measured: the newer entries were only `.DS_Store` files and the folders holding them (Finder, 13:07 the same day, 7 hours before the plan); no file changed after the plan.
- Fix: `plan.measure` newest = files and links only, `inventory.is_noise` left out (a directory root starts at 0). Test `test_dogfood_fixes.TrashLooksOnceMore.test_finder_noise_after_the_plan_is_not_an_edit_but_a_new_file_is`, red without the filter; `test_review_fixes.WindowsDeviceZero.test_a_real_other_device_still_stops_the_descent` now plants a newer file behind the other mount (it relied on folder mtimes).
- Trade-off: an old file moved INTO a planned folder after the plan keeps its old mtime and is not seen; the inode check still catches a replaced root.

## 2026-10-22 Local snapshots read as the cause of the whole GAP; SKILL.md carried merge duplicates

- Symptom: the agent told the owner the 117 GB GAP was Time Machine local snapshots before measuring. Measured afterwards: 3 snapshots, all from the same day; `sudo du` of the Data volume = 300 GiB of files vs 398 GB used; `tmutil deletelocalsnapshots /` (run by the owner, no sudo) freed about 48 GB. So part of the GAP was snapshots, the rest system volumes (26 GB) and root-only folders.
- Owner's ask: a skill that does not oversell ("salvar o mundo"), and says macOS manages snapshots on its own.
- Fix: SKILL.md rewritten (26.6k to 19.0k chars): "Expectations" section (leftovers are hundreds of MB to a few GB; never assign the GAP to one cause), step 12 explains snapshots (made before each backup even to an external disk, no switch to turn off, about 24 h, purgeable, deleted when space is needed; tips: keep the disk connected or back up manually), prevention only on request. Removed merge residue: "What the script refuses" was there 4 times, exit codes and plan groups twice. `manual_command` and the scan hint drop `sudo` (measured: not needed).

## 2026-10-22 CI emailed a failure on every push (6 jobs, all red)

- Symptom: one "Run failed" email per push, README pushes included; macOS, Linux and Windows x Python 3.9 and 3.13.
- Causes (CI was never green): Windows (beta) fails about 140 tests; Linux showed 2 product bugs, `check` creating the state dir from the case probe (`platform_info._state_dir_probe` called `state_dir()`) and `undo` accepting a reused ext4 inode number; the rest were tests tied to the author's Mac (fake Trash at `~/.Trash`, `rg` assumed, git's `maintenance.lock` vanishing mid-walk).
- Fix: 2 jobs (macOS 3.13, Linux 3.9) only when `skills/`, `tests/` or the workflow change; Windows by hand. Probe uses `state_dir_path()`; `undo` also compares mtime_ns off macOS; tests set `GIT_CONFIG_COUNT` (maintenance.auto false, gc.auto 0). Run 39883496192: both jobs green.
