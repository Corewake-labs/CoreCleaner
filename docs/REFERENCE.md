# CoreCleaner reference

How each command works, what it refuses and where its limits are. The overview is in the [README](../README.md); the contract of every subcommand is [SPEC.md](SPEC.md).

## What it does

1. `check` and `free`: OS, Trash availability, free bytes. Both are safe to pre-approve.
2. Onboarding, once: the agent asks whether to install one pinned [dua](https://github.com/Byron/dua-cli) build (downloaded over HTTPS, sha256 checked against `skills/corecleaner/references/pins.tsv`, installed to `~/.local/bin`) and which language to use; both answers are recorded in `~/.corecleaner/settings.json` and never asked again (`settings --dua ask` forgets the dua answer). Without dua the scan uses a slower built-in mode and labels every size as an upper bound.
3. `scan` and `report`: a disk map, plus one offline `report.html` (no network, strict CSP, names rendered as text) that opens on "Junk by folder": every candidate of the plan under the folder that holds it, with counts and bytes per folder, filters by group and category, search by path, and each item's id, action and reason. The disk treemap is the second tab; the part of the disk the scan cannot explain is drawn as a hatched GAP block, never hidden. When the roots are not a whole volume (the default), the gap is labelled "outside the scanned roots" and the scan measures, within 20 s, the folders no root contains (`/private`, other users, and so on) and lists the other volumes of the same APFS container.
4. `inventory` and `plan`: candidates in eleven detected categories (the twelfth, raw files already summarized, needs you; one of the eleven, heavy folders such as a `.wrangler`, a `.venv`, Xcode or Docker data, is only listed with its size) (`skills/corecleaner/references/categorias.md`), each with evidence: git state, age, a running process inside it, other files that mention its path. `plan` takes only the file `inventory` just saved and writes a file with ids, real paths, sizes, inodes, a hash and a signature.
5. `ask`: questions in batches of at most 4, safest option first, "keep" always there, and an "all N" option only within one category.
6. `trash`: dry run by default. Before `--apply` it re-checks each item (still there, same inode, nothing newer inside, not a link, nobody working in it), archives repos with unsaved work, also repos nested inside a scratch folder (git bundle, patch, untracked files, ignored `.env` and key files, verified by cloning), checks again that nothing changed while it archived, then uses the OS Trash and writes a manifest, each line signed with the same key as the plan. `undo` restores from it, ignores a line that fails the signature, and moves back only the very item the run moved (same inode and device) and only from this user's own Trash folder. `trash` exits 46 when a requested id was not moved (denied, failed or skipped), after printing every row.
7. `free` again, and optional retention settings (`cleanupPeriodDays` for Claude Code, `[history] max_bytes` for Codex), each only with a yes.

## Bonus: move big idle repos to an external disk

Ask "which repos are biggest, move the old ones to my HD". Three commands, same rules as the rest:

1. `repos`: every git repo under your home folder, biggest first, with the `node_modules` share, days idle (newest file outside `node_modules`, ignoring Finder files such as `.DS_Store` and git's own bookkeeping, or the last commit), uncommitted work, stashes, branches on no remote, remote owners, linked worktrees, and other files that cite the path. Read-only; the full list is saved signed in the state folder.
2. `migrate-plan --repos <file> --to /Volumes/<disk>/Repos-arquivados`: checks the folder (another device than your home, not inside it, not synced, not FAT32 or exFAT, room for the copy plus 10% and 1 GiB) and offers only repos idle for 45 days or more. A linked worktree outside the repo, a submodule gitdir elsewhere, borrowed objects, a repo config that runs programs, a cloud folder, a live process or a case clash on the disk keeps a repo shown only.
3. `migrate --plan <file> --ids ...` (dry run) and then `--apply`. Unpublished branches become tags `arquivo-YYYY-MM-DD/<branch>`, but only with `--push-owners you,your-org` (a bare name means github.com; another host is `host/owner`, a path on disk `local/<folder>`), only to a remote whose every push URL belongs to one of them, never for `sec/*`, a branch a note in the repo keeps local ("never push", "nunca sobe", "local-only") or a branch that carries their commits, and each tag is checked with `git ls-remote`. Then the repo is copied without `node_modules`, when an install rebuilds it (`package.json` beside it, a lockfile there or above, no link leaving the repo; any other `node_modules` is project content and goes along), with links kept as links and mode, times and extended attributes preserved, verified file by file with sha256 plus `git fsck` and `git status`, given a manifest (`.corecleaner-migrated.json`, with a sha256 over the sorted file list), listed in `INDEX.md` at the destination, read once more, and only if nothing changed moved to the Trash. `undo --run <id>` brings it back; the copy stays.

`INDEX.md` is a table, one row per repo:

```
# Repos arquivados (CoreCleaner)

| Repo | MB | Origem | Onde mais existe | Data | Manifesto |
|---|---|---|---|---|---|
| Documents/old-site | 812 | ~/Documents/old-site | enviado e conferido | 2026-10-21 | Documents/old-site/.corecleaner-migrated.json |
```

"Onde mais existe" tells you whether the disk holds the only copy: `enviado e conferido` (tags pushed and checked), `limpo no GitHub` (nothing to push), `só no HD (sem remoto)`, or `pendência não enviada: <reason>`. Moving a repo again replaces its row; every other line you wrote in the file stays.

## What it never does

- Permanent delete of your data. No `rm`, no `rmtree`, no `--force` on anything it did not create itself (it removes only its own temp files and a failed copy of the same run). A volume without a Trash is refused. A tool's own cleanup command (step 6) is the one permanent action, and you approve it twice.
- Touch credentials, keys, agent settings and memories, browser profiles, your home folder itself, or its own state. The one exception is the retention key of step 7, changed only after your yes. The deny list is code plus `references/never-touch.txt`, matched case-insensitively where the filesystem is, after Unicode normalization and `realpath`, and it covers every parent of a protected path.
- Act on a path. `trash` accepts ids from a plan that `plan` wrote, whose hash and signature still match, nothing else. A plan or a candidate list written or edited by hand is rejected (exit 41), and one older than 12 hours is refused too (exit 42, "re-run inventory"): the files that cite a path and the processes working in it are frozen on the day it was made.
- Run as root, or use `sudo`. Commands that need it are printed for you.
- Run a tool's own cleanup command. It tells the agent the command; the agent runs it only after you approve it separately.
- Empty the Trash. Deleted-to-Trash space comes back only when you empty it.
- Touch synced folders (iCloud, OneDrive, Dropbox, Google Drive) or cloud placeholder files. They are listed only.

## Limits

- Nothing here proves a human is answering. In a bypass or full-auto mode the agent can "answer" for you. The code still refuses what it can know is wrong (deny list, altered plan, changed item, live process), but it cannot tell who clicked yes. What it can see is whether stdout is a terminal: `trash --apply` and `migrate --apply` off a terminal (an agent always is) add the warning "no proof a person answered" to the result. Set `CORECLEANER_REQUIRE_TTY_APPLY=1` and they refuse instead (exit 2), so a person has to run the `--apply` command in their own terminal.
- File and folder names go to your model provider. The summaries that reach the agent (`scan`, `plan`, `ask`, `trash`) carry names stripped of control and bidirectional characters and truncated, and the skill tells the model to treat them as data. That lowers the risk of a folder called "ignore your instructions" and does not remove it. Do not use it where folder names must not leave the machine.
- The signing key is `mac.key` in the state folder (mode 0600). It stops a file written by something that never read the key, such as an agent steered by a folder name. It does not stop a process that can read your state folder; the skill tells agents never to.
- A repo whose own `.git/config` names a filter, gpg program or diff/merge driver is not read (`git status` would run it): it counts as dirty, is listed, and is never trashed. Your global git config and the standard git-lfs setup are not affected.
- A repo with a submodule or a linked worktree that holds work not clean and published is refused: no archive of the repo covers it. The same goes for a repo inside an ignored folder of another repo (a clone in `vendor/`, a project in a monorepo's `.gitignore`d folder) up to 6 levels down, outside `node_modules` and similar: git ignores it, so neither the bundle nor the tars hold its work. A repo found inside a scratch folder (not a repo itself) at any depth up to 6 is archived on its own before the folder moves; one deeper than that stops the move.
- A scratch folder holding keys, `.env` or credentials by name is shown only. Those files inside a repo (ignored by git) are copied into the archive, up to 64 MiB, else the repo is refused. The scan for them has to finish: a repo with an ignored tree too big to scan, or more than 20 such files, is skipped (clean or dirty), because a key past the cut would reach the Trash with no copy.
- A shallow clone (`git clone --depth 1`, or `git fetch --depth 1 <url> <sha>`): its commits at the cut-off came from a remote, so they never count as "commits on no remote", and a clean one needs no archive. One with uncommitted, untracked or local work is archived as a single `shallow-repo.tar.gz` of the whole repo (work tree, ignored files and `.git`), read back to the end, because a bundle of a shallow repo cannot be cloned. That tar is the whole tree, so a shallow clone with a large ignored folder (`node_modules`) is big and can hit the archive cap (exit 44). A shallow linked worktree or submodule is refused: its history lives outside its folder.
- `~/corecleaner-archive` has a cap of 20 GiB in total (`CORECLEANER_ARCHIVE_CAP_GIB` changes it). A repo whose archive would pass it is skipped with exit 44, in the dry run too, and nothing is trashed. Archives are never deleted by CoreCleaner, because one can be the only copy of a repo: every `trash` result lists the archives untouched for 90 days or more and a command, for you to run, that moves them to the Trash.
- Windows is BETA and was not tested on a real Windows machine. The Shell deletes for good an item bigger than the Recycle Bin or holding a path over 240 characters; CoreCleaner refuses those beforehand (Bin size from the registry), and that check is as untested as the rest. On Windows run the script with `py -3` or `python`, not `python3`. The Windows code runs in unit tests with injected helpers and in CI, nothing more. Recycle Bin enumeration in particular is an assumption.
- Linux is lightly tested. Development happened on macOS.
- `migrate` reads "never push" notes from the repo's text files (top level, and `docs/`, `notes/`, `.claude/`, `.github/` three levels deep), from the same files as committed on each unpublished branch, and from `git branch --edit-description`. A note that names no current branch, or more notes than it reads, holds every branch. It decides "nothing to push" from your remote-tracking refs, so run `git fetch` first if a branch may have been deleted on the server. Hardlinked files are copied as separate files. A disk mounted under `/mnt` on Linux is refused by the deny list; mount it under `/media`. A run killed halfway leaves a `<repo>.corecleaner-partial-<run>` folder on the disk, never a half-moved original.
- Sizes without dua are allocated-block upper bounds. Even with dua, the gain is what free space says after the Trash is emptied, not the size column.
- Category H (raw files already turned into a summary) is not detected, because it needs a per-item match that only you can confirm.
- `inventory` reads a lot of metadata and runs `git` in many folders. It took about 3 minutes on a Mac with a busy home folder.
- `scan` with dua can also take minutes on a loaded Mac. It prints a progress line on stderr every 30 s, gives each dua call 540 s (`--timeout`) and can be capped as a whole with `--max-seconds`. A folder dua could not read, or a root that timed out, makes the result `complete:false` and its label starts with "partial scan": the total is then a lower bound.
- The GAP of a scan that does not cover a whole volume is "outside the scanned roots", not "unexplained". What the roots miss is measured with a plain folder walk capped at 20 s (`CORECLEANER_SCAN_OUTSIDE_SECONDS`, 0 skips it); folders the OS hides without Full Disk Access count as unreadable and make that figure a lower bound. Other volumes of the same APFS container (System, VM, Preboot, Update) are listed and not sized, because `statvfs` returns the whole container on each. Local snapshots and purgeable space stay in what is left.
- Sizing the Trash without Full Disk Access means asking Finder, which can show a macOS permission prompt, so it only happens with `scan --ask-finder`.
- The Trash frees nothing, and local Time Machine snapshots and Chrome code-sign clones hold space that no Trash move releases.
- Time Machine takes a local snapshot of the internal disk before each backup, even when backups go to an external disk, and macOS has no switch to turn that off. macOS manages them: it keeps them about 24 h, marks them purgeable and deletes them when an app needs the space. After a day of heavy changes they can hold tens of GB (48 GB on the author's Mac). For the space now, `tmutil deletelocalsnapshots /` (no admin). To keep them small, leave the backup disk connected so backups finish, or set Time Machine to back up manually.
- Expect agent leftovers in the hundreds of MB to a few GB. Most of a full disk is your own files, apps and what the OS holds; CoreCleaner shows where that is instead of promising to clear it.

## Develop

```sh
python3 -m unittest discover -s tests -t .
```

Standard library only, 3.9 to current. Tests write only inside temp directories they create; the one test that uses the real Trash runs only with `CORECLEANER_REAL_TRASH=1`. CI runs the suite on macOS, Linux and Windows with Python 3.9 and 3.13. The contract for each subcommand is `docs/SPEC.md`.
