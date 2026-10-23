"""A path that project code cites is a live dependency: never "sure junk" (P0, measured on the real Mac).

Origin: a stray clone under ~/.cache with referenced_count=0 sat in group 1 (Sure junk, trash) while a script in
~/Documents/Músicas/<project>/ cited a file inside it by absolute path. The dependency search only read agent
instructions and a few named project files, never the project code. Every fixture lives in mkdtemp().
"""

import json
import os
import sys
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_inventory as ti  # noqa: E402
import test_plan_ask as tpa  # noqa: E402

from corecleaner_lib import ask as ask_mod  # noqa: E402
from corecleaner_lib import inventory, plan as plan_mod, safety, views  # noqa: E402

NFD_DIR = unicodedata.normalize("NFD", "Músicas")  # how an older macOS volume stores the name on disk
REL = ".cache/claude-trabalho/x/ref/lib"


class SearchCase(ti.InvCase):
    def clone(self, rel=REL):
        """A clean stray clone with its HEAD on a remote: the plan calls it Sure junk when nothing cites it."""
        lib = self.repo(self.home / rel)
        self.touch(lib / "kernel.js", 30, b"export const k = 1\n")
        ti.git(lib, "add", ".")
        ti.git(lib, "commit", "-q", "-m", "kernel")
        ti.git(lib, "remote", "add", "origin", "https://example.invalid/lib.git")
        ti.git(lib, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.age_tree(lib, 60)
        return lib

    def project_script(self, text, name="script.mjs", where=None):
        base = where or (self.home / "Documents" / NFD_DIR / "proj")
        return self.touch(base / name, 30, text.encode("utf-8"))

    def plan_items(self, cands):
        fakes = (
            mock.patch.object(safety, "is_protected", return_value=(False, "")),
            mock.patch.object(safety, "is_cloud_or_placeholder", return_value=(False, "")),
        )
        for f in fakes:
            f.start()
            self.addCleanup(f.stop)
        plan = plan_mod.build_plan(cands, free_before=1)
        return {it["path"]: it for it in plan["items"]}, plan

    def cand_of(self, lib, ctx=None):
        ctx = ctx or self.ctx()
        return ctx, inventory._cand(ctx, "C", "scratch.clone", str(lib), "unknown")

    def refs(self, lib, text, **kw):
        self.project_script(text)
        ctx, cand = self.cand_of(lib, self.ctx(**kw))
        stats = inventory._apply_refs(ctx, [cand], [])
        return cand["evidence"], stats


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class HairlineRegression(SearchCase):
    def test_a_script_citing_a_file_inside_the_clone_makes_it_group_2_with_the_dependency(self):
        lib = self.clone()
        script = self.project_script('const kernel = "%s";\nexport default kernel\n' % (lib / "kernel.js"))
        cands, meta = self.collect()
        c = self.one(cands, "scratch.clone", lib)
        self.assertGreater(c["evidence"]["referenced_by_total"], 0)
        self.assertEqual(len(c["evidence"]["referenced_by"]), 1)
        self.assertTrue(unicodedata.normalize("NFC", c["evidence"]["referenced_by"][0]).endswith("proj/script.mjs"))
        self.assertEqual(unicodedata.normalize("NFC", c["evidence"]["referenced_by"][0]),
                         unicodedata.normalize("NFC", str(script)))
        self.assertEqual(meta["reference_search"]["status"], "ok")
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual((item["group"], item["action"]), (2, "trash"))
        self.assertGreater(item["evidence"]["referenced_count"], 0)
        self.assertEqual(item["reason"], "live dependency: cited by 1 file(s)")
        self.assertEqual(len(item["evidence"]["referenced_by"]), 1)

    def test_the_same_clone_with_no_citation_is_sure_junk(self):
        """Control: the fixture really is group 1, so the test above can only fail because of the citation."""
        lib = self.clone()
        self.project_script("console.log('no path here')\n")
        cands, meta = self.collect()
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual((item["group"], item["action"], item["evidence"]["referenced_count"]), (1, "trash", 0))
        self.assertIsNone(item["reason"])
        self.assertFalse([u for u in meta["unverified"] if "referenced_by" in u])

    def test_a_known_project_outside_the_usual_folders_is_searched_whole(self):
        lib = self.clone()
        odd = self.home / "somewhere" / "odd" / "app"
        self.touch(odd / "src" / "deep" / "run.sh", 30, ("node %s/kernel.js\n" % lib).encode())
        self.transcript("-odd-app", 1, odd)
        cands, _ = self.collect()
        self.assertEqual(self.one(cands, "scratch.clone", lib)["evidence"]["referenced_by_total"], 1)

    def test_a_node_modules_project_found_by_the_inventory_is_searched_whole(self):
        lib = self.clone()
        proj = self.home / "elsewhere" / "web"
        self.touch(proj / "package.json", 60, b"{}")
        self.touch(proj / "bun.lock", 60, b"")
        self.touch(proj / "node_modules" / "x" / "i.js", 60, b"1")
        self.touch(proj / "lib" / "load.mjs", 60, ("import '%s/kernel.js'\n" % lib).encode())
        self.age_tree(proj, 60)
        cands, _ = self.collect()
        self.assertTrue(self.by_kind(cands, "node_modules"))
        self.assertEqual(self.one(cands, "scratch.clone", lib)["evidence"]["referenced_by_total"], 1)

    def test_this_tools_own_docs_and_code_are_never_a_citation(self):
        """categorias.md names every cache it knows: a checkout of CoreCleaner in ~/Documents must not pin them all."""
        lib = self.clone()
        own = self.home / "Documents" / "CoreCleaner" / "skills" / "corecleaner"
        self.touch(own / "references" / "categorias.md", 30, ("see %s/kernel.js\n" % lib).encode())
        with mock.patch.object(inventory, "OWN_ROOTS", (str(own),)):
            ev, _ = self.refs(lib, "nothing\n")
        self.assertEqual(ev["referenced_by_total"], 0, ev["referenced_by"])
        ev, _ = self.refs(lib, "nothing\n")  # control: the same file outside OWN_ROOTS counts
        self.assertEqual(ev["referenced_by_total"], 1, ev["referenced_by"])

    def test_vendor_dist_build_node_modules_lock_and_binaries_are_not_read(self):
        lib = self.clone()
        line = ("%s/kernel.js\n" % lib).encode()
        base = self.home / "Documents" / "proj"
        for name in ("node_modules/a.js", "dist/a.js", "build/a.js", ".next/a.js", "target/a.txt", "vendor/a.js",
                     "x.lock", "x.png", "log.jsonl"):
            self.touch(base / name, 30, line)
        self.touch(base / "big.txt", 30, line + b"y" * (2 * 1024 * 1024 + 10))
        ev, _ = self.refs(lib, "nothing\n")
        self.assertEqual(ev["referenced_by_total"], 0, ev["referenced_by"])


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class CitationForms(SearchCase):
    def test_every_way_of_writing_the_path_counts_and_a_longer_name_does_not(self):
        lib = self.clone()
        good = {
            "absolute dir": 'cd "%s"\n' % lib,
            "absolute file inside": 'import "%s/kernel.js"\n' % lib,
            "tilde": "source ~/%s/kernel.js\n" % REL,
            "$HOME": 'p="$HOME/%s"\n' % REL,
            "${HOME}": 'p="${HOME}/%s/kernel.js"\n' % REL,
            "relative to HOME": 'join(homedir(), ".cache/claude-trabalho/x/ref/lib/kernel.js")\n',
            "full stop after it": "The engine lives in ~/%s.\n" % REL,
            "end of line": "path = %s" % lib,
        }
        for label, text in good.items():
            with self.subTest(label):
                ev, _ = self.refs(lib, text)
                self.assertEqual(ev["referenced_by_total"], 1, text)
        bad = {
            "longer name": "cd %s-b/kernel.js\n" % lib,
            "extension": "cp %s.bak /tmp/x\n" % lib,
            "word suffix": "echo %s2\n" % lib,
        }
        for label, text in bad.items():
            with self.subTest(label):
                ev, _ = self.refs(lib, text)
                self.assertEqual(ev["referenced_by_total"], 0, text)

    def test_nfc_and_nfd_spellings_match_each_other_on_either_side(self):
        for tag, on_disk, cited in (("a", "NFD", "NFC"), ("b", "NFC", "NFD")):
            with self.subTest(disk=on_disk, cited=cited):
                name = "%s-ação" % tag
                rel = ".cache/claude-trabalho/x/ref/" + unicodedata.normalize(on_disk, name)
                lib = self.clone(rel)
                text = "node %s/kernel.js\n" % unicodedata.normalize(cited, str(lib))
                ev, _ = self.refs(lib, text)
                self.assertEqual(ev["referenced_by_total"], 1)

    def test_a_citation_on_a_very_long_line_is_still_found(self):
        lib = self.clone()
        ev, _ = self.refs(lib, '{"pad":"%s","path":"%s/kernel.js"}\n' % ("p" * 9000, lib))
        self.assertEqual(ev["referenced_by_total"], 1)
        self.assertFalse([u for u in ev["unverified"] if u.startswith("referenced_by")])

    def test_private_tmp_is_also_written_as_tmp(self):
        self.assertIn("/tmp/claude-501/x", inventory._ref_patterns("/Users/a", "/private/tmp/claude-501/x"))
        self.assertIn("/var/folders/q", inventory._ref_patterns("/Users/a", "/private/var/folders/q"))

    def test_a_single_segment_under_home_is_not_searched_bare(self):
        pats = inventory._ref_patterns("/Users/a", "/Users/a/.npm")
        self.assertIn("~/.npm", pats)
        self.assertNotIn(".npm", pats)


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class SearchThatDidNotFinish(SearchCase):
    def junk_item(self, ctx):
        lib = self.clone()
        self.project_script("console.log(1)\n")
        cands, meta = self.collect(ctx=ctx)
        return lib, meta, self.plan_items(cands)[0][str(lib)]

    def assert_demoted(self, item, meta):
        self.assertEqual((item["group"], item["action"]), (2, "trash"))
        self.assertTrue(item["evidence"]["referenced_unverified"])
        self.assertEqual(item["reason"], "dependency search incomplete: not proven unused")
        self.assertTrue([u for u in meta["unverified"] if "referenced_by" in u])

    def test_no_rg_means_not_sure_junk(self):
        ctx = self.ctx(which=lambda n: "/usr/bin/git" if n == "git" else None)
        _, meta, item = self.junk_item(ctx)
        self.assert_demoted(item, meta)

    def test_a_search_that_hits_the_deadline_is_labelled_and_not_sure_junk(self):
        ctx = self.ctx(scripted={"rg": (127, "")}, ref_seconds=0.0)
        _, meta, item = self.junk_item(ctx)
        self.assertEqual(meta["reference_search"]["status"], "timed out")
        self.assert_demoted(item, meta)

    def test_a_failed_search_is_not_sure_junk(self):
        ctx = self.ctx(scripted={"rg": (127, "")})
        _, meta, item = self.junk_item(ctx)
        self.assertEqual(meta["reference_search"]["status"], "failed")
        self.assert_demoted(item, meta)

    def test_a_cloud_synced_project_folder_is_not_read_and_the_result_says_so(self):
        docs = self.home / "Documents"
        ctx = self.ctx(safety=ti.FakeSafety(cloud=[str(docs)]))
        lib = self.clone()
        self.touch(docs / "proj" / "script.mjs", 30, ("%s/kernel.js\n" % lib).encode())
        cands, meta = self.collect(ctx=ctx)
        self.assertEqual(meta["reference_search"]["skipped_cloud"], 1)
        c = self.one(cands, "scratch.clone", lib)
        self.assertEqual(c["evidence"]["referenced_by_total"], 0)  # never read ...
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual(item["group"], 2)  # ... and so not proven unused
        self.assertTrue(item["evidence"]["referenced_unverified"])

    def test_a_package_cache_stays_group_1_when_the_search_is_incomplete(self):
        """Its own tool purges and refills it: an unread .envrc with PIP_CACHE_DIR changes nothing."""
        old = os.path.getmtime(str(self.root)) - 40 * 86400
        cands = []
        for name, notes in (("unproven", ["referenced_by: not verified (rg not found)"]), ("proven", [])):
            real = self.root / name
            real.mkdir()
            (real / "f").write_bytes(b"x")
            os.utime(str(real / "f"), (old, old))
            os.utime(str(real), (old, old))
            cands.append({"category": "F", "kind": "cache.pip", "path": str(real), "bytes": 10, "mtime": old, "owner": "tool",
                          "evidence": tpa.evidence(tool_command="npm cache clean --force", unverified=notes)})
        with mock.patch.object(inventory, "clean_commands_for", return_value={"npm cache clean --force"}):
            items = self.plan_items(cands)[0]
        unproven, proven = items[str(self.root / "unproven")], items[str(self.root / "proven")]
        self.assertEqual((unproven["group"], unproven["action"], unproven["reason"]), (1, "tool_command", None))
        self.assertTrue(unproven["evidence"]["referenced_unverified"])
        self.assertEqual((proven["group"], proven["action"]), (1, "tool_command"))


class RefsCase(SearchCase):
    """Helpers for the review findings: one _apply_refs call on a clone, no project script written first."""

    TAIL = "claude-trabalho/x/ref/lib/kernel.js"

    def refs_of(self, lib, **kw):
        ctx, cand = self.cand_of(lib, self.ctx(**kw))
        stats = inventory._apply_refs(ctx, [cand], [])
        return cand["evidence"], stats

    def put(self, rel, text, base=None):
        return self.touch((base or self.home) / rel, 30, text.encode("utf-8"))

    def maybe_notes(self, ev):
        return [u for u in ev["unverified"] if u.startswith("referenced_by: possibly cited")]


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class CodeOutsideTheProjectFolders(RefsCase):
    """Code that cites a clone does not always sit under ~/Documents or in a folder with a Claude session."""

    def test_shell_start_up_files_bin_folders_config_and_launch_agents_are_read(self):
        lib = self.clone()
        spots = {
            ".zshrc": 'export PATH="%s/bin:$PATH"\n',
            "bin/run": "#!/bin/sh\nexec %s/kernel.js\n",
            ".local/bin/run": "#!/bin/sh\nexec %s/kernel.js\n",
            ".config/app/conf": "path=%s\n",
            "Library/LaunchAgents/com.me.job.plist": "<string>%s/kernel.js</string>\n",
        }
        for rel, text in spots.items():
            self.put(rel, text % lib)
        ev, stats = self.refs_of(lib)
        self.assertEqual(stats["status"], "ok")
        seen = {os.path.relpath(f, str(self.home)) for f in ev["referenced_by"]}
        self.assertEqual(seen, set(spots))
        self.assertEqual(ev["referenced_by_total"], len(spots))

    def test_the_crontab_is_read_even_when_there_is_no_file_to_search(self):
        lib = self.clone()

        def no_rg(argv):
            self.fail("rg must not run without a root: it would read the working folder")

        ev, stats = self.refs_of(lib, scripted={"crontab": (0, "*/5 * * * * node %s/kernel.js\n" % lib), "rg": no_rg})
        self.assertEqual(ev["referenced_by"], ["crontab -l"])
        self.assertEqual(stats["status"], "ok")

    def test_any_visible_folder_of_home_is_a_project_folder(self):
        lib = self.clone()
        for rel in ("workspace/app/run.sh", "Coding/tool/src/go.sh", "git/site/build.sh"):
            self.put(rel, "node %s/kernel.js\n" % lib)
        ev, _ = self.refs_of(lib)
        self.assertEqual(ev["referenced_by_total"], 3)

    def test_media_and_package_folders_of_home_are_left_alone(self):
        lib = self.clone()
        for rel in ("Movies/notes.txt", "Downloads/run.sh", "Library/Application Support/x/run.sh"):
            self.put(rel, "node %s/kernel.js\n" % lib)
        ev, stats = self.refs_of(lib)
        self.assertEqual(ev["referenced_by_total"], 0)
        self.assertEqual(stats["skipped_cloud"], 0)
        self.assertIn("Downloads", stats["not_searched"])

    def test_a_project_folder_that_is_a_link_to_another_volume_is_searched(self):
        lib = self.clone()
        ext = self.root / "ext" / "Projects"
        self.put("app/run.sh", "node %s/kernel.js\n" % lib, base=ext)
        os.symlink(str(ext), str(self.home / "Projects"))
        ev, _ = self.refs_of(lib)
        self.assertEqual(ev["referenced_by_total"], 1)

    def test_a_known_project_under_library_is_searched_when_it_is_not_synced(self):
        lib = self.clone()
        app = self.home / "Library" / "CloudStorage" / "Dropbox" / "app"
        self.put("src/run.sh", "node %s/kernel.js\n" % lib, base=app)
        self.transcript("-dropbox-app", 1, app)
        cands, meta = self.collect()
        self.assertEqual(self.one(cands, "scratch.clone", lib)["evidence"]["referenced_by_total"], 1)

    def test_a_known_project_under_library_that_is_synced_is_reported_not_dropped(self):
        lib = self.clone()
        app = self.home / "Library" / "CloudStorage" / "Dropbox" / "app"
        self.put("src/run.sh", "node %s/kernel.js\n" % lib, base=app)
        self.transcript("-dropbox-app", 1, app)
        cands, meta = self.collect(ctx=self.ctx(safety=ti.FakeSafety(cloud=[str(app)])))
        self.assertEqual(meta["reference_search"]["skipped_cloud"], 1)
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual(item["group"], 2)
        self.assertTrue(item["evidence"]["referenced_unverified"])

    def test_a_link_that_points_into_the_clone_is_a_dependency(self):
        lib = self.clone()
        (self.home / "Documents").mkdir()
        os.symlink(str(lib), str(self.home / "Documents" / "vendored"))
        (self.home / ".local" / "bin").mkdir(parents=True)
        os.symlink(str(lib / "kernel.js"), str(self.home / ".local" / "bin" / "tool"))
        mods = self.home / "Documents" / "proj" / "node_modules"
        (mods / "@scope").mkdir(parents=True)
        os.symlink(str(lib), str(mods / "mylib"))
        os.symlink(str(lib), str(mods / "@scope" / "pkg"))
        os.symlink(str(lib / "kernel.js"), str(lib / "self-link"))  # inside the clone: no outside user
        ev, _ = self.refs_of(lib)
        names = sorted(os.path.relpath(f, str(self.home)) for f in ev["referenced_by"])
        self.assertEqual(names, [".local/bin/tool", "Documents/proj/node_modules/@scope/pkg",
                                 "Documents/proj/node_modules/mylib", "Documents/vendored"])


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class LinkedAncestors(RefsCase):
    """A path under a linked folder has two names; a script uses the one it typed."""

    def test_home_dot_cache_linked_to_another_volume(self):
        ext = self.root / "ext" / "cache"
        ext.mkdir(parents=True)
        os.symlink(str(ext), str(self.home / ".cache"))
        lib = self.clone()
        self.assertTrue(str(lib.resolve()).startswith(str(ext)), "the candidate is the real path")
        self.project_script("source ~/.cache/%s\n" % "claude-trabalho/x/ref/lib/kernel.js")
        cands, _ = self.collect()
        self.assertEqual(self.one(cands, "scratch.clone")["evidence"]["referenced_by_total"], 1)
        self.assertEqual(self.plan_items(cands)[0][str(lib.resolve())]["group"], 2)

    def test_a_linked_folder_deeper_down_is_remembered_by_the_candidate(self):
        ext = self.root / "ext" / "ct"
        lib = self.clone(str(ext / "x" / "ref" / "lib"))
        (self.home / ".cache").mkdir()
        os.symlink(str(ext), str(self.home / ".cache" / "claude-trabalho"))
        typed = self.home / ".cache" / "claude-trabalho" / "x" / "ref" / "lib"
        ctx, cand = self.cand_of(typed)
        self.assertEqual(cand["path"], str(lib.resolve()))
        self.assertEqual(cand["evidence"]["alias_paths"], [str(typed)])
        self.project_script("source ~/.cache/%s\n" % self.TAIL)
        inventory._apply_refs(ctx, [cand], [])
        self.assertEqual(cand["evidence"]["referenced_by_total"], 1)


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class PathsWrittenOtherWays(RefsCase):
    def total(self, lib, text, **kw):
        ev, _ = self.refs(lib, text, **kw)
        return ev["referenced_by_total"]

    def test_environment_variable_forms(self):
        lib = self.clone()
        cases = {
            "$XDG_CACHE_HOME": "source $XDG_CACHE_HOME/%s\n" % self.TAIL,
            "${XDG_CACHE_HOME}": "source ${XDG_CACHE_HOME}/%s\n" % self.TAIL,
            "quoted": 'source "$XDG_CACHE_HOME"/%s\n' % self.TAIL,
            "with a default": 'source "${XDG_CACHE_HOME:-$HOME/.cache}/%s"\n' % self.TAIL,
        }
        for env in ({}, {"XDG_CACHE_HOME": str(self.home / ".cache")}):
            for label, text in cases.items():
                with self.subTest(label, env=bool(env)):
                    self.assertEqual(self.total(lib, text, env=env), 1, text)

    def test_temp_folder_variables(self):
        ctx = self.ctx(env={"CLAUDE_CODE_TMPDIR": "/private/tmp"}, tmp_bases=["/private/tmp", "/tmp"])
        pats = inventory._ref_patterns("/Users/me", "/private/tmp/claude-501/-Users-me-proj/abc/lib",
                                       inventory._env_bases(ctx))
        tail = "claude-501/-Users-me-proj/abc/lib"
        for text in ("cd ${TMPDIR:-/tmp}/%s" % tail, "cd $TMPDIR/%s" % tail, "cd $CLAUDE_CODE_TMPDIR/%s" % tail,
                     'cd "$TMPDIR"/%s' % tail, "cd /tmp/%s" % tail):
            with self.subTest(text):
                self.assertTrue(any(inventory._mentions(text, p) for p in pats), text)
        self.assertFalse(any(inventory._mentions("cd $TMPDIR/claude-501/-Users-me-proj/abc/lib-b", p) for p in pats))

    def test_the_quoted_home_form_also_works_for_one_segment(self):
        pats = inventory._ref_patterns("/Users/a", "/Users/a/lonely")
        self.assertTrue(any(inventory._mentions('rm -rf "$HOME"/lonely', p) for p in pats))
        self.assertTrue(any(inventory._mentions('rm -rf "${HOME}"/lonely', p) for p in pats))
        self.assertFalse(any(inventory._mentions("rm -rf lonely", p) for p in pats))

    def test_json_escaped_space_escaped_and_percent_encoded_spellings(self):
        lib = self.clone()
        self.assertEqual(self.total(lib, '{"cmd":"%s\\/kernel.js"}\n' % str(lib).replace("/", "\\/")), 1)
        spaced = self.clone(".cache/my tools/lib")
        self.assertEqual(self.total(spaced, "source ~/.cache/my\\ tools/lib/kernel.js\n"), 1)
        self.assertEqual(self.total(spaced, "source file://%s/kernel.js\n" % str(spaced).replace(" ", "%20")), 1)

    def test_a_wrong_case_citation_counts_where_the_volume_ignores_case(self):
        lib = self.clone()
        text = "source ~/.Cache/Claude-Trabalho/x/ref/lib/kernel.js\n"
        with mock.patch.object(inventory, "_case_insensitive", return_value=True):
            self.assertEqual(self.total(lib, text), 1)
        with mock.patch.object(inventory, "_case_insensitive", return_value=False):
            self.assertEqual(self.total(lib, text), 0, "on a case-sensitive volume it is another path")

    def test_a_line_with_a_unicode_line_separator_before_the_path_is_still_read(self):
        lib = self.clone()
        for sep in ("\u2028", "\u2029", "\x0b", "\x0c", "\x1c", "\x85"):
            with self.subTest(repr(sep)):
                self.assertEqual(self.total(lib, "note%sload %s/kernel.js\n" % (sep, lib)), 1)

    def test_windows_spellings(self):
        with mock.patch.object(inventory.os, "sep", "\\"):
            pats = inventory._ref_patterns("C:\\Users\\me", "C:\\Users\\me\\AppData\\Local\\Temp\\claude\\lib",
                                           [("TEMP", "C:\\Users\\me\\AppData\\Local\\Temp")])
        for text in ("C:\\Users\\me\\AppData\\Local\\Temp\\claude\\lib", "C:/Users/me/AppData/Local/Temp/claude/lib",
                     "C:\\\\Users\\\\me\\\\AppData\\\\Local\\\\Temp\\\\claude\\\\lib",
                     "%USERPROFILE%\\AppData\\Local\\Temp\\claude\\lib", "%TEMP%\\claude\\lib",
                     "~/AppData/Local/Temp/claude/lib"):
            with self.subTest(text):
                self.assertTrue(any(inventory._mentions(text, p) for p in pats), text)


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class PathsAssembledAtRunTime(RefsCase):
    """Text cannot prove a path built from parts: its likely forms mark the clone "possibly cited" (group 2)."""

    def clone_named(self):
        return self.clone(".cache/claude-trabalho/x/reference/library")

    def test_a_path_built_from_parts_is_possibly_cited_and_never_sure_junk(self):
        lib = self.clone_named()
        cases = {
            "path.join": 'path.join(os.homedir(), ".cache", "claude-trabalho", "x", "reference", "library", "k.js")\n',
            "pathlib": "Path.home() / '.cache' / 'claude-trabalho' / 'x' / 'reference' / 'library'\n",
            "cd to the parent": "cd ~/.cache/claude-trabalho/x/reference && ./library/kernel.js\n",
            "variable holding the parent": 'LIBS=~/.cache/claude-trabalho/x/reference\nsource "$LIBS/library/kernel.js"\n',
            "relative from a sibling": "source ../reference/library/kernel.js\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                ev, _ = self.refs(lib, text)
                self.assertEqual(ev["referenced_by_total"], 0, "not a proven citation")
                self.assertEqual(len(self.maybe_notes(ev)), 1, ev["unverified"])
        self.project_script(cases["path.join"])
        cands, _ = self.collect()
        item = self.plan_items(cands)[0][str(lib)]
        self.assertEqual((item["group"], item["reason"]),
                         (2, "possibly cited: a file may build this path in code, not proven unused"))
        self.assertEqual(len(item["evidence"]["referenced_maybe"]), 1)

    def test_naming_a_sibling_or_a_common_word_is_not_a_hint(self):
        lib = self.clone_named()
        for text in ("source ~/.cache/claude-trabalho/x/reference/other/kernel.js\n",
                     'path.join(root, "reference", "other")\n', "const library = require('library')\n"):
            with self.subTest(text):
                ev, _ = self.refs(lib, text)
                self.assertEqual((ev["referenced_by_total"], self.maybe_notes(ev)), (0, []))

    def test_a_proven_citation_is_not_also_listed_as_a_guess(self):
        lib = self.clone_named()
        ev, _ = self.refs(lib, "cd %s && ls\n" % lib)
        self.assertEqual((ev["referenced_by_total"], self.maybe_notes(ev)), (1, []))


@unittest.skipUnless(ti.HAVE_RG and ti.HAVE_GIT, "needs rg and git")
class FilesTheSearchMustRead(RefsCase):
    """A FILE called build, dist or vendor, and what a repository keeps in .git, are user code."""

    def found(self, lib, rel):
        path = self.put("Documents/proj/" + rel, "%s/kernel.js\n" % lib)
        try:
            ev, _ = self.refs_of(lib)
        finally:
            os.remove(str(path))
        return ev["referenced_by_total"]

    def test_files_named_like_a_skipped_folder_and_git_hooks_and_config_are_read(self):
        lib = self.clone()
        for rel in ("scripts/build", "bin/dist", "tools/vendor", "scripts/target", ".git/hooks/pre-push", ".git/config",
                    ".git/FETCH_HEAD", ".gitmodules", "sub/.git", "x.bin", "run.sh"):
            with self.subTest(rel):
                self.assertEqual(self.found(lib, rel), 1)

    def test_the_folders_that_only_hold_generated_output_and_git_history_are_still_skipped(self):
        lib = self.clone()
        for rel in ("build/a.sh", "dist/a.sh", "vendor/a.sh", "target/a.sh", "node_modules/p/a.js", ".next/a.js",
                    ".git/objects/ab/cdef", ".git/logs/HEAD", ".git/refs/heads/main", "Cargo.lock", "x.map", "a.min.js"):
            with self.subTest(rel):
                self.assertEqual(self.found(lib, rel), 0)


class DependencyPlan(tpa.Base):
    FILES = ["/Users/x/Documents/p/a.mjs", "/Users/x/Documents/p/b.mjs", "/Users/x/Documents/p/c.mjs",
             "/Users/x/Documents/p/d.mjs"]

    def cited(self, name, cat="C", **ev):
        base = dict(referenced_by=self.FILES, referenced_by_total=7)
        if cat == "C":
            base["git"] = dict(tpa.REPO_CLEAN)
        base.update(ev)
        return self.cand(self.mkdir(name), cat=cat, **base)

    def test_a_cited_clone_is_group_2_with_reason_count_and_the_first_three_files(self):
        plan = plan_mod.build_plan([self.cited("clone")])
        it = plan["items"][0]
        self.assertEqual((it["group"], it["action"], it["deny"]), (2, "trash", None))
        self.assertEqual(it["reason"], "live dependency: cited by 7 file(s)")
        self.assertEqual(it["evidence"]["referenced_count"], 7)
        self.assertEqual(it["evidence"]["referenced_by"], self.FILES[:3])
        self.assertEqual(plan["sha256"], plan_mod.plan_hash(plan))

    def test_without_citation_the_same_clone_is_group_1(self):
        it = plan_mod.build_plan([self.cand(self.mkdir("clone"), cat="C", git=dict(tpa.REPO_CLEAN))])["items"][0]
        self.assertEqual((it["group"], it["reason"], it["evidence"]["referenced_count"]), (1, None, 0))

    def test_a_cited_scratch_unit_is_never_group_1_but_a_cited_package_cache_is(self):
        d = self.cited("scratch", cat="D")
        f = self.cited("cache", cat="F", tool_command="npm cache clean --force")
        f["kind"] = "cache.npm"
        b = self.cited("browsers", cat="F", tool_command="npm cache clean --force")
        b["kind"] = "cache.playwright"  # not refilled by the next install: a citing project would break
        with mock.patch.object(inventory, "clean_commands_for", return_value={"npm cache clean --force"}):
            by = self.by_display(plan_mod.build_plan([d, f, b]))
        self.assertEqual(by["scratch"]["group"], 2)
        self.assertEqual((by["cache"]["group"], by["cache"]["action"]), (1, "tool_command"))
        self.assertEqual(by["cache"]["reason"], "cited by 7 file(s); its own tool rebuilds it")
        self.assertEqual((by["browsers"]["group"], by["browsers"]["reason"]), (2, "live dependency: cited by 7 file(s)"))

    def test_a_cited_repo_with_unsaved_work_keeps_archive_then_trash(self):
        git = dict(tpa.REPO_CLEAN, dirty=True)
        it = plan_mod.build_plan([self.cited("dirty", git=git)])["items"][0]
        self.assertEqual((it["group"], it["action"]), (2, "archive_then_trash"))
        self.assertIn("live dependency", it["reason"])

    def test_a_keep_note_is_still_shown_only(self):
        it = plan_mod.build_plan([self.cited("kept", keep_note=True)])["items"][0]
        self.assertEqual((it["group"], it["action"]), (3, "list_only"))
        self.assertIn("note", it["deny"])

    def test_the_agent_view_carries_reason_and_the_files(self):
        view = plan_mod.plan_view(plan_mod.build_plan([self.cited("clone")]))
        row = view["items"][0]
        self.assertEqual(row["reason"], "live dependency: cited by 7 file(s)")
        self.assertEqual(row["evidence"]["referenced_by"], self.FILES[:3])

    def test_ask_names_the_dependency_in_the_option_description(self):
        plan = plan_mod.build_plan([self.cited("clone")])
        out = ask_mod.render(plan, "claude")
        q = out["questions"][0]
        yes = [o for o in q["options"] if o["label"].startswith("Move to Trash")][0]
        self.assertIn("LIVE DEPENDENCY: cited by 7 file(s)", yes["description"])
        self.assertIn("a.mjs", yes["description"])
        self.assertIn("live dependency: cited by 7 file(s)", out["text"])
        pt = ask_mod.render(plan, "claude", lang="pt")["questions"][0]
        self.assertIn("DEPENDÊNCIA VIVA", [o for o in pt["options"] if o["label"].startswith("Mover")][0]["description"])

    def test_ask_never_warns_live_dependency_for_a_cache_its_tool_refills(self):
        f = self.cited("cache", cat="F", tool_command="npm cache clean --force")
        f["kind"] = "cache.npm"
        with mock.patch.object(inventory, "clean_commands_for", return_value={"npm cache clean --force"}):
            plan = plan_mod.build_plan([f])
        for lang, word in (("en", "LIVE DEPENDENCY"), ("pt", "DEPENDÊNCIA VIVA")):
            text = json.dumps(ask_mod.render(plan, "claude", lang=lang)["questions"], ensure_ascii=False)
            self.assertNotIn(word, text)
            self.assertIn("7", text)

    def test_a_cited_item_is_never_swept_into_trash_all(self):
        plain = [self.cand(self.mkdir("e%d" % i), cat="E") for i in range(5)]
        cited = self.cited("clone", cat="E")
        plan = plan_mod.build_plan(plain + [cited])
        out = ask_mod.render(plan, "claude")
        cited_id = [i["id"] for i in plan["items"] if i["display"] == "clone"][0]
        group_ids = [o["ids"] for u in out["answer_map"] for o in u["options"] if o["effect"] == "trash" and len(o["ids"]) > 1]
        self.assertEqual(len(group_ids), 1)
        self.assertNotIn(cited_id, group_ids[0])
        single = [o["ids"] for u in out["answer_map"] for o in u["options"] if o["effect"] == "trash" and o["ids"] == [cited_id]]
        self.assertEqual(len(single), 1)
        table = out["text"]
        self.assertIn("live dependency", [ln for ln in table.splitlines() if cited_id in ln][0])

    def test_a_possible_citation_is_group_2_with_its_own_reason_and_the_file_in_the_option(self):
        c = self.cand(self.mkdir("scratch"), cat="D", referenced_maybe=self.FILES[:2],
                      unverified=["referenced_by: possibly cited in 2 file(s), the path may be assembled from parts"])
        plan = plan_mod.build_plan([c])
        it = plan["items"][0]
        self.assertEqual((it["group"], it["reason"]),
                         (2, "possibly cited: a file may build this path in code, not proven unused"))
        self.assertEqual(it["evidence"]["referenced_maybe"], self.FILES[:2])
        yes = [o for o in ask_mod.render(plan, "claude")["questions"][0]["options"]
               if o["label"].startswith("Move to Trash")][0]
        self.assertIn("may build this path in code", yes["description"])
        self.assertIn("a.mjs", yes["description"])
        pt = [o for o in ask_mod.render(plan, "claude", lang="pt")["questions"][0]["options"]
              if o["label"].startswith("Mover")][0]
        self.assertIn("pode montar este caminho", pt["description"])

    def test_an_incomplete_search_is_said_in_the_option_and_the_table(self):
        c = self.cand(self.mkdir("scratch"), cat="D", unverified=["referenced_by: not verified (rg not found)"])
        plan = plan_mod.build_plan([c])
        self.assertEqual(plan["items"][0]["group"], 2)
        out = ask_mod.render(plan, "claude")
        yes = [o for o in out["questions"][0]["options"] if o["label"].startswith("Move to Trash")][0]
        self.assertIn("did not finish", yes["description"])
        self.assertIn("dependency search incomplete", out["text"])


class ApparentCeilingView(unittest.TestCase):
    def test_code_sign_clones_are_a_ceiling_not_a_gain(self):
        GB = 1_000_000_000
        inv = {
            "candidates": [
                {"category": "J", "kind": "os.code_sign_clone", "path": "/p/a", "bytes": 461 * GB,
                 "evidence": {"apparent_upper_bound": {"bytes": 461 * GB, "clones": 12}, "action": "reboot frees these"}},
                {"category": "J", "kind": "os.trash", "path": "/home/.Trash", "bytes": 5, "evidence": {}},
                {"category": "C", "kind": "scratch.clone", "path": "/c", "bytes": 7, "evidence": {}},
            ],
            "reference_search": {"status": "ok", "roots": 4, "skipped_cloud": 0, "seconds": 3.5},
        }
        view = views.inventory_view(inv, Path("/state/inv.json"))
        j = view["by_category"]["J"]
        self.assertEqual(j["count"], 2)
        self.assertEqual(j["bytes"], 5, "the 461 GB ceiling must not be summed into bytes")
        self.assertEqual(j["apparent_upper_bound"], {"count": 1, "bytes": 461 * GB, "clones": 12})
        self.assertEqual(j["note"], "reboot frees these")
        self.assertEqual(view["by_category"]["C"], {"count": 1, "bytes": 7})
        self.assertEqual(view["reference_search"], {"status": "ok", "roots": 4, "skipped_cloud": 0, "seconds": 3.5})

    def test_the_view_tells_the_agent_what_the_search_cannot_see(self):
        inv = {"candidates": [], "reference_search": {"status": "ok", "roots": 1, "skipped_cloud": 0, "seconds": 1.0,
                                                      "not_searched": inventory.REF_NOT_SEARCHED}}
        seen = views.inventory_view(inv, Path("/state/inv.json"))["reference_search"]
        self.assertIn("Downloads", seen["not_searched"])
        self.assertIn("assembled at run time", seen["not_searched"])


if __name__ == "__main__":
    unittest.main()
