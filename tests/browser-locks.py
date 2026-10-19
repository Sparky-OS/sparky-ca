# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser locks defer only opted-in profiles, without writes or attention alerts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

binary, data = (str(Path(argument).resolve()) for argument in sys.argv[1:3])
del sys.argv[1:3]


class BrowserLocks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sparky-ca-browser-locks-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.profile = self.home / ".mozilla/firefox/fixture"
        self.profile.mkdir(parents=True)
        (self.profile.parent / "profiles.ini").write_text("[Profile0]\nPath=fixture\nIsRelative=1\n")
        subprocess.run(["certutil", "-N", "-d", f"sql:{self.profile}", "--empty-password"], check=True, capture_output=True)
        self.manifest = self.profile / ".sparky-ca.json"
        self.lock = self.profile / "lock"

    def snapshot(self):
        return {path.name: ("link", os.readlink(path)) if path.is_symlink() else ("file", path.read_bytes())
                for path in self.profile.iterdir()}

    def run_auto(self, discover=False):
        args = [binary, "--data", data, "--cache-dir", str(self.home / "cache"),
                "--config-dir", str(self.home / "config"), "--home", str(self.home), "--scope", "user"]
        if not discover:
            args += ["--nss", str(self.profile)]
        result = subprocess.run([*args, "auto", "run"], capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, JOURNAL_STREAM="1:1"))
        status = json.loads((self.home / ".local/state/sparky-ca/status.json").read_text())
        return result, status

    def assert_unselected_ignored(self, discover=False):
        before = self.snapshot()
        result, status = self.run_auto(discover)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(status["outcome"], "ok")
        self.assertEqual(status["stores"], [])
        self.assertEqual(status["notices"], [])
        self.assertEqual(status.get("deferred", []), [])
        self.assertNotIn(str(self.profile), result.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_discovered_locked_profile_without_selection_is_ignored(self):
        self.lock.symlink_to("127.0.0.1:+2147483647")
        self.assert_unselected_ignored(discover=True)

    def test_locked_profile_with_empty_selection_is_ignored(self):
        self.manifest.write_text(json.dumps({"groups": [], "owned": []}))
        self.lock.symlink_to(f"127.0.0.1:+{os.getpid()}")
        self.assert_unselected_ignored()

    def test_selected_active_and_stale_locks_stay_deferred_without_writes(self):
        self.manifest.write_text(json.dumps({"groups": ["icp-roots"], "owned": []}))
        for target in (f"127.0.0.1:+{os.getpid()}", "127.0.0.1:+2147483647"):
            with self.subTest(lock=target):
                self.lock.unlink(missing_ok=True)
                self.lock.symlink_to(target)
                before = self.snapshot()
                for _ in range(2):
                    result, status = self.run_auto()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(status["outcome"], "ok")
                    self.assertEqual(status["stores"], [])
                    self.assertEqual(status["notices"], [])
                    self.assertEqual(len(status["deferred"]), 1)
                    self.assertIn(str(self.profile), status["deferred"][0])
                    self.assertIn("<6>" + status["deferred"][0], result.stdout)
                    self.assertEqual(self.snapshot(), before)
                self.lock.unlink()

    def test_invalid_selection_manifest_still_fails(self):
        self.manifest.write_text("invalid json")
        result, status = self.run_auto()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(status["outcome"], "failed")
        self.assertIn("Invalid store ownership manifest", status["error"])
        self.assertIn("<3>", result.stdout)

    def test_selected_group_refresh_error_still_needs_attention(self):
        self.manifest.write_text(json.dumps({"groups": ["missing-fixture-group"], "owned": []}))
        result, status = self.run_auto()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(status["outcome"], "attention")
        self.assertIn("missing-fixture-group", status["stores"][0]["errors"][0])
        self.assertIn("<4>", result.stdout)


unittest.main()
