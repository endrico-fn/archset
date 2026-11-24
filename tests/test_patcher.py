#!/usr/bin/env python3
"""Unit tests for targeted line-patching (patcher.py) and fstab normalization."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import disk  # noqa: E402
import patcher  # noqa: E402


class PatcherTests(unittest.TestCase):
    def test_patch_pacman_conf_preserves_comments_and_multilib_toggle(self) -> None:
        sample = """\
# Upstream comment must remain intact
[options]
HoldPkg     = pacman glibc
#Color
#CheckSpace
#VerbosePkgLists
#ParallelDownloads = 5
DownloadUser = alpm

[core]
Include = /etc/pacman.d/mirrorlist

#[multilib]
#Include = /etc/pacman.d/mirrorlist
"""
        without_ml = patcher.patch_pacman_conf(sample, enable_multilib=False)
        self.assertIn("# Upstream comment must remain intact", without_ml)
        self.assertIn("DownloadUser = alpm", without_ml)
        self.assertIn("\nColor\n", without_ml)
        self.assertIn("\nILoveCandy\n", without_ml)
        self.assertIn("\nCheckSpace\n", without_ml)
        self.assertIn("\nVerbosePkgLists\n", without_ml)
        self.assertIn("\nParallelDownloads = 5\n", without_ml)
        self.assertIn("#[multilib]", without_ml)

        with_ml = patcher.patch_pacman_conf(sample, enable_multilib=True)
        self.assertIn("\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n", with_ml)
        # Idempotent on repeated pass
        self.assertEqual(with_ml, patcher.patch_pacman_conf(with_ml, enable_multilib=True))

    def test_patch_dnscrypt_toml_targets_only_expected_keys(self) -> None:
        sample = """\
# Keep this header comment
# server_names = ['scaleway-fr', 'google']
listen_addresses = ['127.0.0.1:53']
max_clients = 250
ipv6_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
use_syslog = false
bootstrap_resolvers = ['9.9.9.11:53', '1.1.1.1:53']
ignore_system_dns = false
netprobe_address = '9.9.9.11:53'
block_ipv6 = false
"""
        patched = patcher.patch_dnscrypt_toml(sample)
        self.assertIn("# Keep this header comment", patched)
        self.assertIn("max_clients = 250", patched)
        self.assertIn("require_dnssec = true", patched)
        self.assertIn(
            "server_names = ['quad9-doh-ip4-port443-filter-pri', 'mullvad-doh']",
            patched,
        )
        self.assertIn("listen_addresses = ['127.0.0.1:5300']", patched)
        self.assertIn("ipv6_servers = false", patched)
        self.assertIn("require_nofilter = false", patched)
        self.assertIn("use_syslog = true", patched)
        self.assertIn(
            "bootstrap_resolvers = ['9.9.9.9:53', '149.112.112.112:53']",
            patched,
        )
        self.assertIn("ignore_system_dns = true", patched)
        self.assertIn("netprobe_address = '9.9.9.9:53'", patched)
        self.assertIn("block_ipv6 = true", patched)
        # Idempotent
        self.assertEqual(patched, patcher.patch_dnscrypt_toml(patched))

    def test_patch_linux_preset_enables_uki_and_comments_legacy_images(self) -> None:
        sample = """\
# mkinitcpio preset file for the 'linux' package
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default' 'fallback')

default_image="/boot/initramfs-linux.img"
#default_uki="/efi/EFI/Linux/arch-linux.efi"
#default_options="--splash /usr/share/systemd/bootctl/splash-arch.bmp"

fallback_image="/boot/initramfs-linux-fallback.img"
#fallback_uki="/efi/EFI/Linux/arch-linux-fallback.efi"
fallback_options="-S autodetect"
"""
        patched = patcher.patch_linux_preset(sample, fallback=True)
        self.assertIn("# mkinitcpio preset file for the 'linux' package", patched)
        self.assertIn('ALL_kver="/boot/vmlinuz-linux"', patched)
        self.assertIn("#default_image=", patched)
        self.assertIn("#fallback_image=", patched)
        self.assertIn('default_uki="/boot/EFI/Linux/arch-linux.efi"', patched)
        self.assertIn('default_options=""', patched)
        self.assertIn(
            'fallback_uki="/boot/EFI/Linux/arch-linux-fallback.efi"', patched
        )
        self.assertIn('fallback_options="-S autodetect"', patched)
        # Idempotent
        self.assertEqual(patched, patcher.patch_linux_preset(patched, fallback=True))

    def test_patch_snapper_config_preserves_subvolume_and_tunes_limits(self) -> None:
        sample = """\
SUBVOLUME="/"
FSTYPE="btrfs"
ALLOW_GROUPS=""
NUMBER_MIN_AGE="1800"
NUMBER_LIMIT="50"
NUMBER_LIMIT_IMPORTANT="10"
TIMELINE_MIN_AGE="1800"
TIMELINE_LIMIT_HOURLY="10"
TIMELINE_LIMIT_DAILY="10"
TIMELINE_LIMIT_WEEKLY="0"
TIMELINE_LIMIT_MONTHLY="10"
TIMELINE_LIMIT_QUARTERLY="0"
TIMELINE_LIMIT_YEARLY="10"
EMPTY_PRE_POST_MIN_AGE="1800"
"""
        patched = patcher.patch_snapper_config(sample)
        self.assertIn('SUBVOLUME="/"', patched)
        self.assertIn('FSTYPE="btrfs"', patched)
        self.assertIn('ALLOW_GROUPS="wheel"', patched)
        self.assertIn('NUMBER_LIMIT="15"', patched)
        self.assertIn('NUMBER_MIN_AGE="3600"', patched)
        self.assertIn('TIMELINE_LIMIT_HOURLY="5"', patched)
        self.assertIn('TIMELINE_LIMIT_DAILY="7"', patched)
        self.assertIn('TIMELINE_LIMIT_MONTHLY="0"', patched)
        self.assertIn('TIMELINE_LIMIT_YEARLY="0"', patched)
        self.assertEqual(patched, patcher.patch_snapper_config(patched))

    def test_patch_loader_conf_preserves_comments(self) -> None:
        sample = """\
# Custom comment
timeout 5
#console-mode keep
"""
        patched = patcher.patch_loader_conf(sample)
        self.assertIn("# Custom comment", patched)
        self.assertIn("timeout 3", patched)
        self.assertIn("console-mode max", patched)
        self.assertIn("editor no", patched)
        self.assertEqual(patched, patcher.patch_loader_conf(patched))

    def test_patch_apparmor_parser_conf_enables_cache_and_fast_compress(self) -> None:
        sample = """\
## Turn creating/updating of the cache on by default
#write-cache

## Show cache hits
#show-cache

## Adjust compression
#Optimize=compress-small
#Optimize=compress-fast
"""
        patched = patcher.patch_apparmor_parser_conf(sample)
        self.assertIn("## Turn creating/updating of the cache on by default", patched)
        self.assertIn("\nwrite-cache\n", patched)
        self.assertIn("#show-cache", patched)
        self.assertIn("#Optimize=compress-small", patched)
        self.assertIn("\nOptimize=compress-fast\n", patched)
        self.assertEqual(patched, patcher.patch_apparmor_parser_conf(patched))

    def test_patch_pam_system_auth_removes_nullok_only_on_pam_unix_lines(self) -> None:
        sample = """\
#%PAM-1.0
# Comment mentioning pam_unix.so nullok must stay intact
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       optional                    pam_unix.so          try_first_pass nullresetok
password   required                    pam_unix.so          try_first_pass nullok shadow
"""
        patched = patcher.patch_pam_system_auth(sample)
        self.assertIn("# Comment mentioning pam_unix.so nullok must stay intact", patched)
        self.assertIn("try_first_pass\n", patched)
        self.assertIn("try_first_pass nullresetok\n", patched)
        self.assertIn("try_first_pass shadow\n", patched)
        self.assertNotIn("try_first_pass nullok", patched)
        self.assertEqual(patched, patcher.patch_pam_system_auth(patched))

    def test_patch_login_defs_updates_umask_without_corrupting_prose_comment(self) -> None:
        sample = """\
# UMASK is also used by useradd(8) and newusers(8) to set the mode for new
# home directories if HOME_MODE is not set.
UMASK\t\t022
HOME_MODE\t0700
ENCRYPT_METHOD YESCRYPT
"""
        patched = patcher.patch_login_defs(sample)
        self.assertIn(
            "# UMASK is also used by useradd(8) and newusers(8) to set the mode for new",
            patched,
        )
        self.assertIn("\nUMASK\t\t027\n", patched)
        self.assertNotIn("UMASK\t\t022", patched)
        self.assertIn("HOME_MODE\t0700", patched)
        self.assertIn("ENCRYPT_METHOD YESCRYPT", patched)
        self.assertEqual(patched, patcher.patch_login_defs(patched))

    def test_normalize_fstab_sets_boot_passno_2_and_btrfs_0(self) -> None:
        sample = """\
# Static filesystem table
UUID=aaa / btrfs rw,noatime,subvol=/@ 0 1
UUID=bbb /boot vfat rw,fmask=0177,dmask=0077 0 0
/swap/swapfile none swap defaults 0 0
"""
        out = disk.normalize_fstab(sample)
        self.assertIn("# Static filesystem table", out)
        self.assertIn("UUID=aaa\t/\tbtrfs\trw,noatime,subvol=/@\t0\t0", out)
        self.assertIn("UUID=bbb\t/boot\tvfat\trw,fmask=0177,dmask=0077\t0\t2", out)
        self.assertIn("/swap/swapfile none swap defaults 0 0", out)


if __name__ == "__main__":
    unittest.main()
