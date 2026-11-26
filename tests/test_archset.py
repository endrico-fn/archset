#!/usr/bin/env python3
"""Unit tests for archset guards, UKI sd-encrypt config, --additional, and log redaction."""

from __future__ import annotations

import contextlib
import fcntl
import os
import pty
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import archset  # noqa: E402
from src import additional, configs, disk, hardware, system, ui  # noqa: E402


class StaticFilesAndBootConfigTests(unittest.TestCase):
    def test_all_registered_static_files_exist_and_non_empty(self) -> None:
        for src_rel, _dst, _mode in configs.SYSTEM_STATIC_FILES:
            content = configs.load_file(src_rel)
            self.assertTrue(content.strip(), f"Empty system static file: {src_rel}")
        for src_rel, _dst, _mode in configs.USER_STATIC_FILES:
            content = configs.load_file(src_rel)
            self.assertTrue(content.strip(), f"Empty user static file: {src_rel}")

        mk_dropin = configs.load_file(configs.MKINITCPIO_DROPIN_SRC)
        self.assertIn("systemd", mk_dropin)
        self.assertIn("sd-encrypt", mk_dropin)
        self.assertIn("sd-archrelius", mk_dropin)
        self.assertIn("sd-vconsole", mk_dropin)
        self.assertNotIn("udev", mk_dropin)

        sd_hook = configs.load_file("etc/initcpio/install/sd-archrelius")
        self.assertIn("add_binary /usr/local/lib/systemd/archrelius-askpw", sd_hook)
        self.assertIn("add_systemd_drop_in systemd-ask-password-console.service", sd_hook)

        i915 = configs.load_file("etc/modprobe.d/i915.conf")
        self.assertNotIn("fastboot", i915)
        self.assertIn("enable_fbc=1", i915)

    def test_cmdline_root_uses_sd_encrypt_luks_uuid_not_partuuid(self) -> None:
        sample_uuid = "11111111-2222-3333-4444-555555555555"
        cmdline = configs.cmdline_root(sample_uuid)
        self.assertIn(f"rd.luks.name={sample_uuid}=root", cmdline)
        self.assertIn(f"rd.luks.options={sample_uuid}=discard", cmdline)
        self.assertIn("root=/dev/mapper/root", cmdline)
        self.assertIn("rootflags=subvol=@", cmdline)
        self.assertNotIn("cryptdevice=", cmdline)
        self.assertNotIn("PARTUUID=", cmdline)

    def test_security_cmdline_and_audit_hardening_assets(self) -> None:
        sec_cmdline = configs.load_file(configs.CMDLINE_SECURITY_SRC)
        for token in (
            "lsm=landlock,lockdown,yama,integrity,apparmor,bpf",
            "audit=1",
            "audit_backlog_limit=8192",
            "lockdown=integrity",
            "init_on_alloc=1",
            "slab_nomerge",
            "vsyscall=none",
            "randomize_kstack_offset=on",
        ):
            self.assertIn(token, sec_cmdline)

        boot_ui_cmdline = configs.load_file(configs.CMDLINE_BOOT_UI_SRC)
        for token in (
            "quiet",
            "loglevel=3",
            "rd.udev.log_level=3",
            "systemd.tpm2_measured_os=0",
            "systemd.tpm2_wait=0",
        ):
            self.assertIn(token, boot_ui_cmdline)

        # Do not shadow upstream /usr/lib/tmpfiles.d/audit.conf (keep root-only 0700 logs)
        self.assertFalse(configs.file_path("etc/tmpfiles.d/audit.conf").exists())
        static_map = {dst: mode for _src, dst, mode in configs.SYSTEM_STATIC_FILES}
        self.assertNotIn("/etc/tmpfiles.d/audit.conf", static_map)
        self.assertEqual(static_map["/etc/nftables.conf"], 0o600)

        nft = configs.load_file("etc/nftables.conf")
        self.assertIn(
            "fib daddr . iif type != { local, broadcast, multicast } counter drop", nft
        )
        self.assertIn("limit rate 10/minute burst 15 packets accept", nft)

        nm_conf = configs.load_file("etc/NetworkManager/conf.d/nm.conf")
        self.assertIn("ipv6.method=disabled", nm_conf)

        zram_conf = configs.load_file("etc/systemd/zram-generator.conf")
        self.assertIn("zram-size = min(ram, 8192)", zram_conf)
        self.assertIn("swap-priority = 100", zram_conf)

        sysctl_conf = configs.load_file("etc/sysctl.d/99-knsfd.conf")
        self.assertIn("vm.swappiness                                                           = 80", sysctl_conf)
        self.assertIn("kernel.unprivileged_bpf_disabled                                        = 1", sysctl_conf)
        self.assertIn("kernel.yama.ptrace_scope                                                = 1", sysctl_conf)
        self.assertIn("vm.mmap_rnd_bits                                                        = 32", sysctl_conf)
        self.assertIn("vm.mmap_rnd_compat_bits                                                 = 16", sysctl_conf)
        self.assertIn("net.ipv4.conf.all.log_martians                                          = 1", sysctl_conf)
        self.assertIn("net.ipv4.conf.all.drop_unicast_in_l2_multicast                          = 1", sysctl_conf)
        self.assertIn("net.ipv6.conf.all.accept_redirects                                      = 0", sysctl_conf)

        wpa_sandbox = configs.load_file(
            "etc/systemd/system/wpa_supplicant.service.d/10-hardening.conf"
        )
        self.assertIn("ProtectSystem=strict", wpa_sandbox)
        self.assertIn("RuntimeDirectory=wpa_supplicant", wpa_sandbox)
        self.assertIn("DevicePolicy=closed", wpa_sandbox)
        self.assertIn("DeviceAllow=/dev/rfkill rw", wpa_sandbox)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", wpa_sandbox)
        self.assertNotIn("PrivateDevices=true", wpa_sandbox)

        audit_rules = configs.load_file("etc/audit/rules.d/30-archset.rules")
        active_audit = [
            l.strip()
            for l in audit_rules.splitlines()
            if l.strip() and not l.lstrip().startswith("#")
        ]
        self.assertIn("-w /etc/shadow -p wa -k identity", active_audit)
        self.assertIn("-w /etc/sudoers.d/ -p wa -k sudoers", active_audit)
        self.assertIn("-w /etc/nftables.conf -p wa -k firewall", active_audit)
        self.assertNotIn("-e 2", active_audit)
        self.assertEqual(static_map["/etc/audit/rules.d/30-archset.rules"], 0o640)

        coredump_conf = configs.load_file("etc/systemd/coredump.conf.d/00-limit.conf")
        self.assertIn("Storage=none", coredump_conf)
        self.assertIn("ProcessSizeMax=0", coredump_conf)
        limits_conf = configs.load_file("etc/security/limits.d/10-coredump.conf")
        self.assertIn("* hard core 0", limits_conf)

        mod_bl_active = [
            l.strip()
            for l in configs.load_file("etc/modprobe.d/blacklist-unused.conf").splitlines()
            if l.strip() and not l.lstrip().startswith("#")
        ]
        for mod in ("sctp", "rds", "tipc", "firewire-ohci"):
            self.assertIn(f"install {mod} /usr/bin/false", mod_bl_active)
        self.assertFalse(any("usb-storage" in l for l in mod_bl_active))

        self.assertIn("Defaults umask = 0022", configs.SUDOERS_UMASK)
        self.assertIn("Defaults umask_override", configs.SUDOERS_UMASK)

        self.assertIn("audit", system.INSTALL_PHASES["Network, Wi-Fi, Bluetooth & Security"])
        self.assertIn("auditd.service", system.REQUIRED_SERVICES)
        self.assertIn("audit-rules.service", system.REQUIRED_SERVICES)

    def test_verify_enforces_safe_shadow_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home" / "alice"
            required_rel = [
                "etc/fstab",
                "etc/mkinitcpio.conf.d/10-archset.conf",
                "etc/cmdline.d/10-root.conf",
                "etc/cmdline.d/20-security.conf",
                "etc/cmdline.d/30-boot-ui.conf",
                "boot/EFI/Linux/arch-linux.efi",
                "boot/loader/loader.conf",
                "etc/snapper/configs/root",
                "etc/snapper/configs/home",
                "etc/udev/rules.d/50-usb-hid-nosuspend.rules",
                "etc/nftables.conf",
                "etc/sysctl.d/99-knsfd.conf",
                "etc/sudoers.d/20-umask",
                "etc/audit/rules.d/30-archset.rules",
                "etc/security/limits.d/10-coredump.conf",
                "etc/modprobe.d/blacklist-unused.conf",
                "etc/archrelius.conf",
                "etc/initcpio/install/sd-archrelius",
                "usr/local/src/archrelius-askpw.c",
                "usr/local/lib/systemd/archrelius-askpw",
                "etc/systemd/system/wpa_supplicant.service.d/10-hardening.conf",
                "etc/systemd/resolved.conf.d/10-dnscrypt.conf",
                "etc/NetworkManager/dispatcher.d/10-enforce-no-ipv6.sh",
                "home/alice/.zshenv",
                "home/alice/.config/zsh/.zshenv",
                "home/alice/.config/zsh/.zshrc",
                "home/alice/.config/environment.d/10-env.conf",
                "home/alice/.config/nvim/sudoedit.lua",
                "home/alice/.local/share/cargo/config.toml",
                "home/alice/.config/git/config",
                "home/alice/.config/kitty/kitty.conf",
                "home/alice/.config/kdeglobals",
                "home/alice/.local/share/color-schemes/BreezeDarkMod.colors",
                "home/alice/.config/starship.toml",
            ]
            for rel in required_rel:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("placeholder\n", encoding="utf-8")

            (root / "etc/fstab").write_text("UUID=x / btrfs rw,subvol=/@ 0 0\n", encoding="utf-8")
            (root / "etc/cmdline.d/10-root.conf").write_text(
                "rd.luks.name=1234=root root=/dev/mapper/root\n", encoding="utf-8"
            )
            shadow = root / "etc/shadow"
            gshadow = root / "etc/gshadow"
            shadow.write_text("root:*:1:0:99999:7:::\n", encoding="utf-8")
            gshadow.write_text("root:::\n", encoding="utf-8")
            os.chmod(shadow, 0o000)
            os.chmod(gshadow, 0o600)

            prev_target = system.TARGET
            prev_dry_run = ui.DRY_RUN
            system.TARGET = str(root)
            ui.DRY_RUN = False
            try:
                fake_passwd = ui.Result(
                    "getent passwd alice",
                    0,
                    f"alice:x:1000:1000::/home/alice:{system.DEFAULT_SHELL}\n",
                    "",
                )
                with mock.patch.object(system, "chroot", return_value=fake_passwd):
                    # Mode 0000 breaks AppArmor v4 unix-chkpwd login -> must fail
                    with self.assertRaises(ui.ArchsetError) as ctx:
                        system.verify("alice")
                    self.assertIn("unsafe mode", str(ctx.exception))

                    # World-readable 0644 leaks hashes -> must fail
                    os.chmod(shadow, 0o644)
                    with self.assertRaises(ui.ArchsetError):
                        system.verify("alice")

                    # Standard Arch 0600 and future-proof 0640 -> both pass
                    os.chmod(shadow, 0o600)
                    system.verify("alice")
                    os.chmod(shadow, 0o640)
                    system.verify("alice")
            finally:
                os.chmod(shadow, 0o600)
                system.TARGET = prev_target
                ui.DRY_RUN = prev_dry_run
                self.assertTrue(home.exists())


class GuardsAndLoggingTests(unittest.TestCase):
    def test_instance_lock_prevents_double_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "archset.lock"
            with ui.InstanceLock(lock_path):
                with self.assertRaises(ui.ArchsetError) as ctx:
                    ui.InstanceLock(lock_path).acquire()
                self.assertIn("already running", str(ctx.exception))
            # Lock can be acquired again cleanly after release
            with ui.InstanceLock(lock_path):
                pass

    def test_logger_redacts_registered_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = ui.init(tmp)
            try:
                ui.log.register_secret("Sup3rS3cretRoot!")
                ui.log.register_secret("LuksP@ssphrase99")
                ui.info("Testing message with Sup3rS3cretRoot! inside")
                ui.debug("Raw debug LuksP@ssphrase99 leak check")
            finally:
                ui.log.clear_secrets()
                ui.log.close()

            text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("Sup3rS3cretRoot!", text)
            self.assertNotIn("LuksP@ssphrase99", text)
            self.assertIn("***REDACTED***", text)
            self.assertEqual(oct(log_path.stat().st_mode & 0o777), "0o600")

    def test_additional_standalone_dry_run_never_touches_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "test.lock"
            with (
                mock.patch.object(
                    disk, "wipe", side_effect=AssertionError("disk.wipe must not run")
                ),
                mock.patch.object(
                    disk,
                    "partition",
                    side_effect=AssertionError("disk.partition must not run"),
                ),
                mock.patch.object(
                    disk,
                    "luks_format",
                    side_effect=AssertionError("disk.luks_format must not run"),
                ),
            ):
                rc = archset.main(
                    [
                        "--appditional",
                        "--yes",
                        "--dry-run",
                        "--log-dir",
                        tmp,
                        "--lock-file",
                        str(lock_path),
                    ]
                )
            self.assertEqual(rc, 0)
            logs = list(Path(tmp).glob("archset-*.log"))
            self.assertEqual(len(logs), 1)
            log_text = logs[0].read_text(encoding="utf-8")
            self.assertIn("pacman -S --needed --noconfirm", log_text)
            self.assertIn("steam", log_text)


class InstallOrderAndNeovimTests(unittest.TestCase):
    def test_finalize_dns_symlink_runs_after_inject_user_configs(self) -> None:
        call_order: list[str] = []

        def record(name: str):
            def _fn(*_args, **_kwargs):
                call_order.append(name)
            return _fn

        inputs = archset.Inputs(
            hostname="archbox",
            username="alice",
            root_password="rootpassword1",
            user_password="userpassword2",
            luks_passphrase="lukspassphrase3",
            additional_packages=[],
        )
        info = disk.DiskInfo("/dev/nvme0n1", "nvme0n1", 256 * 1024**3, "NVMe", "1", "nvme")
        args = archset.parse_args(["--dry-run"])

        prev_dry_run = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with contextlib.ExitStack() as stack:
                for name in (
                    "wipe",
                    "partition",
                    "mkfs_esp",
                    "luks_format",
                    "luks_open",
                    "mkfs_btrfs",
                    "create_subvolumes",
                    "mount_all",
                    "mount_esp",
                    "make_swapfile",
                    "write_fstab",
                    "unmount_all",
                    "flush_and_unmount",
                ):
                    stack.enter_context(mock.patch.object(disk, name, side_effect=record(name)))
                for name in (
                    "install_base",
                    "copy_mirrorlist",
                    "configure_pacman",
                    "install_phases",
                    "configure_locale",
                    "create_user",
                    "setup_snapper",
                    "inject_system_configs",
                    "enable_services",
                    "setup_bootloader",
                    "inject_user_configs",
                    "finalize_dns_symlink",
                    "verify",
                    "export_logs",
                ):
                    stack.enter_context(mock.patch.object(system, name, side_effect=record(name)))
                archset.install(inputs, info, args)
        finally:
            ui.DRY_RUN = prev_dry_run

        self.assertLess(
            call_order.index("inject_user_configs"),
            call_order.index("finalize_dns_symlink"),
            "DNS symlink must run AFTER chroot git clones in inject_user_configs()",
        )
        self.assertLess(
            call_order.index("configure_locale"),
            call_order.index("setup_bootloader"),
            "/etc/vconsole.conf must exist before mkinitcpio sd-vconsole runs",
        )

    def test_unified_bracket_menu_and_post_install_chroot_then_poweroff_flush_order(self) -> None:
        import io

        # 1) Verify [ 1 ] / * [ 2 ] bracket rendering in ui.menu()
        buf = io.StringIO()
        with (
            mock.patch("builtins.input", return_value=""),
            contextlib.redirect_stdout(buf),
        ):
            choice = ui.menu(
                "Select Action",
                ["Enter arch-chroot", "Stay in Live ISO", "Poweroff System"],
                default=2,
                subtitles=["inspect /mnt", "", "safe USB removal"],
            )
        self.assertEqual(choice, 2)
        rendered = buf.getvalue()
        self.assertIn("[ 1 ] Enter arch-chroot", rendered)
        self.assertIn("└─ inspect /mnt", rendered)
        self.assertIn("* [ 3 ] Poweroff System", rendered)

        # 2) Verify post_install_action: [1] enters arch-chroot BEFORE DNS stub & unmount,
        #    then [3] finalizes DNS, exports logs, runs 6-stage SSD flush, and returns 'poweroff'
        events: list[str] = []
        info = disk.DiskInfo("/dev/nvme0n1", "nvme0n1", 512 * 1024**3, "Samsung", "S1", "nvme")
        inputs = archset.Inputs("archbox", "alice", "", "", "")

        with (
            mock.patch.object(ui, "menu", side_effect=[0, 2]),
            mock.patch.object(archset, "enter_arch_chroot", side_effect=lambda: events.append("chroot")),
            mock.patch.object(system, "finalize_dns_symlink", side_effect=lambda: events.append("dns_stub")),
            mock.patch.object(system, "export_logs", side_effect=lambda *_a: events.append("export_logs")),
            mock.patch.object(disk, "flush_and_unmount", side_effect=lambda *_a, **_kw: events.append("flush_ssd")),
        ):
            action = archset.post_install_action(info, inputs, interactive=True)

        self.assertEqual(action, "poweroff")
        self.assertEqual(events, ["chroot", "dns_stub", "export_logs", "flush_ssd"])

        # 3) Verify 6-stage hardware SSD flush sequence in disk.flush_and_unmount()
        flush_cmds: list[list[str]] = []
        prev_dry = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with mock.patch.object(
                ui,
                "run",
                side_effect=lambda cmd, **_kw: (flush_cmds.append(list(cmd)) or ui.Result("", 0, "", "")),
            ):
                disk.flush_and_unmount("/dev/nvme0n1", strict=True)
        finally:
            ui.DRY_RUN = prev_dry

        flat = [" ".join(c) for c in flush_cmds]
        self.assertIn("btrfs filesystem sync /mnt", flat)
        self.assertIn("umount -R /mnt", flat)
        self.assertIn("cryptsetup close root", flat)
        self.assertIn("blockdev --flushbufs /dev/nvme0n1", flat)
        self.assertLess(flat.index("btrfs filesystem sync /mnt"), flat.index("umount -R /mnt"))
        self.assertLess(flat.index("umount -R /mnt"), flat.index("cryptsetup close root"))
        self.assertLess(flat.index("cryptsetup close root"), flat.index("blockdev --flushbufs /dev/nvme0n1"))

        # 4) Verify poweroff action calls systemctl poweroff
        with mock.patch.object(subprocess, "run") as mock_sub:
            archset.execute_power_action("poweroff", dry_run=False)
            mock_sub.assert_called_once_with(["systemctl", "poweroff"], check=False)

    def test_nvim_clone_falls_back_to_sudoedit_lua_on_failure(self) -> None:
        written_paths: list[str] = []

        def fake_write(rel: str, _content: str, mode: int = 0o644) -> None:
            written_paths.append(rel)

        def fake_chroot(cmd: list[str], **_kwargs):
            if cmd[:2] == ["git", "clone"] and configs.NVIM_REPO_URL in cmd:
                raise ui.CommandError("git clone", 128, "network unreachable")
            return ui.Result(" ".join(cmd), 0, "", "")

        prev_dry_run = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with (
                mock.patch.object(system, "write", side_effect=fake_write),
                mock.patch.object(system, "chroot", side_effect=fake_chroot),
                mock.patch.object(ui, "mkdir"),
            ):
                system.inject_user_configs("alice", "archbox")
        finally:
            ui.DRY_RUN = prev_dry_run

        self.assertIn("/home/alice/.config/nvim/sudoedit.lua", written_paths)

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not available")
    def test_archrelius_askpw_c_compiles_with_hardened_flags_and_handles_pty_socket(
        self,
    ) -> None:
        src = configs.file_path("usr/local/src/archrelius-askpw.c")
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "archrelius-askpw"
            ask_dir = Path(tmp) / "ask-password"
            ask_dir.mkdir()
            sck_path = ask_dir / "sck.test"
            notify_path = Path(tmp) / "notify.sock"

            cc_cmd = [
                arg
                if arg not in (configs.ASKPW_SRC_DST, configs.ASKPW_BIN_DST)
                else (str(src) if arg == configs.ASKPW_SRC_DST else str(bin_path))
                for arg in configs.ASKPW_CC_ARGS
            ]
            subprocess.run(cc_cmd, check=True)

            recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            recv_sock.bind(str(sck_path))
            recv_sock.settimeout(5.0)

            notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            notify_sock.bind(str(notify_path))
            notify_sock.settimeout(5.0)

            (ask_dir / "ask.0001").write_text(
                f"[Ask]\nPID={os.getpid()}\nSocket={sck_path}\n"
                "Id=cryptsetup:/dev/nvme0n1p2\nMessage=Unlock:\n",
                encoding="utf-8",
            )

            master_fd, slave_fd = pty.openpty()
            # Start at dummycon 160x50 (exact pre-i915 KMS grid), then resize to 170x48!
            fcntl.ioctl(
                slave_fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 50, 160, 1280, 800),
            )
            env = os.environ.copy()
            env["NOTIFY_SOCKET"] = str(notify_path)

            proc = subprocess.Popen(
                [
                    str(bin_path),
                    "--query",
                    "--no-intro",
                    f"--tty={os.ttyname(slave_fd)}",
                    f"--ask-dir={ask_dir}",
                ],
                env=env,
            )
            try:
                self.assertEqual(notify_sock.recv(64), b"READY=1\n")
                # Read initial 160x50 TUI frame with greenish-cyan (#64beaf = 100;190;175) accent
                rendered = bytearray()
                deadline = time.time() + 1.2
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        rendered.extend(os.read(master_fd, 16384))
                        if "Enter passphrase for /dev/nvme0n1p2: " in rendered.decode(
                            "utf-8", "replace"
                        ):
                            break
                text_ui = rendered.decode("utf-8", "replace")
                self.assertIn("Enter passphrase for /dev/nvme0n1p2: ", text_ui)
                self.assertIn("38;2;100;190;175m", text_ui)
                # Only the passphrase box itself may draw corner glyphs (no banner corner brackets)
                self.assertEqual(text_ui.count("┌"), 1)
                self.assertEqual(text_ui.count("┐"), 1)
                self.assertEqual(text_ui.count("└"), 1)
                self.assertEqual(text_ui.count("┘"), 1)

                # Simulate i915drmfb deferred takeover switching console to 170x48
                fcntl.ioctl(
                    slave_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 48, 170, 1366, 768),
                )

                # Tab and Shift+Tab must be ignored (single Quantum theme, no theme toast, buffer intact)
                os.write(master_fd, b"Secr\t\x1b[Z")
                buf2 = bytearray()
                end_wait = time.time() + 0.15
                while time.time() < end_wait:
                    r, _, _ = select.select([master_fd], [], [], 0.04)
                    if r:
                        buf2.extend(os.read(master_fd, 32768))
                self.assertNotIn("Theme ", buf2.decode("utf-8", "replace"))

                os.write(master_fd, b"X\x7f\x1b[Det#99\n")
                # Drain PTY output while waiting for socket datagram & process exit
                deadline = time.time() + 2.0
                reply = b""
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd, recv_sock], [], [], 0.05)
                    if master_fd in r:
                        try:
                            os.read(master_fd, 32768)
                        except OSError:
                            pass
                    if recv_sock in r:
                        reply = recv_sock.recv(256)
                        break
                self.assertEqual(reply, b"+Secret#99")
                while proc.poll() is None and time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.02)
                    if r:
                        try:
                            os.read(master_fd, 32768)
                        except OSError:
                            break
                self.assertEqual(proc.wait(timeout=3), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
                os.close(master_fd)
                os.close(slave_fd)
                recv_sock.close()
                notify_sock.close()

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not available")
    def test_archrelius_elf_hardening_and_systemd_dropin_sandbox(self) -> None:
        src = configs.file_path("usr/local/src/archrelius-askpw.c")
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "archrelius-askpw"
            cc_cmd = [
                arg
                if arg not in (configs.ASKPW_SRC_DST, configs.ASKPW_BIN_DST)
                else (str(src) if arg == configs.ASKPW_SRC_DST else str(bin_path))
                for arg in configs.ASKPW_CC_ARGS
            ]
            subprocess.run(cc_cmd, check=True)

            notes = subprocess.run(
                ["readelf", "-n", str(bin_path)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertIn("IBT", notes, "Missing Intel CET IBT (-fcf-protection)")
            self.assertIn("SHSTK", notes, "Missing Shadow Stack (-fcf-protection)")

            phdrs = subprocess.run(
                ["readelf", "-l", str(bin_path)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertIn("GNU_RELRO", phdrs)
            for line in phdrs.splitlines():
                if "GNU_STACK" in line:
                    self.assertNotIn("RWE", line)

            # Execute sd-archrelius build() in a controlled shell harness
            hook_path = configs.file_path("etc/initcpio/install/sd-archrelius")
            conf_file = configs.file_path("etc/archrelius.conf")
            self.assertTrue(conf_file.is_file(), "Missing default files/etc/archrelius.conf")

            harness = f"""
            set -euo pipefail
            added_bins=()
            added_files=()
            warning() {{ echo "WARN:$*"; }}
            add_binary() {{ added_bins+=("$1"); }}
            add_file() {{ added_files+=("$1"); }}
            add_systemd_drop_in() {{
                echo "DROPIN:$1:$2"
                cat
            }}
            source "{hook_path}"
            build_fn="$(declare -f build)"
            build_fn="${{build_fn//\\/usr\\/local\\/lib\\/systemd\\/archrelius-askpw/{bin_path}}}"
            build_fn="${{build_fn//\\/etc\\/archrelius.conf/{conf_file}}}"
            eval "$build_fn"
            build
            printf 'BINS:%s\\n' "${{added_bins[*]}}"
            printf 'FILES:%s\\n' "${{added_files[*]}}"
            """
            res = subprocess.run(
                ["bash", "-c", harness], capture_output=True, text=True, check=True
            )
            self.assertIn(f"FILES:{conf_file}", res.stdout)
            for directive in (
                "LimitCORE=0",
                "IPAddressDeny=any",
                "RestrictAddressFamilies=AF_UNIX",
                "MemoryDenyWriteExecute=yes",
                "LockPersonality=yes",
                "RestrictRealtime=yes",
            ):
                self.assertIn(directive, res.stdout)

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not available")
    def test_archrelius_real_boot_unlock_scanner_and_access_granted_without_echo_leak(
        self,
    ) -> None:
        src = configs.file_path("usr/local/src/archrelius-askpw.c")
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "archrelius-askpw"
            ask_dir = Path(tmp) / "ask-password"
            ask_dir.mkdir()
            sck_path = ask_dir / "sck.real"
            sym_sck = ask_dir / "sck.symlink"

            cc_cmd = [
                arg
                if arg not in (configs.ASKPW_SRC_DST, configs.ASKPW_BIN_DST)
                else (str(src) if arg == configs.ASKPW_SRC_DST else str(bin_path))
                for arg in configs.ASKPW_CC_ARGS
            ]
            subprocess.run(cc_cmd, check=True)

            recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            recv_sock.bind(str(sck_path))
            recv_sock.settimeout(5.0)
            sym_sck.symlink_to(sck_path)

            # Symlinked socket must be rejected (never trusted via lstat)
            (ask_dir / "ask.sym").write_text(
                f"[Ask]\nPID={os.getpid()}\nSocket={sym_sck}\n"
                "Id=cryptsetup:/dev/nvme0n1p2\nMessage=Bad symlink:\n",
                encoding="utf-8",
            )

            # Simulate real systemd-cryptsetup worker process that unlinks ask.*
            # immediately upon receiving datagram, runs Argon2id, then exits 0.
            crypt_worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

            ask_file = ask_dir / "ask.0002"
            ask_file.write_text(
                f"[Ask]\nPID={crypt_worker.pid}\nSocket={sck_path}\n"
                "Id=tls:nginx\nMessage=Enter TLS key passphrase:\n",
                encoding="utf-8",
            )

            master_fd, slave_fd = pty.openpty()
            # 4K display size with 8x16 font -> 480x135
            fcntl.ioctl(
                slave_fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 135, 480, 3840, 2160),
            )

            proc = subprocess.Popen(
                [
                    str(bin_path),
                    "--watch",
                    "--no-intro",
                    f"--tty={os.ttyname(slave_fd)}",
                    f"--ask-dir={ask_dir}",
                ],
            )
            try:
                out = bytearray()
                deadline = time.time() + 1.5
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        out.extend(os.read(master_fd, 65536))
                        decoded = out.decode("utf-8", "replace")
                        if "Enter TLS key passphrase:" in decoded:
                            break
                decoded = out.decode("utf-8", "replace")
                self.assertIn("Enter TLS key passphrase:", decoded)
                self.assertNotIn("/dev/mapper/root", decoded)
                self.assertIn("\x1b[?7l", decoded)
                self.assertIn("\x1b[?2026h", decoded)

                # Submit passphrase; immediately unlink ask.0002 just like systemd-cryptsetup
                # does BEFORE running Argon2id while crypt_worker PID remains alive!
                os.write(master_fd, b"FirstPass\n")
                reply = recv_sock.recv(256)
                self.assertEqual(reply, b"+FirstPass")
                ask_file.unlink()

                # Inject stray keystrokes during Argon2id — MUST NEVER ECHO, and
                # "Unlocking volume" MUST remain visible while crypt_worker is alive!
                os.write(master_fd, b"LeakedDuringArgon2id")
                argon_out = bytearray()
                end_window = time.time() + 0.30
                while time.time() < end_window:
                    r, _, _ = select.select([master_fd], [], [], 0.04)
                    if r:
                        argon_out.extend(os.read(master_fd, 65536))

                argon_txt = argon_out.decode("utf-8", "replace")
                self.assertIn("Unlocking volume", argon_txt)
                self.assertNotIn(
                    "LeakedDuringArgon2id",
                    argon_txt,
                    "CRITICAL: Extra keystrokes during Argon2id echoed in plaintext!",
                )

                # Finish crypt_worker (Argon2id succeeded) -> ACCESS GRANTED must render!
                crypt_worker.terminate()
                crypt_worker.wait(timeout=2)

                grant_out = bytearray()
                deadline = time.time() + 1.5
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        grant_out.extend(os.read(master_fd, 65536))
                        if "ACCESS GRANTED" in grant_out.decode("utf-8", "replace"):
                            break

                grant_txt = grant_out.decode("utf-8", "replace")
                self.assertIn("ACCESS GRANTED", grant_txt)
                self.assertIn("38;2;86;184;141m", grant_txt)

                (ask_dir / "ask.sym").unlink()
                proc.terminate()
                while proc.poll() is None:
                    r, _, _ = select.select([master_fd], [], [], 0.02)
                    if r:
                        try:
                            grant_out.extend(os.read(master_fd, 65536))
                        except OSError:
                            break
                self.assertEqual(proc.wait(timeout=3), 0)
                self.assertNotIn(
                    "LeakedDuringArgon2id",
                    grant_out.decode("utf-8", "replace"),
                )
            finally:
                if crypt_worker.poll() is None:
                    crypt_worker.kill()
                    crypt_worker.wait(timeout=2)
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
                os.close(master_fd)
                os.close(slave_fd)
                recv_sock.close()

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not available")
    def test_archrelius_conf_safe_customization_and_malformed_rejection(self) -> None:
        src = configs.file_path("usr/local/src/archrelius-askpw.c")
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "archrelius-askpw"
            ask_dir = Path(tmp) / "ask-password"
            ask_dir.mkdir()
            sck_path = ask_dir / "sck.cfg"

            cc_cmd = [
                arg
                if arg not in (configs.ASKPW_SRC_DST, configs.ASKPW_BIN_DST)
                else (str(src) if arg == configs.ASKPW_SRC_DST else str(bin_path))
                for arg in configs.ASKPW_CC_ARGS
            ]
            subprocess.run(cc_cmd, check=True)

            recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                recv_sock.bind(str(sck_path))
                recv_sock.settimeout(5.0)

                (ask_dir / "ask.0001").write_text(
                    f"[Ask]\nPID={os.getpid()}\nSocket={sck_path}\n"
                    "Id=cryptsetup:/dev/nvme0n1p2\nMessage=Unlock:\n",
                    encoding="utf-8",
                )

                # 1) Custom declarative config: custom hex #58a6ff (88;166;255), custom label
                cfg_ok = Path(tmp) / "custom.conf"
                cfg_ok.write_text(
                    "intro = false\n"
                    "accent_color = #58a6ff\n"
                    "highlight_color = #a5d6ff\n"
                    "compact_title = MYVAULT\n",
                    encoding="utf-8",
                )

                master_fd, slave_fd = pty.openpty()
                # Compact viewport (80x24) to verify custom compact_title + custom RGB
                fcntl.ioctl(
                    slave_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 24, 80, 640, 384),
                )
                proc = subprocess.Popen(
                    [
                        str(bin_path),
                        "--query",
                        f"--config={cfg_ok}",
                        f"--tty={os.ttyname(slave_fd)}",
                        f"--ask-dir={ask_dir}",
                    ],
                )
                try:
                    out = bytearray()
                    deadline = time.time() + 1.2
                    while time.time() < deadline:
                        r, _, _ = select.select([master_fd], [], [], 0.05)
                        if r:
                            out.extend(os.read(master_fd, 32768))
                            txt = out.decode("utf-8", "replace")
                            if "MYVAULT" in txt and "Enter passphrase" in txt:
                                break
                    txt = out.decode("utf-8", "replace")
                    self.assertIn("MYVAULT", txt)
                    self.assertIn("38;2;88;166;255m", txt)
                    self.assertIn("38;2;165;214;255m", txt)
                    os.write(master_fd, b"ok\n")
                    self.assertEqual(recv_sock.recv(64), b"+ok")
                    self.assertEqual(proc.wait(timeout=3), 0)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=2)
                    os.close(master_fd)
                    os.close(slave_fd)

                # 2) Malformed values + symlink config -> rejected safely, falls back to #64beaf (100;190;175)
                cfg_bad = Path(tmp) / "bad.conf"
                cfg_bad.write_text(
                    "theme = 9999\n"
                    "accent_color = $(reboot)\n"
                    "compact_title = \x1b[2Jevil\n",
                    encoding="utf-8",
                )
                cfg_sym = Path(tmp) / "sym.conf"
                cfg_sym.symlink_to(cfg_ok)

                for test_cfg in (cfg_bad, cfg_sym):
                    master_fd, slave_fd = pty.openpty()
                    fcntl.ioctl(
                        slave_fd,
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", 48, 170, 1366, 768),
                    )
                    proc = subprocess.Popen(
                        [
                            str(bin_path),
                            "--query",
                            "--no-intro",
                            f"--config={test_cfg}",
                            f"--tty={os.ttyname(slave_fd)}",
                            f"--ask-dir={ask_dir}",
                        ],
                    )
                    try:
                        out = bytearray()
                        deadline = time.time() + 1.2
                        while time.time() < deadline:
                            r, _, _ = select.select([master_fd], [], [], 0.05)
                            if r:
                                out.extend(os.read(master_fd, 32768))
                                if "38;2;100;190;175m" in out.decode("utf-8", "replace"):
                                    break
                        txt = out.decode("utf-8", "replace")
                        self.assertIn("38;2;100;190;175m", txt)
                        self.assertNotIn("MYVAULT", txt)
                        self.assertNotIn("evil", txt)
                        os.write(master_fd, b"fallback\n")
                        self.assertEqual(recv_sock.recv(64), b"+fallback")
                        self.assertEqual(proc.wait(timeout=3), 0)
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.wait(timeout=2)
                        os.close(master_fd)
                        os.close(slave_fd)
            finally:
                recv_sock.close()

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not available")
    def test_archrelius_masked_feedback_multivolume_guard_fifo_and_preview(self) -> None:
        src = configs.file_path("usr/local/src/archrelius-askpw.c")
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "archrelius-askpw"
            ask_dir = Path(tmp) / "ask-password"
            mapper_dir = Path(tmp) / "mapper"
            ask_dir.mkdir()
            mapper_dir.mkdir()
            # Pre-populate 1 already-unlocked volume (simulating multi-volume LUKS setup)
            (mapper_dir / "root").write_text("", encoding="utf-8")

            cc_cmd = [
                arg
                if arg not in (configs.ASKPW_SRC_DST, configs.ASKPW_BIN_DST)
                else (str(src) if arg == configs.ASKPW_SRC_DST else str(bin_path))
                for arg in configs.ASKPW_CC_ARGS
            ]
            subprocess.run(cc_cmd, check=True)

            # 1) Preview mode renders HUD, masked password feedback on typing, and exits cleanly on Esc
            master_p, slave_p = pty.openpty()
            fcntl.ioctl(slave_p, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 130, 1040, 480))
            cfg_mask = Path(tmp) / "masked.conf"
            cfg_mask.write_text("intro = false\npassword_feedback = masked\n", encoding="utf-8")

            proc_p = subprocess.Popen(
                [
                    str(bin_path),
                    "--preview",
                    f"--config={cfg_mask}",
                    f"--tty={os.ttyname(slave_p)}",
                ]
            )
            try:
                preview_buf = bytearray()
                deadline = time.time() + 1.2
                while time.time() < deadline:
                    r, _, _ = select.select([master_p], [], [], 0.05)
                    if r:
                        preview_buf.extend(os.read(master_p, 32768))
                        if "[PREVIEW]" in preview_buf.decode("utf-8", "replace"):
                            break
                self.assertIn("[PREVIEW]", preview_buf.decode("utf-8", "replace"))

                # Type 3 chars after raw TTY is ready -> must render 3 bullet masks ('•') without plaintext
                os.write(master_p, b"abc")
                typed_buf = bytearray()
                deadline = time.time() + 1.0
                while time.time() < deadline:
                    r, _, _ = select.select([master_p], [], [], 0.05)
                    if r:
                        typed_buf.extend(os.read(master_p, 32768))
                        if typed_buf.decode("utf-8", "replace").count("•") >= 3:
                            break
                ttxt = typed_buf.decode("utf-8", "replace")
                self.assertGreaterEqual(ttxt.count("•"), 3)
                self.assertNotIn("abc", ttxt)
                os.write(master_p, b"\x1b")
                self.assertEqual(proc_p.wait(timeout=3), 0)
            finally:
                if proc_p.poll() is None:
                    proc_p.kill()
                    proc_p.wait(timeout=2)
                os.close(master_p)
                os.close(slave_p)

            # 2) Multi-volume LUKS failure (mapper_before == 1, mapper_now == 1 after worker exits)
            #    MUST NOT render false-positive ACCESS GRANTED!
            sck_path = ask_dir / "sck.multi"
            recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            recv_sock.bind(str(sck_path))
            recv_sock.settimeout(5.0)
            worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

            ask_f = ask_dir / "ask.second"
            ask_f.write_text(
                f"[Ask]\nPID={worker.pid}\nSocket={sck_path}\n"
                "Id=cryptsetup:/dev/nvme1n1p1\nMessage=Unlock data:\n",
                encoding="utf-8",
            )

            master_m, slave_m = pty.openpty()
            fcntl.ioctl(slave_m, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 130, 1040, 480))
            proc_m = subprocess.Popen(
                [
                    str(bin_path),
                    "--query",
                    "--no-intro",
                    f"--tty={os.ttyname(slave_m)}",
                    f"--ask-dir={ask_dir}",
                    f"--mapper-dir={mapper_dir}",
                ]
            )
            try:
                out_m = bytearray()
                deadline = time.time() + 1.0
                while time.time() < deadline:
                    r, _, _ = select.select([master_m], [], [], 0.05)
                    if r:
                        out_m.extend(os.read(master_m, 32768))
                        if "Enter passphrase for /dev/nvme1n1p1:" in out_m.decode("utf-8", "replace"):
                            break
                os.write(master_m, b"WrongPassOnLastTry\n")
                self.assertEqual(recv_sock.recv(64), b"+WrongPassOnLastTry")
                ask_f.unlink()
                # Worker exits WITHOUT adding a 2nd mapper target (still only 1 target 'root')
                worker.terminate()
                worker.wait(timeout=2)

                while proc_m.poll() is None:
                    r, _, _ = select.select([master_m], [], [], 0.03)
                    if r:
                        try:
                            out_m.extend(os.read(master_m, 32768))
                        except OSError:
                            break
                self.assertEqual(proc_m.wait(timeout=3), 0)
                self.assertNotIn(
                    "ACCESS GRANTED",
                    out_m.decode("utf-8", "replace"),
                    "Must NOT show ACCESS GRANTED when 2nd LUKS volume fails to add a mapper target!",
                )
            finally:
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=2)
                if proc_m.poll() is None:
                    proc_m.kill()
                    proc_m.wait(timeout=2)
                os.close(master_m)
                os.close(slave_m)
                recv_sock.close()


class HardwareAndAdditionalPlanTests(unittest.TestCase):
    def test_hardware_detect_enforces_strict_intel_only_and_supports_i915_xe_hybrid_hidpi(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            # 1) AMD system MUST be rejected by strict Intel-only guard
            cpu_amd = base / "cpu_amd"
            cpu_amd.write_text("vendor_id\t: AuthenticAMD\nflags\t\t: fpu sse2\n", encoding="utf-8")
            pci_amd = base / "pci_amd"
            (pci_amd / "0000:03:00.0").mkdir(parents=True)
            (pci_amd / "0000:03:00.0/class").write_text("0x030000\n", encoding="utf-8")
            (pci_amd / "0000:03:00.0/vendor").write_text("0x1002\n", encoding="utf-8")

            hw_amd = hardware.detect(
                proc_cpuinfo=cpu_amd,
                pci_dir=pci_amd,
                dmi_dir=base / "no_dmi",
                modules_dir=base / "no_mods",
                drm_dir=base / "no_drm",
            )
            self.assertEqual(hw_amd.cpu_vendor, "amd")
            with self.assertRaises(ui.ArchsetError):
                hardware.assert_intel_hardware(hw_amd, allow_vm=False)

            # 2) Modern Intel Lunar Lake / Xe2 laptop (xe driver + 2.8K HiDPI + rtw89 NOT rtw88 + hybrid NVIDIA)
            cpu_intel = base / "cpu_intel"
            cpu_intel.write_text("vendor_id\t: GenuineIntel\nflags\t\t: fpu sse4_2\n", encoding="utf-8")
            pci_xe = base / "pci_xe"
            drv_xe = base / "drivers" / "xe"
            drv_rtw89 = base / "drivers" / "rtw89_8852be"
            drv_sof = base / "drivers" / "sof-audio-pci-intel-lnl"
            for d in (drv_xe, drv_rtw89, drv_sof):
                d.mkdir(parents=True)

            igpu = pci_xe / "0000:00:02.0"
            igpu.mkdir(parents=True)
            (igpu / "class").write_text("0x030000\n", encoding="utf-8")
            (igpu / "vendor").write_text("0x8086\n", encoding="utf-8")
            (igpu / "driver").symlink_to(drv_xe)

            dgpu = pci_xe / "0000:01:00.0"
            dgpu.mkdir(parents=True)
            (dgpu / "class").write_text("0x030200\n", encoding="utf-8")
            (dgpu / "vendor").write_text("0x10de\n", encoding="utf-8")

            wifi = pci_xe / "0000:02:00.0"
            wifi.mkdir(parents=True)
            (wifi / "class").write_text("0x028000\n", encoding="utf-8")
            (wifi / "vendor").write_text("0x10ec\n", encoding="utf-8")
            (wifi / "driver").symlink_to(drv_rtw89)

            audio = pci_xe / "0000:00:1f.3"
            audio.mkdir(parents=True)
            (audio / "class").write_text("0x040100\n", encoding="utf-8")
            (audio / "vendor").write_text("0x8086\n", encoding="utf-8")
            (audio / "driver").symlink_to(drv_sof)

            drm_xe = base / "drm_xe"
            (drm_xe / "card0-eDP-1").mkdir(parents=True)
            (drm_xe / "card0-eDP-1/modes").write_text("2880x1800\n1920x1200\n", encoding="utf-8")

            hw_xe = hardware.detect(
                proc_cpuinfo=cpu_intel,
                pci_dir=pci_xe,
                dmi_dir=base / "no_dmi",
                modules_dir=base / "no_mods",
                drm_dir=drm_xe,
            )
            hardware.assert_intel_hardware(hw_xe, allow_vm=False)
            self.assertEqual(hw_xe.intel_drm_driver, "xe")
            self.assertEqual(hw_xe.initramfs_modules(), ["xe"])
            self.assertIn("MODULES=(xe)", hw_xe.mkinitcpio_dropin())
            self.assertFalse(hw_xe.has_rtw88_wifi, "rtw89 must not be misdetected as rtw88")
            self.assertTrue(hw_xe.has_nvidia_dgpu)
            self.assertTrue(hw_xe.has_sof_audio)
            self.assertEqual(hw_xe.console_font(), "ter-v32n")
            self.assertIn("vpl-gpu-rt", hw_xe.graphics_packages())
            self.assertNotIn("libva-mesa-driver", hw_xe.graphics_packages())
            self.assertEqual(hw_xe.multilib_gpu_packages(), ["lib32-mesa", "lib32-vulkan-intel"])

            # Verify inject_system_configs skips i915.conf on xe, injects blacklist-nvidia.conf, and skips rtw88
            written_dsts: list[str] = []
            prev_dry = ui.DRY_RUN
            ui.DRY_RUN = True
            try:
                with (
                    mock.patch.object(
                        system, "write", side_effect=lambda dst, *_a, **_k: written_dsts.append(dst)
                    ),
                    mock.patch.object(ui, "patch_file"),
                ):
                    system.inject_system_configs(hw_xe, regdom="US")
            finally:
                ui.DRY_RUN = prev_dry
            self.assertNotIn("/etc/modprobe.d/i915.conf", written_dsts)
            self.assertIn("/etc/modprobe.d/blacklist-nvidia.conf", written_dsts)
            self.assertNotIn("/etc/modprobe.d/rtw88_powersave.conf", written_dsts)
            self.assertIn("/etc/udev/rules.d/50-usb-hid-nosuspend.rules", written_dsts)

            phases_us = system.build_install_phases(hw_xe, regdom="US")
            self.assertIn("sof-firmware", phases_us["Graphics Drivers & Audio"])
            self.assertIn("thermald", phases_us["Graphics Drivers & Audio"])
            self.assertIn("xdg-desktop-portal-kde", phases_us["Desktop Environment (KDE Plasma) & Fonts"])
            self.assertIn("terminus-font", phases_us["Desktop Environment (KDE Plasma) & Fonts"])
            self.assertIn(
                "tesseract-data-eng",
                phases_us["Terminal, Shell, Core Utilities & Development"],
            )
            self.assertNotIn(
                "tesseract-data-ind",
                phases_us["Terminal, Shell, Core Utilities & Development"],
            )

            # 3) QEMU/KVM Virtual Machine: rejected unless allow_vm=True
            cpu_vm = base / "cpu_vm"
            cpu_vm.write_text("vendor_id\t: GenuineIntel\nflags\t\t: fpu hypervisor\n", encoding="utf-8")
            dmi_vm = base / "dmi_vm"
            dmi_vm.mkdir()
            (dmi_vm / "sys_vendor").write_text("QEMU\n", encoding="utf-8")
            pci_vm = base / "pci_vm"
            (pci_vm / "0000:00:01.0").mkdir(parents=True)
            (pci_vm / "0000:00:01.0/class").write_text("0x030000\n", encoding="utf-8")
            (pci_vm / "0000:00:01.0/vendor").write_text("0x1af4\n", encoding="utf-8")

            hw_vm = hardware.detect(
                proc_cpuinfo=cpu_vm,
                pci_dir=pci_vm,
                dmi_dir=dmi_vm,
                modules_dir=base / "no_mods",
                drm_dir=base / "no_drm",
            )
            self.assertTrue(hw_vm.is_vm)
            with self.assertRaises(ui.ArchsetError):
                hardware.assert_intel_hardware(hw_vm, allow_vm=False)
            hardware.assert_intel_hardware(hw_vm, allow_vm=True)
            self.assertEqual(hw_vm.ucode_packages(), [])
            self.assertEqual(hw_vm.initramfs_modules(), [])
            self.assertIn("MODULES=()", hw_vm.mkinitcpio_dropin())
            self.assertEqual(hw_vm.graphics_packages(), ["mesa"])
            self.assertEqual(hw_vm.console_font(), "default8x16")

    def test_select_mirrors_locks_https_singapore_and_indonesia_only(self) -> None:
        recorded_cmds: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            recorded_cmds.append(list(cmd))
            return ui.Result(" ".join(cmd), 0, "", "")

        prev_dry = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with (
                mock.patch.object(ui, "run", side_effect=fake_run),
                mock.patch.object(shutil, "which", return_value="/usr/bin/reflector"),
                mock.patch.object(system, "_server_count", return_value=5),
            ):
                system.select_mirrors("US")
        finally:
            ui.DRY_RUN = prev_dry

        reflector_calls = [c for c in recorded_cmds if c and c[0] == "reflector"]
        self.assertEqual(len(reflector_calls), 1)
        cmd = reflector_calls[0]
        self.assertIn("Singapore", cmd)
        self.assertIn("Indonesia", cmd)
        self.assertNotIn("Japan", cmd)
        self.assertIn("https", cmd)

    def test_run_with_retry_and_streaming_capture_and_luks_colon_password(self) -> None:
        # 1) Streaming subprocess captures real stdout & stderr lines
        res = ui.run(
            [sys.executable, "-c", "import sys; print('hello-out'); print('hello-err', file=sys.stderr)"],
            readonly=True,
            stream_label="Testing stream",
        )
        self.assertIn("hello-out", res.stdout)
        self.assertIn("hello-err", res.stderr)

        # 2) run_with_retry retries transient CommandError then succeeds
        attempts = 0

        def flaky(*_a, **_kw):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ui.CommandError("pacman -S", 1, "mirror timeout")
            return ui.Result("pacman -S", 0, "ok", "")

        with mock.patch.object(ui, "run", side_effect=flaky):
            out = ui.run_with_retry(["pacman", "-S", "neovim"], attempts=3, delay_sec=0.0)
        self.assertEqual(out.stdout, "ok")
        self.assertEqual(attempts, 3)

        # 3) ask_password allows ':' for LUKS passphrase when allow_colon=True
        with mock.patch("getpass.getpass", side_effect=["Vault:Key:2026!", "Vault:Key:2026!"]):
            pw = ui.ask_password("LUKS2 passphrase", allow_colon=True)
        self.assertEqual(pw, "Vault:Key:2026!")
        ui.log.clear_secrets()

    def test_setup_snapper_mounts_root_and_home_snapshots_with_wheel_group(self) -> None:
        chroot_cmds: list[list[str]] = []
        host_cmds: list[list[str]] = []

        prev_dry = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with (
                mock.patch.object(
                    system,
                    "chroot",
                    side_effect=lambda cmd, **_kw: (chroot_cmds.append(list(cmd)) or ui.Result("", 0, "", "")),
                ),
                mock.patch.object(
                    ui,
                    "run",
                    side_effect=lambda cmd, **_kw: (host_cmds.append(list(cmd)) or ui.Result("", 0, "", "")),
                ),
                mock.patch.object(ui, "patch_file"),
                mock.patch.object(ui, "mkdir"),
            ):
                system.setup_snapper()
        finally:
            ui.DRY_RUN = prev_dry

        self.assertTrue(
            any("subvol=@home_snapshots" in " ".join(c) for c in host_cmds),
            "Expected @home_snapshots mount in setup_snapper()",
        )
        self.assertIn(
            ["chown", "root:wheel", "/.snapshots", "/home/.snapshots"],
            chroot_cmds,
        )

    def test_crypto_wipe_efibootmgr_cleanup_and_export_backup_bundle(self) -> None:
        import tarfile
        from src import maintenance

        # 1) disk.wipe() destroys LUKS2 keyslots with cryptsetup erase + blkdiscard + flushbufs
        wipe_cmds: list[list[str]] = []

        def fake_wipe_run(cmd, **_kw):
            c = list(cmd)
            wipe_cmds.append(c)
            if c[:2] == ["cryptsetup", "isLuks"]:
                rc = 0 if c[-1].endswith("p2") else 1
                return ui.Result(" ".join(c), rc, "", "")
            return ui.Result(" ".join(c), 0, "", "")

        prev_dry = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with (
                mock.patch.object(disk, "partitions", return_value=["/dev/nvme0n1p1", "/dev/nvme0n1p2"]),
                mock.patch.object(ui, "run", side_effect=fake_wipe_run),
            ):
                disk.wipe("/dev/nvme0n1")
        finally:
            ui.DRY_RUN = prev_dry

        flat_wipe = [" ".join(c) for c in wipe_cmds]
        self.assertIn("cryptsetup erase --batch-mode /dev/nvme0n1p2", flat_wipe)
        self.assertNotIn("cryptsetup erase --batch-mode /dev/nvme0n1p1", flat_wipe)
        self.assertIn("blkdiscard -f /dev/nvme0n1", flat_wipe)
        self.assertIn("blockdev --flushbufs /dev/nvme0n1", flat_wipe)

        # 2) efibootmgr parser & cleanup removes only Linux Boot Manager / Arch Linux entries
        sample_efi = (
            "BootCurrent: 0003\n"
            "Timeout: 1 seconds\n"
            "BootOrder: 0001,0003,0000\n"
            "Boot0000* Windows Boot Manager\tHD(1,GPT,aaa)/File(\\EFI\\Microsoft\\Boot\\bootmgfw.efi)\n"
            "Boot0001* Linux Boot Manager\tHD(1,GPT,bbb)/File(\\EFI\\systemd\\systemd-bootx64.efi)\n"
            "Boot0003* UEFI: SanDisk USB\tPciRoot(0x0)/USB(1,0)\n"
        )
        entries = maintenance.parse_efibootmgr_entries(sample_efi)
        self.assertEqual(entries, [("0001", "Linux Boot Manager")])

        efi_cmds: list[list[str]] = []

        def fake_efi_run(cmd, **_kw):
            c = list(cmd)
            efi_cmds.append(c)
            if c == ["efibootmgr"]:
                return ui.Result("efibootmgr", 0, sample_efi, "")
            return ui.Result(" ".join(c), 0, "", "")

        prev_dry = ui.DRY_RUN
        ui.DRY_RUN = True
        try:
            with mock.patch.object(ui, "run", side_effect=fake_efi_run):
                removed = maintenance.cleanup_efi_boot_entries(interactive=False)
        finally:
            ui.DRY_RUN = prev_dry
        self.assertEqual(removed, 1)
        self.assertIn(["efibootmgr", "-b", "0001", "-B"], efi_cmds)

        # 3) export_backup creates 0600 tar.gz with archrelius.conf, WireGuard profiles & pkglist
        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp) / "sysroot"
            out_dir = Path(tmp) / "out"
            (fake_root / "etc/wireguard/profiles").mkdir(parents=True)
            (fake_root / "var/lib/importwgp").mkdir(parents=True)
            (fake_root / "etc/archrelius.conf").write_text("accent_color = #64beaf\n", encoding="utf-8")
            (fake_root / "etc/wireguard/profiles/sg1.conf").write_text("[Interface]\n", encoding="utf-8")
            (fake_root / "var/lib/importwgp/index.tsv").write_text("sg1\tSG#1\n", encoding="utf-8")

            with mock.patch.object(
                ui,
                "run",
                return_value=ui.Result("pacman -Qqe", 0, "base\nlinux\nneovim\n", ""),
            ):
                bundle = maintenance.export_backup(
                    dest_dir=out_dir,
                    root_dir=fake_root,
                    hostname="intelbox",
                )

            self.assertTrue(bundle.is_file())
            self.assertEqual(oct(bundle.stat().st_mode & 0o777), "0o600")
            with tarfile.open(bundle, "r:gz") as tar:
                names = set(tar.getnames())
            self.assertIn("etc/archrelius.conf", names)
            self.assertIn("etc/wireguard/profiles/sg1.conf", names)
            self.assertIn("var/lib/importwgp/index.tsv", names)
            self.assertIn("pkglist-explicit.txt", names)

    def test_group_selection_parser_and_pacman_download_table(self) -> None:
        self.assertEqual(additional.parse_group_selection("none", 5), [])
        self.assertEqual(additional.parse_group_selection("", 5), [])
        self.assertEqual(additional.parse_group_selection("all", 5), [0, 1, 2, 3, 4])
        self.assertEqual(additional.parse_group_selection("1, 3-4", 5), [0, 2, 3])
        self.assertIsNone(additional.parse_group_selection("0,9", 5))
        self.assertIsNone(additional.parse_group_selection("invalid", 5))

        sample_si = """\
Repository      : extra
Name            : firefox
Version         : 136.0-1
Download Size   : 72.50 MiB
Installed Size  : 245.00 MiB

Repository      : extra
Name            : keepassxc
Version         : 2.7.9-2
Download Size   : 9728.00 KiB
Installed Size  : 36.00 MiB
"""
        parsed = additional.parse_pacman_si(sample_si)
        self.assertAlmostEqual(float(parsed["firefox"]["download_mib"]), 72.5, places=1)
        self.assertAlmostEqual(float(parsed["keepassxc"]["download_mib"]), 9.5, places=1)

        rows = [
            {
                "name": "firefox",
                "repo": "extra",
                "version": "136.0-1",
                "download_mib": 72.5,
                "installed_mib": 245.0,
                "installed": False,
            },
            {
                "name": "keepassxc",
                "repo": "extra",
                "version": "2.7.9-2",
                "download_mib": 9.5,
                "installed_mib": 36.0,
                "installed": True,
            },
        ]
        new_cnt, total_dl, total_inst = ui.render_download_plan(rows)
        self.assertEqual(new_cnt, 1)
        self.assertAlmostEqual(total_dl, 72.5, places=1)
        self.assertAlmostEqual(total_inst, 245.0, places=1)


if __name__ == "__main__":
    unittest.main()
