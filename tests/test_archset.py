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

import additional  # noqa: E402
import archset  # noqa: E402
import configs  # noqa: E402
import disk  # noqa: E402
import system  # noqa: E402
import ui  # noqa: E402


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

        sysctl_conf = configs.load_file("etc/sysctl.d/99-knsfd.conf")
        self.assertIn("vm.swappiness                                                           = 100", sysctl_conf)
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
                "etc/nftables.conf",
                "etc/sysctl.d/99-knsfd.conf",
                "etc/sudoers.d/20-umask",
                "etc/audit/rules.d/30-archset.rules",
                "etc/security/limits.d/10-coredump.conf",
                "etc/modprobe.d/blacklist-unused.conf",
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
                    f"--tty={os.ttyname(slave_fd)}",
                    f"--ask-dir={ask_dir}",
                ],
                env=env,
            )
            try:
                self.assertEqual(notify_sock.recv(64), b"READY=1\n")
                # Read initial 160x50 TUI frame (box_col = (160-50)//2 + 1 = 56)
                rendered = bytearray()
                deadline = time.time() + 1.0
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        rendered.extend(os.read(master_fd, 8192))
                        if "┌─ Enter passphrase for /dev/nvme0n1p2: " in rendered.decode(
                            "utf-8", "replace"
                        ):
                            break
                text_ui = rendered.decode("utf-8", "replace")
                self.assertIn("┌─ Enter passphrase for /dev/nvme0n1p2: ─────────┐", text_ui)
                self.assertIn("\x1b[27;56H┌─", text_ui)

                # Simulate i915drmfb deferred takeover switching console to 170x48 without keypress
                fcntl.ioctl(
                    slave_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 48, 170, 1366, 768),
                )
                resized_out = bytearray()
                deadline = time.time() + 1.0
                expected_resized = "\x1b[26;61H┌─ Enter passphrase for /dev/nvme0n1p2: ─────────┐"
                while time.time() < deadline:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if r:
                        resized_out.extend(os.read(master_fd, 8192))
                        if expected_resized in resized_out.decode("utf-8", "replace"):
                            break
                self.assertIn(expected_resized, resized_out.decode("utf-8", "replace"))

                # Send passphrase with Backspace + Arrow-Left escape sequence
                os.write(master_fd, b"SecrX\x7f\x1b[Det#99\n")
                reply = recv_sock.recv(256)
                self.assertEqual(reply, b"+Secret#99")
                self.assertEqual(proc.wait(timeout=3), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
                os.close(master_fd)
                os.close(slave_fd)
                recv_sock.close()
                notify_sock.close()


if __name__ == "__main__":
    unittest.main()
