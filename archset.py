#!/usr/bin/env python3
"""archset - opinionated, hardened Arch Linux installer (stdlib only).

Target layout:

    ESP 1 GiB (vfat) -> /boot (fmask=0177,dmask=0077,nodev,nosuid,noexec)
    LUKS2 (argon2id, passphrase-only, no TPM2, no Secure Boot) -> btrfs
    Subvolumes: @, @home, @log, @pkg, @snapshots, @swap
    systemd-boot + UKI (mkinitcpio drop-in: systemd + sd-encrypt)
    IPv6 permanently disabled, dnscrypt-proxy + systemd-resolved + nftables
    KDE Plasma (Wayland, BreezeDarkMod), kitty, zsh + starship + fzf-tab, nvim

Run from the Arch ISO as root:

    python3 archset.py --dry-run
    python3 archset.py

Install optional additional applications later on an installed system:

    sudo python3 archset.py --additional
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import additional
import disk
import hardware
import system
import ui

TOTAL_STEPS = 12
DEFAULT_TIMEZONE = "Asia/Jakarta"
DEFAULT_REGDOM = "ID"
_storage_started = False

REQUIRED_TOOLS = [
    "arch-chroot",
    "blkid",
    "cryptsetup",
    "findmnt",
    "genfstab",
    "lsblk",
    "mkfs.btrfs",
    "mkfs.fat",
    "pacman",
    "pacstrap",
    "partprobe",
    "sgdisk",
    "udevadm",
    "wipefs",
]


@dataclass
class Inputs:
    hostname: str
    username: str
    root_password: str
    user_password: str
    luks_passphrase: str
    additional_packages: list[str] = field(default_factory=list)
    timezone: str = DEFAULT_TIMEZONE
    regdom: str = DEFAULT_REGDOM


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="archset",
        description=(
            "Opinionated Arch Linux installer (LUKS2 sd-encrypt + UKI + btrfs + KDE Plasma)."
        ),
    )
    parser.add_argument(
        "--additional",
        action="store_true",
        help="non-destructive mode: interactively install optional additional applications on an existing system",
    )
    parser.add_argument(
        "--appditional",
        dest="additional",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="auto-confirm all groups in --additional mode (never bypasses disk wipe confirmation)",
    )
    parser.add_argument(
        "--disk",
        metavar="DEVICE",
        help="target block device, for example /dev/nvme0n1",
    )
    parser.add_argument("--hostname", help="hostname (prompted when omitted)")
    parser.add_argument("--username", help="primary user (prompted when omitted)")
    parser.add_argument(
        "--timezone",
        default=None,
        help=f"system timezone (prompted when omitted; default: {DEFAULT_TIMEZONE})",
    )
    parser.add_argument(
        "--regdom",
        default=None,
        help=f"2-letter ISO Wi-Fi regulatory domain (prompted when omitted; default: {DEFAULT_REGDOM})",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help=f"directory for the raw installation log (default: {ui.LOG_DIR})",
    )
    parser.add_argument(
        "--lock-file",
        default=None,
        help=f"single-instance lock file path (default: {ui.DEFAULT_LOCK_PATH})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log every command without executing modifying operations",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow full install outside the Arch ISO (dangerous)",
    )
    parser.add_argument("--version", action="version", version=f"archset {ui.VERSION}")
    return parser.parse_args(argv)


def _hostname_validator(value: str) -> tuple[bool, str]:
    if len(value) > 63:
        return False, "hostname must be 63 characters or fewer"
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
        return (
            False,
            "use letters, digits and hyphens; do not start or end with a hyphen",
        )
    if value.lower() == "localhost":
        return False, "hostname cannot be 'localhost'"
    return True, ""


def _username_validator(value: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        return False, "use lowercase letters, digits, underscore or hyphen (max 32)"
    if value in ("root", "nobody"):
        return False, "that username is reserved"
    return True, ""


def _timezone_validator(value: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[A-Za-z0-9_+./-]+", value) or ".." in value:
        return False, "invalid timezone format (example: Asia/Jakarta or UTC)"
    zoneinfo = Path("/usr/share/zoneinfo")
    if zoneinfo.is_dir() and not (zoneinfo / value).is_file():
        return False, f"timezone '{value}' not found under /usr/share/zoneinfo"
    return True, ""


def _regdom_validator(value: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[A-Za-z]{2}|00", value.strip()):
        return False, "enter a 2-letter ISO country code (e.g. ID, US, SG, JP) or 00"
    return True, ""


def check_network() -> None:
    url = "https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            response.read(1)
    except (urllib.error.URLError, OSError) as exc:
        raise ui.ArchsetError(
            "No internet access. Connect to the network and run archset again."
        ) from exc


def preflight(args: argparse.Namespace) -> None:
    if os.geteuid() != 0:
        raise ui.ArchsetError("archset must be run as root.")
    if not Path("/sys/firmware/efi").exists():
        raise ui.ArchsetError(
            "UEFI firmware is required; legacy BIOS is not supported."
        )
    if not Path("/sys/firmware/efi/efivars").exists():
        raise ui.ArchsetError(
            "EFI variables are not available; boot the ISO in UEFI mode."
        )

    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise ui.ArchsetError(
            "Missing required tools: "
            + ", ".join(missing)
            + ". Run archset from the Arch ISO."
        )

    if os.path.ismount("/mnt"):
        raise ui.ArchsetError(
            "/mnt is already mounted. Unmount it before running archset."
        )
    disk.assert_no_active_luks()

    if not Path("/run/archiso").exists():
        if not args.force:
            raise ui.ArchsetError(
                "archset is not running from the Arch ISO. Use --force only if you are certain, "
                "or run --additional for non-destructive package installation."
            )
        ui.warn("Running outside the Arch ISO because --force was supplied.")

    ui.run(["timedatectl", "set-ntp", "true"], check=False)

    check_network()
    system.select_mirrors(args.regdom or DEFAULT_REGDOM)
    system.refresh_iso_keyring()
    ui.ok("Preflight checks passed")


def collect_inputs(
    args: argparse.Namespace,
    hw: hardware.HardwareProfile | None = None,
) -> Inputs:
    profile = hw or hardware.detect()
    ui.info(f"Detected hardware profile: {profile.summary()}")

    if args.hostname:
        ok, message = _hostname_validator(args.hostname)
        if not ok:
            raise ui.ArchsetError(f"Invalid hostname: {message}")
        hostname = args.hostname
    else:
        hostname = ui.ask(
            "Hostname",
            default="archlinux",
            validator=_hostname_validator,
        )

    if args.username:
        ok, message = _username_validator(args.username)
        if not ok:
            raise ui.ArchsetError(f"Invalid username: {message}")
        username = args.username
    else:
        username = ui.ask("Username", validator=_username_validator)

    if args.timezone:
        ok, message = _timezone_validator(args.timezone)
        if not ok:
            raise ui.ArchsetError(f"Invalid timezone: {message}")
        timezone = args.timezone
    else:
        timezone = ui.ask(
            "Timezone",
            default=DEFAULT_TIMEZONE,
            validator=_timezone_validator,
        )

    if args.regdom:
        ok, message = _regdom_validator(args.regdom)
        if not ok:
            raise ui.ArchsetError(f"Invalid regdom: {message}")
        regdom = args.regdom.upper()
    else:
        regdom = ui.ask(
            "Wi-Fi regulatory domain (ISO 2-letter)",
            default=DEFAULT_REGDOM,
            validator=_regdom_validator,
        ).upper()

    print()
    ui.info("Set separate passwords for root, primary user, and LUKS2 encryption.")
    root_password = ui.ask_password("root password")
    user_password = ui.ask_password(f"user '{username}' password")
    luks_passphrase = ui.ask_password("LUKS2 passphrase (no TPM2)")

    additional_packages = additional.prompt_additional_selection(
        interactive=True, hw=profile
    )

    return Inputs(
        hostname=hostname,
        username=username,
        root_password=root_password,
        user_password=user_password,
        luks_passphrase=luks_passphrase,
        additional_packages=additional_packages,
        timezone=timezone,
        regdom=regdom,
    )


def select_disk(args: argparse.Namespace) -> disk.DiskInfo:
    disks = disk.list_disks(include_loop=bool(args.disk))
    if not disks:
        raise ui.ArchsetError("No usable block devices were found.")

    if args.disk:
        info = next((item for item in disks if item.path == args.disk), None)
        if info is None:
            raise ui.ArchsetError(f"{args.disk} is not a detected block device.")
    else:
        live = disk.live_disks()
        candidates = [
            item
            for item in disks
            if item.size >= disk.MIN_DISK_BYTES and item.path not in live
        ]
        if not candidates:
            raise ui.ArchsetError("No disk with at least 20 GiB is available.")
        labels = []
        for item in candidates:
            note = " [mounted]" if disk.is_mounted(item.path) else ""
            labels.append(
                f"{item.path:<14} {ui.format_bytes(item.size):>9}  "
                f"{item.model or item.name}  [{item.tran or 'unknown'}]{note}"
            )
        index = ui.menu("Select the disk to erase and install Arch Linux on", labels)
        info = candidates[index]

    disk.assert_safe_target(info.path)
    ui.ok(f"Target disk: {info.path} ({ui.format_bytes(info.size)})")
    return info


def confirm_destruction(info: disk.DiskInfo, inputs: Inputs) -> None:
    ui.hr("=")
    ui.warn("DESTRUCTIVE OPERATION: ALL DATA ON THE TARGET DISK WILL BE LOST")
    ui.hr("=")
    print(f"  Device     : {info.path}")
    print(f"  Model      : {info.model or 'unknown'}")
    print(f"  Serial     : {info.serial or 'unknown'}")
    print(f"  Size       : {ui.format_bytes(info.size)}")
    print(f"  Hostname   : {inputs.hostname}")
    print(f"  Username   : {inputs.username}")
    print(f"  Region     : {inputs.timezone} (Wi-Fi regdom: {inputs.regdom})")
    print("  Boot Stack : UEFI + systemd-boot + UKI (sd-encrypt + ARCHRELIUS TUI, no TPM2)")
    print("  Network    : IPv6 disabled + dnscrypt-proxy + nftables")
    print(f"  Additional : {len(inputs.additional_packages)} optional package(s)")
    print()
    print("  The disk will be repartitioned, encrypted with LUKS2 and formatted.")
    print("  There is no undo.")
    ui.hr("=")

    if not ui.confirm_typed("erase the target disk", f"WIPE {info.path}"):
        raise ui.ArchsetError("Destructive operation was not confirmed. Aborting.")

    if not ui.confirm(
        "Begin the installation now? This cannot be undone.", default=False
    ):
        raise ui.ArchsetError("Installation cancelled by the user.")


def install(
    inputs: Inputs,
    info: disk.DiskInfo,
    args: argparse.Namespace,
    *,
    hw: hardware.HardwareProfile | None = None,
) -> None:
    global _storage_started
    profile = hw or hardware.detect()
    target = info.path
    esp = disk.part_path(target, 1)
    root_part = disk.part_path(target, 2)
    mapper = f"/dev/mapper/{disk.LUKS_NAME}"
    enable_multilib = additional.needs_multilib(inputs.additional_packages)
    tz = args.timezone or inputs.timezone or DEFAULT_TIMEZONE
    regdom = (args.regdom or inputs.regdom or DEFAULT_REGDOM).upper()

    ui.step(5, TOTAL_STEPS, f"Wiping and partitioning {target}")
    _storage_started = True
    disk.wipe(target)
    disk.partition(target)
    disk.mkfs_esp(esp)

    ui.step(6, TOTAL_STEPS, "Creating LUKS2 container (argon2id) and btrfs subvolumes")
    disk.luks_format(root_part, inputs.luks_passphrase)
    disk.luks_open(root_part, disk.LUKS_NAME, inputs.luks_passphrase)
    disk.mkfs_btrfs(mapper)
    disk.create_subvolumes(mapper)

    ui.step(7, TOTAL_STEPS, "Mounting filesystems and creating swapfile")
    disk.mount_all(mapper)
    disk.mount_esp(esp)
    disk.make_swapfile()

    ui.step(8, TOTAL_STEPS, "Installing base stack and patching pacman.conf")
    system.install_base(profile)
    disk.write_fstab()
    system.copy_mirrorlist()
    system.configure_pacman(enable_multilib=enable_multilib)

    ui.step(9, TOTAL_STEPS, "Installing phased system, desktop, dev and optional packages")
    system.install_phases(inputs.additional_packages, hw=profile, regdom=regdom)

    ui.step(10, TOTAL_STEPS, "Configuring locale, users, snapper, configs and services")
    system.configure_locale(inputs.hostname, tz)
    system.create_user(inputs.username, inputs.user_password, inputs.root_password)
    system.setup_snapper()
    system.inject_system_configs(profile, regdom=regdom)
    system.enable_services()

    ui.step(11, TOTAL_STEPS, "Configuring systemd-boot and building sd-encrypt UKI")
    root_luks_uuid = (
        "00000000-0000-0000-0000-000000000000"
        if ui.DRY_RUN
        else disk.luks_uuid(root_part)
    )
    system.setup_bootloader(root_luks_uuid, profile)

    ui.step(12, TOTAL_STEPS, "Applying user dotfiles, finalizing DNS and exporting logs")
    system.inject_user_configs(inputs.username, inputs.hostname)
    system.finalize_dns_symlink()
    system.verify(inputs.username)
    system.export_logs(ui.log.path, inputs.username)
    disk.unmount_all()

    ui.ok("Installation finished successfully")
    ui.info(f"Raw setup log exported to /home/{inputs.username}/archset/setup.log")
    if not inputs.additional_packages:
        ui.info(
            "Tip: install additional apps anytime after reboot with: "
            "sudo python3 archset.py --additional"
        )
    print()
    print("Remove the installation media and reboot into the new system.")


def cleanup() -> None:
    if not _storage_started:
        ui.debug("cleanup skipped; storage was not modified")
        return
    ui.info("Cleaning up mounts and the device mapper")
    try:
        disk.unmount_all()
    except Exception as exc:  # noqa: BLE001 - cleanup must never mask the real error
        ui.log.debug(f"cleanup failed: {exc}")


def _resolve_runtime_paths(args: argparse.Namespace) -> tuple[str, str]:
    is_root = os.geteuid() == 0
    if args.log_dir:
        log_dir = args.log_dir
    elif is_root:
        log_dir = ui.LOG_DIR
    else:
        log_dir = f"/tmp/archset-{os.getuid()}-logs"

    if args.lock_file:
        lock_file = args.lock_file
    elif is_root:
        lock_file = ui.DEFAULT_LOCK_PATH
    else:
        lock_file = f"/tmp/archset-{os.getuid()}.lock"

    return log_dir, lock_file


def main(argv: list[str] | None = None) -> int:
    global _storage_started
    _storage_started = False
    args = parse_args(argv)
    log_dir, lock_file = _resolve_runtime_paths(args)

    try:
        lock = ui.InstanceLock(lock_file)
        lock.acquire()
    except (ui.ArchsetError, OSError) as exc:
        print(f"archset: {exc}", file=sys.stderr)
        return 1

    try:
        try:
            ui.init(log_dir)
        except OSError as exc:
            print(
                f"archset: cannot create the log file in {log_dir}: {exc}",
                file=sys.stderr,
            )
            return 1

        ui.DRY_RUN = args.dry_run
        ui.banner()

        if args.dry_run:
            ui.warn("Dry run enabled: no modifying command will be executed.")

        try:
            # Strict non-destructive branch: never touches disk.py or /run/archiso
            if args.additional:
                return additional.run_standalone(
                    username=args.username,
                    log_path=ui.log.path,
                    assume_yes=args.yes,
                )

            hw = hardware.detect()

            ui.step(1, TOTAL_STEPS, "Running preflight checks")
            preflight(args)

            ui.step(2, TOTAL_STEPS, "Collecting installation settings")
            inputs = collect_inputs(args, hw)

            ui.step(3, TOTAL_STEPS, "Selecting the target disk")
            info = select_disk(args)

            ui.step(4, TOTAL_STEPS, "Confirming the destructive operation")
            confirm_destruction(info, inputs)

            install(inputs, info, args, hw=hw)
        except KeyboardInterrupt:
            ui.error("Installation interrupted by the user.")
            cleanup()
            return 130
        except ui.ArchsetError as exc:
            ui.error(str(exc))
            if ui.log.path is not None:
                ui.error(f"Full log: {ui.log.path}")
            cleanup()
            return 1
        except Exception as exc:  # noqa: BLE001 - last-resort handler for a clean log
            ui.error(f"Unexpected error: {exc}")
            ui.log.debug(traceback.format_exc())
            if ui.log.path is not None:
                ui.error(f"Full log: {ui.log.path}")
            cleanup()
            return 1
        finally:
            ui.log.clear_secrets()
            ui.log.close()
    finally:
        lock.release()

    return 0


if __name__ == "__main__":
    sys.exit(main())
