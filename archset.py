#!/usr/bin/env python3
"""archset - opinionated Arch Linux installer.

Target layout:

    ESP 1 GiB (vfat) -> /boot
    LUKS2 -> btrfs with @, @home, @log, @pkg, @swap
    systemd-boot + unified kernel image
    KDE Plasma on Wayland, zsh + starship + kitty

Run from the Arch ISO as root:

    python archset.py

Use --dry-run to log the full command sequence without changing anything.
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
from dataclasses import dataclass
from pathlib import Path

import disk
import system
import ui

TOTAL_STEPS = 12
DEFAULT_TIMEZONE = "Asia/Jakarta"
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
    luks_passphrase: str


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="archset",
        description="Opinionated Arch Linux installer (LUKS2 + btrfs + KDE Plasma).",
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
        default=DEFAULT_TIMEZONE,
        help=f"system timezone (default: {DEFAULT_TIMEZONE})",
    )
    parser.add_argument(
        "--log-dir",
        default=ui.LOG_DIR,
        help=f"directory for the installation log (default: {ui.LOG_DIR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log every command without executing it",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow running outside the Arch ISO (dangerous)",
    )
    parser.add_argument("--version", action="version", version=f"archset {ui.VERSION}")
    return parser.parse_args(argv)


def _hostname_validator(value: str) -> tuple[bool, str]:
    if len(value) > 63:
        return False, "hostname must be 63 characters or fewer"
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
        return False, "use letters, digits and hyphens; do not start or end with a hyphen"
    if value.lower() == "localhost":
        return False, "hostname cannot be 'localhost'"
    return True, ""


def _username_validator(value: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        return False, "use lowercase letters, digits, underscore or hyphen (max 32)"
    if value in ("root", "nobody"):
        return False, "that username is reserved"
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
        raise ui.ArchsetError("UEFI firmware is required; legacy BIOS is not supported.")
    if not Path("/sys/firmware/efi/efivars").exists():
        raise ui.ArchsetError("EFI variables are not available; boot the ISO in UEFI mode.")

    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise ui.ArchsetError(
            "Missing required tools: " + ", ".join(missing) + ". Run archset from the Arch ISO."
        )

    if os.path.ismount("/mnt"):
        raise ui.ArchsetError("/mnt is already mounted. Unmount it before running archset.")

    if not Path("/run/archiso").exists():
        if not args.force:
            raise ui.ArchsetError(
                "archset is not running from the Arch ISO. Use --force only if you are certain."
            )
        ui.warn("Running outside the Arch ISO because --force was supplied.")

    # Ensure accurate clock before HTTPS/TLS checks and pacman GPG verification.
    ui.run(["timedatectl", "set-ntp", "true"], check=False)

    check_network()
    system.select_mirrors()
    ui.ok("Preflight checks passed")


def collect_inputs(args: argparse.Namespace) -> Inputs:
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

    print()
    ui.info(f"The root password will also be used for user '{username}'.")
    root_password = ui.ask_password("root password")
    luks_passphrase = ui.ask_password("LUKS passphrase")

    return Inputs(
        hostname=hostname,
        username=username,
        root_password=root_password,
        luks_passphrase=luks_passphrase,
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


def confirm_destruction(info: disk.DiskInfo) -> None:
    ui.hr("=")
    ui.warn("DESTRUCTIVE OPERATION: ALL DATA ON THE TARGET DISK WILL BE LOST")
    ui.hr("=")
    print(f"  Device : {info.path}")
    print(f"  Model  : {info.model or 'unknown'}")
    print(f"  Serial : {info.serial or 'unknown'}")
    print(f"  Size   : {ui.format_bytes(info.size)}")
    print()
    print("  The disk will be repartitioned, encrypted with LUKS2 and formatted.")
    print("  There is no undo.")
    ui.hr("=")

    if not ui.confirm_typed("erase the target disk", f"WIPE {info.path}"):
        raise ui.ArchsetError("Destructive operation was not confirmed. Aborting.")

    if not ui.confirm("Begin the installation now? This cannot be undone.", default=False):
        raise ui.ArchsetError("Installation cancelled by the user.")


def install(inputs: Inputs, info: disk.DiskInfo, args: argparse.Namespace) -> None:
    global _storage_started
    target = info.path
    esp = disk.part_path(target, 1)
    root_part = disk.part_path(target, 2)
    mapper = f"/dev/mapper/{disk.LUKS_NAME}"

    ui.step(5, TOTAL_STEPS, f"Wiping and partitioning {target}")
    _storage_started = True
    disk.wipe(target)
    disk.partition(target)
    disk.mkfs_esp(esp)

    ui.step(6, TOTAL_STEPS, "Creating the LUKS2 container and btrfs filesystem")
    disk.luks_format(root_part, inputs.luks_passphrase)
    disk.luks_open(root_part, disk.LUKS_NAME, inputs.luks_passphrase)
    disk.mkfs_btrfs(mapper)
    disk.create_subvolumes(mapper)

    ui.step(7, TOTAL_STEPS, "Mounting filesystems and creating swap")
    disk.mount_all(mapper)
    disk.mount_esp(esp)
    disk.make_swapfile()

    ui.step(8, TOTAL_STEPS, "Installing the base system")
    system.install_base()
    disk.write_fstab()
    system.copy_mirrorlist()
    system.configure_pacman()

    ui.step(9, TOTAL_STEPS, "Installing KDE Plasma and user packages")
    system.install_groups()

    ui.step(10, TOTAL_STEPS, "Configuring locale, users, snapper and services")
    system.configure_locale(inputs.hostname, args.timezone)
    system.create_user(inputs.username, inputs.root_password)
    system.setup_zram()
    system.setup_snapper()
    system.enable_services()

    ui.step(11, TOTAL_STEPS, "Applying system configs, systemd-boot and building the UKI")
    system.inject_system_configs()
    root_partuuid = "DRY-RUN-PARTUUID" if ui.DRY_RUN else disk.partuuid(root_part)
    system.setup_bootloader(root_partuuid)

    ui.step(12, TOTAL_STEPS, "Applying user configuration and finalizing")
    system.inject_user_configs(inputs.username, inputs.hostname)
    system.verify(inputs.username)
    system.copy_log(ui.log.path)
    disk.unmount_all()

    ui.ok("Installation finished successfully")
    ui.info(f"Installation log: {ui.log.path}")
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        ui.init(args.log_dir)
    except OSError as exc:
        print(
            f"archset: cannot create the log file in {args.log_dir}: {exc}",
            file=sys.stderr,
        )
        return 1
    ui.DRY_RUN = args.dry_run
    ui.banner()

    if args.dry_run:
        ui.warn("Dry run enabled: no command will be executed.")

    try:
        ui.step(1, TOTAL_STEPS, "Running preflight checks")
        preflight(args)

        ui.step(2, TOTAL_STEPS, "Collecting installation settings")
        inputs = collect_inputs(args)

        ui.step(3, TOTAL_STEPS, "Selecting the target disk")
        info = select_disk(args)

        ui.step(4, TOTAL_STEPS, "Confirming the destructive operation")
        confirm_destruction(info)

        install(inputs, info, args)
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
        ui.log.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
