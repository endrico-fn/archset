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
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from src import additional, configs, disk, hardware, maintenance, system, ui

TOTAL_STEPS = 12
DEFAULT_TIMEZONE = configs.DEFAULT_TIMEZONE
DEFAULT_REGDOM = configs.DEFAULT_REGDOM
_storage_started = False

REQUIRED_TOOLS = [
    "arch-chroot",
    "blkdiscard",
    "blkid",
    "blockdev",
    "btrfs",
    "cryptsetup",
    "efibootmgr",
    "findmnt",
    "genfstab",
    "lsblk",
    "mkfs.btrfs",
    "mkfs.fat",
    "mount",
    "pacman",
    "pacstrap",
    "partprobe",
    "sgdisk",
    "swapoff",
    "swapon",
    "sync",
    "systemctl",
    "timedatectl",
    "udevadm",
    "umount",
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
        "--uninstall",
        action="store_true",
        help="Live-ISO decommission mode: crypto-erase target disk (LUKS2 + blkdiscard) and clean UEFI NVRAM entries",
    )
    parser.add_argument(
        "--export-backup",
        nargs="?",
        const="",
        default=None,
        metavar="DIR",
        help="non-destructive: export WireGuard profiles, archrelius.conf, and package list into a 0600 tar.gz bundle",
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
    parser.add_argument(
        "--allow-vm",
        action="store_true",
        help="allow running on virtual machine hardware for testing (Intel-only policy override)",
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


def _ping_mirror() -> bool:
    url = "https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            response.read(1)
        return True
    except (urllib.error.URLError, OSError):
        return False


def check_network(*, interactive: bool = False) -> None:
    if _ping_mirror():
        return
    if (
        interactive
        and sys.stdin.isatty()
        and Path("/run/archiso").exists()
        and shutil.which("iwctl") is not None
    ):
        ui.warn("No internet connection detected on the Arch ISO.")
        if ui.confirm("Open interactive iwctl now to connect Wi-Fi?", default=True):
            subprocess.run(["iwctl"], check=False)
            if _ping_mirror():
                ui.ok("Internet connection established")
                return
    raise ui.ArchsetError(
        "No internet access. Connect to the network (e.g. iwctl) and run archset again."
    )


def preflight(
    args: argparse.Namespace,
    hw: hardware.HardwareProfile | None = None,
) -> None:
    profile = hw or hardware.detect()
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

    hardware.assert_intel_hardware(profile, allow_vm=getattr(args, "allow_vm", False))

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

    check_network(interactive=not args.dry_run)
    ui.ok(f"Preflight & Intel hardware check passed ({profile.summary()})")


def prepare_live_iso() -> None:
    ui.run(["timedatectl", "set-ntp", "true"], check=False)
    system.select_mirrors()
    system.refresh_iso_keyring()
    ui.ok("Live ISO NTP, HTTPS mirrors (Singapore & Indonesia), and keyring ready")


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
    luks_passphrase = ui.ask_password("LUKS2 passphrase (no TPM2)", allow_colon=True)

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
        subtitles = []
        for item in candidates:
            note = " [mounted]" if disk.is_mounted(item.path) else ""
            labels.append(
                f"{item.path:<14} {ui.format_bytes(item.size):>9}  "
                f"{item.model or item.name}  [{item.tran or 'unknown'}]{note}"
            )
            subtitles.append(disk.partition_summary(item.path))
        index = ui.menu(
            "Select Target Disk (ALL DATA ON SELECTED DISK WILL BE WIPED)",
            labels,
            subtitles=subtitles,
        )
        info = candidates[index]

    disk.assert_safe_target(info.path)
    ui.ok(f"Target disk: {info.path} ({ui.format_bytes(info.size)})")
    return info


def review_settings(
    info: disk.DiskInfo,
    inputs: Inputs,
    args: argparse.Namespace,
    hw: hardware.HardwareProfile,
) -> disk.DiskInfo:
    """Interactive `[ 1 ]..[ 6 ]` review & edit loop prior to WIPE confirmation."""
    if not sys.stdin.isatty() or ui.DRY_RUN:
        return info

    while True:
        items = [
            f"Hostname         : {inputs.hostname}",
            f"Username         : {inputs.username}",
            f"Region           : {inputs.timezone} (Wi-Fi regdom: {inputs.regdom})",
            "Credentials      : Configured (separate root, user & LUKS2 passphrases)",
            f"Additional Apps  : {len(inputs.additional_packages)} package(s) selected",
            f"Target Disk      : {info.path} ({ui.format_bytes(info.size)} — {info.model or info.name})",
        ]
        choice = ui.menu(
            "Review Configuration (Select number to edit before wiping)",
            items,
            zero_option="Continue to Disk Wipe Confirmation",
        )
        if choice == -1:
            return info
        if choice == 0:
            inputs.hostname = ui.ask(
                "Hostname", default=inputs.hostname, validator=_hostname_validator
            )
        elif choice == 1:
            inputs.username = ui.ask(
                "Username", default=inputs.username, validator=_username_validator
            )
        elif choice == 2:
            inputs.timezone = ui.ask(
                "Timezone", default=inputs.timezone, validator=_timezone_validator
            )
            inputs.regdom = ui.ask(
                "Wi-Fi regulatory domain (ISO 2-letter)",
                default=inputs.regdom,
                validator=_regdom_validator,
            ).upper()
        elif choice == 3:
            inputs.root_password = ui.ask_password("root password")
            inputs.user_password = ui.ask_password(f"user '{inputs.username}' password")
            inputs.luks_passphrase = ui.ask_password(
                "LUKS2 passphrase (no TPM2)", allow_colon=True
            )
        elif choice == 4:
            inputs.additional_packages = additional.prompt_additional_selection(
                interactive=True, hw=hw
            )
        elif choice == 5:
            disk_args = argparse.Namespace(**vars(args))
            disk_args.disk = None
            info = select_disk(disk_args)


def confirm_destruction(info: disk.DiskInfo, inputs: Inputs) -> None:
    ui.hr("=", 76)
    ui.warn("DESTRUCTIVE OPERATION: ALL DATA ON THE TARGET DISK WILL BE LOST")
    ui.hr("=", 76)
    print(f"  Device     : {info.path}")
    print(f"  Model      : {info.model or 'unknown'}")
    print(f"  Serial     : {info.serial or 'unknown'}")
    print(f"  Size       : {ui.format_bytes(info.size)} (ESP {disk.esp_size_for_disk(info.size)} + LUKS2 Btrfs)")
    print(f"  Hostname   : {inputs.hostname}")
    print(f"  Username   : {inputs.username}")
    print(f"  Region     : {inputs.timezone} (Wi-Fi regdom: {inputs.regdom})")
    print("  Boot Stack : UEFI + systemd-boot + UKI (sd-encrypt + ARCHRELIUS TUI, Intel-only)")
    print("  Mirrors    : HTTPS Singapore & Indonesia (reflector)")
    print("  Network    : IPv6 disabled + dnscrypt-proxy + nftables")
    print(f"  Additional : {len(inputs.additional_packages)} optional package(s)")
    print()
    print("  The disk will be crypto-erased, repartitioned, encrypted with LUKS2 and formatted.")
    print("  There is no undo.")
    ui.hr("=", 76)

    if not ui.confirm_typed("erase the target disk", f"WIPE {info.path}"):
        raise ui.ArchsetError("Destructive operation was not confirmed. Aborting.")

    if not ui.confirm(
        "Begin the installation now? This cannot be undone.", default=False
    ):
        raise ui.ArchsetError("Installation cancelled by the user.")


def enter_arch_chroot() -> None:
    if ui.DRY_RUN:
        ui.log.debug(f"DRY-RUN  arch-chroot /mnt {configs.DEFAULT_SHELL}")
        return
    subprocess.run(["arch-chroot", "/mnt", configs.DEFAULT_SHELL], check=False)


def post_install_action(
    info: disk.DiskInfo,
    inputs: Inputs,
    *,
    interactive: bool | None = None,
) -> str:
    """Present `[ 1 ]..[ 4 ]` post-install menu, keep /mnt live for chroot, then flush SSD."""
    global _storage_started
    use_menu = (sys.stdin.isatty() and not ui.DRY_RUN) if interactive is None else interactive
    action = "stay"

    if use_menu:
        options = [
            "Enter arch-chroot   (inspect /mnt with live DNS; 'exit' returns here)",
            "Stay in Live ISO    (flush SSD, unmount /mnt & close LUKS)",
            "Poweroff System     (flush SSD, unmount /mnt & close LUKS -> systemctl poweroff)",
            "Reboot System       (flush SSD, unmount /mnt & close LUKS -> systemctl reboot)",
        ]
        while True:
            choice = ui.menu(
                "Installation Finished — Select Next Action",
                options,
                default=2,
            )
            if choice == 0:
                ui.info(
                    "Entering interactive arch-chroot /mnt (type 'exit' to return to this menu)"
                )
                enter_arch_chroot()
                continue
            if choice == 1:
                action = "stay"
                break
            if choice == 2:
                action = "poweroff"
                break
            if choice == 3:
                action = "reboot"
                break

    system.finalize_dns_symlink()
    system.export_logs(ui.log.path, inputs.username)
    disk.flush_and_unmount(info.path, strict=True)
    _storage_started = False
    return action


def execute_power_action(action: str, *, dry_run: bool = False) -> None:
    if dry_run or action not in ("poweroff", "reboot"):
        return
    subprocess.run(["systemctl", action], check=False)


def install(
    inputs: Inputs,
    info: disk.DiskInfo,
    args: argparse.Namespace,
    *,
    hw: hardware.HardwareProfile | None = None,
) -> str:
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
    disk.partition(target, esp_size=disk.esp_size_for_disk(info.size))
    disk.mkfs_esp(esp)

    ui.step(6, TOTAL_STEPS, "Creating LUKS2 container (argon2id) and btrfs subvolumes")
    disk.luks_format(root_part, inputs.luks_passphrase)
    disk.luks_open(root_part, disk.LUKS_NAME, inputs.luks_passphrase)
    inputs.luks_passphrase = ""
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
    system.configure_locale(
        inputs.hostname,
        tz,
        console_font=profile.console_font(),
    )
    system.create_user(inputs.username, inputs.user_password, inputs.root_password)
    inputs.user_password = ""
    inputs.root_password = ""
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

    ui.step(12, TOTAL_STEPS, "Applying user dotfiles, verifying system & finalizing SSD")
    system.inject_user_configs(inputs.username, inputs.hostname)
    system.verify(inputs.username)
    ui.ok("Installation verified successfully")
    ui.info(f"Raw setup log destination: /home/{inputs.username}/archset/setup.log")
    if not inputs.additional_packages:
        ui.info(
            "Tip: install additional apps anytime after boot with: "
            "sudo python3 archset.py --additional"
        )

    action = post_install_action(info, inputs)
    if action == "stay":
        print()
        print("Safe to remove installation media or inspect from the Live ISO shell.")
    elif action == "poweroff":
        ui.info("Powering off system now (unplug USB media once powered off)...")
    elif action == "reboot":
        ui.info("Rebooting system now...")
    return action


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

    post_action = "stay"
    prev_dry_run = ui.DRY_RUN
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
            active_modes = sum(
                [
                    bool(args.additional),
                    bool(args.uninstall),
                    args.export_backup is not None,
                ]
            )
            if active_modes > 1:
                raise ui.ArchsetError(
                    "--additional, --uninstall, and --export-backup cannot be combined."
                )

            # Strict non-destructive branches: never touch disk.py
            if args.additional:
                return additional.run_standalone(
                    username=args.username,
                    log_path=ui.log.path,
                    assume_yes=args.yes,
                )

            if args.export_backup is not None:
                dest = args.export_backup if args.export_backup else None
                maintenance.export_backup(dest_dir=dest, username=args.username)
                return 0

            if args.uninstall:
                rc, post_action = maintenance.run_uninstall(
                    args, select_disk_fn=select_disk
                )
                if rc != 0:
                    return rc
            else:
                hw = hardware.detect()

                ui.step(1, TOTAL_STEPS, "Running fast preflight & Intel hardware checks")
                preflight(args, hw)

                ui.step(2, TOTAL_STEPS, "Collecting installation settings, disk & optional apps")
                inputs = collect_inputs(args, hw)
                info = select_disk(args)

                ui.step(3, TOTAL_STEPS, "Reviewing configuration & confirming disk wipe")
                info = review_settings(info, inputs, args, hw)
                confirm_destruction(info, inputs)

                ui.step(4, TOTAL_STEPS, "Preparing live ISO (NTP, SG/ID HTTPS mirrors & keyring)")
                prepare_live_iso()

                post_action = install(inputs, info, args, hw=hw)
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
            ui.DRY_RUN = prev_dry_run
            ui.log.clear_secrets()
            ui.log.close()
    finally:
        lock.release()

    execute_power_action(post_action, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
