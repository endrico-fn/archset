#!/usr/bin/env python3
"""Device decommissioning (--uninstall) and migration backup (--export-backup)."""

from __future__ import annotations

import io
import os
import pwd
import re
import socket
import sys
import tarfile
from datetime import datetime
from pathlib import Path

from . import additional, disk, ui

EFI_BOOT_LABELS = ("linux boot manager", "arch linux")

BACKUP_PATHS = (
    "etc/archrelius.conf",
    "etc/wireguard/profiles",
    "var/lib/importwgp/index.tsv",
)


def parse_efibootmgr_entries(output: str) -> list[tuple[str, str]]:
    """Return ``(boot_hex, label)`` pairs for systemd-boot / Arch Linux NVRAM entries."""
    matches: list[tuple[str, str]] = []
    for line in output.splitlines():
        m = re.match(r"^Boot([0-9A-Fa-f]{4})\*?\s+([^\t]+?)(?:\t|$)", line.strip())
        if not m:
            continue
        boot_id = m.group(1).upper()
        label = m.group(2).strip()
        if label.lower() in EFI_BOOT_LABELS:
            matches.append((boot_id, label))
    return matches


def cleanup_efi_boot_entries(*, interactive: bool = True) -> int:
    """Detect and remove stale systemd-boot / Arch Linux UEFI NVRAM entries."""
    res = ui.run(["efibootmgr"], readonly=True, check=False)
    if res.returncode != 0:
        ui.warn("Could not query efibootmgr; skipping UEFI NVRAM cleanup.")
        return 0

    entries = parse_efibootmgr_entries(res.stdout)
    if not entries:
        ui.info("No 'Linux Boot Manager' or 'Arch Linux' UEFI NVRAM entries found.")
        return 0

    for boot_id, label in entries:
        ui.info(f"Detected UEFI NVRAM entry: Boot{boot_id} ({label})")

    if interactive and not ui.confirm(
        f"Remove {len(entries)} Arch/systemd-boot UEFI NVRAM boot entr(ies)?",
        default=True,
    ):
        ui.info("Kept existing UEFI NVRAM entries.")
        return 0

    removed = 0
    for boot_id, label in entries:
        ui.info(f"Removing UEFI boot entry Boot{boot_id} ({label})")
        del_res = ui.run(["efibootmgr", "-b", boot_id, "-B"], check=False)
        if del_res.returncode == 0 or ui.DRY_RUN:
            removed += 1
    ui.ok(f"Cleaned {removed} UEFI NVRAM boot entr(ies)")
    return removed


def run_uninstall(args, *, select_disk_fn) -> tuple[int, str]:
    """Run Live-ISO cryptographic disk decommission & UEFI boot entry cleanup.

    Returns ``(exit_code, power_action)``.
    """
    if os.geteuid() != 0 and not ui.DRY_RUN:
        raise ui.ArchsetError("--uninstall must be run as root from the Arch ISO.")
    if os.path.ismount("/mnt"):
        raise ui.ArchsetError("/mnt is mounted. Unmount it before running --uninstall.")
    disk.assert_no_active_luks()

    if not Path("/run/archiso").exists():
        if not args.force:
            raise ui.ArchsetError(
                "--uninstall must be run from the Arch Live ISO (or pass --force if certain)."
            )
        ui.warn("Running --uninstall outside the Arch ISO because --force was supplied.")

    info = select_disk_fn(args)

    ui.hr("=", 76)
    ui.warn("DECOMMISSION / UNINSTALL: ALL DATA & LUKS2 KEYSLOTS WILL BE DESTROYED")
    ui.hr("=", 76)
    print(f"  Device : {info.path}")
    print(f"  Model  : {info.model or 'unknown'}")
    print(f"  Serial : {info.serial or 'unknown'}")
    print(f"  Size   : {ui.format_bytes(info.size)}")
    print("  Action : cryptsetup erase + 16 MiB head/tail zero + blkdiscard + UEFI cleanup")
    ui.hr("=", 76)

    if not ui.confirm_typed("permanently crypto-erase the disk", f"ERASE {info.path}"):
        raise ui.ArchsetError("Uninstall confirmation mismatch. Aborting.")
    if not ui.confirm(
        "Destroy all partitions and LUKS2 keyslots now? This cannot be undone.",
        default=False,
    ):
        raise ui.ArchsetError("Uninstall cancelled by the user.")

    disk.wipe(info.path)
    if Path("/sys/firmware/efi/efivars").exists() or ui.DRY_RUN:
        cleanup_efi_boot_entries(interactive=sys.stdin.isatty() and not ui.DRY_RUN)

    ui.ok(f"Disk {info.path} has been cryptographically erased and decommissioned")

    action = "stay"
    if sys.stdin.isatty() and not ui.DRY_RUN:
        choice = ui.menu(
            "Uninstall Complete — Select Next Action",
            [
                "Stay in Live ISO    (return to shell)",
                "Poweroff System     (systemctl poweroff — safe USB removal)",
                "Reboot System       (systemctl reboot)",
            ],
            default=1,
        )
        action = ("stay", "poweroff", "reboot")[choice]

    return 0, action


def export_backup(
    *,
    dest_dir: str | Path | None = None,
    username: str | None = None,
    root_dir: str | Path = "/",
    hostname: str | None = None,
) -> Path:
    """Create a mode-0600 migration bundle (WireGuard profiles, archrelius.conf, pkglist)."""
    root_path = Path(root_dir)
    if root_path == Path("/") and os.geteuid() != 0 and not ui.DRY_RUN:
        raise ui.ArchsetError(
            "--export-backup requires root privileges (run with sudo) to read /etc/wireguard."
        )

    target_user = additional.resolve_target_user(username)
    pw_entry = None
    if target_user:
        try:
            pw_entry = pwd.getpwnam(target_user)
        except KeyError:
            pw_entry = None

    if dest_dir:
        out_dir = Path(dest_dir)
    elif pw_entry is not None:
        out_dir = Path(pw_entry.pw_dir) / "archset"
    else:
        out_dir = Path("/root/archset")

    host = re.sub(r"[^A-Za-z0-9._-]+", "-", hostname or socket.gethostname()).strip("-") or "arch"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bundle_path = out_dir / f"archset-backup-{host}-{stamp}.tar.gz"

    if ui.DRY_RUN:
        ui.info(f"[dry-run] Would export migration bundle to {bundle_path}")
        return bundle_path

    out_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw_fh, tarfile.open(fileobj=raw_fh, mode="w:gz") as tar:
        for rel in BACKUP_PATHS:
            candidate = root_path / rel
            if candidate.exists() and not candidate.is_symlink():
                tar.add(candidate, arcname=rel, recursive=True)

        pkg_res = ui.run(["pacman", "-Qqe"], readonly=True, check=False)
        pkg_bytes = pkg_res.stdout.encode("utf-8")
        info = tarfile.TarInfo(name="pkglist-explicit.txt")
        info.size = len(pkg_bytes)
        info.mode = 0o600
        info.mtime = int(datetime.now().timestamp())
        tar.addfile(info, io.BytesIO(pkg_bytes))

    os.chmod(bundle_path, 0o600)
    if os.geteuid() == 0 and pw_entry is not None:
        os.chown(out_dir, pw_entry.pw_uid, pw_entry.pw_gid)
        os.chown(bundle_path, pw_entry.pw_uid, pw_entry.pw_gid)

    ui.ok(f"Migration backup exported to {bundle_path} (mode 0600)")
    return bundle_path
