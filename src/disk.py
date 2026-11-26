#!/usr/bin/env python3
"""Disk discovery and storage stack creation for archset.

Layout produced on the selected disk:

    p1  1 GiB  vfat (ESP)          -> /boot
    p2  rest   LUKS2 -> btrfs      -> / with subvolumes
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from . import ui

ESP_SIZE = "1G"
LARGE_DISK_ESP_THRESHOLD = 64 * 1024**3
SWAP_SIZE = "4G"
LUKS_NAME = "root"
BTRFS_LABEL = "arch"
MIN_DISK_BYTES = 20 * 1024**3

MOUNT_OPTS = "noatime,compress=zstd:3,space_cache=v2"
SWAP_MOUNT_OPTS = "noatime,compress=no,space_cache=v2"

# (subvolume name, mountpoint)
SUBVOLUMES = [
    ("@", "/"),
    ("@home", "/home"),
    ("@log", "/var/log"),
    ("@pkg", "/var/cache/pacman/pkg"),
    ("@snapshots", "/.snapshots"),
    ("@home_snapshots", "/home/.snapshots"),
    ("@swap", "/swap"),
]

TMP_BTRFS = "/run/archset/btrfs"


@dataclass
class DiskInfo:
    path: str
    name: str
    size: int
    model: str
    serial: str
    tran: str


def _lsblk_json(args: list[str]) -> dict:
    result = ui.run(["lsblk", "-J", *args], readonly=True, check=False)
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def list_disks(*, include_loop: bool = False) -> list[DiskInfo]:
    data = _lsblk_json(
        ["-b", "-d", "-o", "NAME,PATH,SIZE,MODEL,SERIAL,TRAN,TYPE"]
    )
    allowed_types = ("disk", "loop") if include_loop else ("disk",)
    disks: list[DiskInfo] = []
    for node in data.get("blockdevices", []):
        if node.get("type") not in allowed_types:
            continue
        name = str(node.get("name", ""))
        if name.startswith(("zram", "sr", "rom")):
            continue
        try:
            size = int(node.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        disks.append(
            DiskInfo(
                path=str(node.get("path") or f"/dev/{name}"),
                name=name,
                size=size,
                model=str(node.get("model") or "").strip(),
                serial=str(node.get("serial") or "").strip(),
                tran=str(node.get("tran") or "").strip(),
            )
        )
    return disks


def partitions(disk: str) -> list[str]:
    data = _lsblk_json(["-o", "NAME,PATH,TYPE", disk])
    result: list[str] = []

    def walk(node: dict) -> None:
        if node.get("type") == "part":
            result.append(str(node.get("path") or f"/dev/{node.get('name')}"))
        for child in node.get("children", []) or []:
            walk(child)

    for node in data.get("blockdevices", []):
        walk(node)
    return result


def partition_summary(disk: str) -> str:
    """Return a concise one-line summary of existing partitions on ``disk``."""
    data = _lsblk_json(["-b", "-o", "NAME,TYPE,SIZE,FSTYPE,LABEL", disk])
    entries: list[str] = []

    def walk(node: dict) -> None:
        if node.get("type") == "part":
            name = str(node.get("name") or "part")
            fstype = str(node.get("fstype") or "raw")
            try:
                sz = ui.format_bytes(int(node.get("size") or 0))
            except (TypeError, ValueError):
                sz = "?"
            label = str(node.get("label") or "").strip()
            lbl = f" ({label})" if label else ""
            entries.append(f"{name}: {fstype} {sz}{lbl}")
        for child in node.get("children", []) or []:
            walk(child)

    for node in data.get("blockdevices", []):
        walk(node)
    if not entries:
        return "unpartitioned / empty"
    joined = ", ".join(entries)
    return joined if len(joined) <= 64 else joined[:61] + "..."


def _source_of(path: str) -> str:
    """Resolve a mountpoint to its backing device, stripping btrfs suffixes."""
    result = ui.run(
        ["findmnt", "-n", "-o", "SOURCE", path],
        readonly=True,
        check=False,
    )
    lines = result.stdout.strip().splitlines()
    if not lines:
        return path
    return lines[0].split("[", 1)[0]


def backing_disk(path: str) -> str | None:
    if os.path.isdir(path) or not os.path.exists(path):
        path = _source_of(path)
    result = ui.run(
        ["lsblk", "-s", "-n", "-l", "-o", "NAME,TYPE", path],
        readonly=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] in ("disk", "loop"):
            return f"/dev/{fields[0]}"
    return None


def live_disks() -> set[str]:
    found: set[str] = set()
    for mountpoint in ("/run/archiso/bootmnt", "/"):
        disk = backing_disk(mountpoint)
        if disk:
            found.add(disk)
    return found


def is_mounted(disk: str) -> bool:
    data = _lsblk_json(["-o", "NAME,MOUNTPOINTS", disk])

    def walk(node: dict) -> bool:
        mountpoints = node.get("mountpoints") or []
        if isinstance(mountpoints, str):
            mountpoints = [mountpoints]
        if any(mountpoints):
            return True
        return any(walk(child) for child in node.get("children", []) or [])

    return any(walk(node) for node in data.get("blockdevices", []))


def assert_no_active_luks(name: str = LUKS_NAME) -> None:
    mapper = f"/dev/mapper/{name}"
    if os.path.exists(mapper):
        raise ui.ArchsetError(
            f"{mapper} is already active. Close it (cryptsetup close {name}) before installing."
        )


def assert_safe_target(disk: str) -> None:
    assert_no_active_luks()
    info = next(
        (item for item in list_disks(include_loop=True) if item.path == disk),
        None,
    )
    if info is None:
        raise ui.ArchsetError(f"{disk} is not a usable block device.")
    if info.size < MIN_DISK_BYTES:
        raise ui.ArchsetError(
            f"{disk} is only {ui.format_bytes(info.size)}; at least 20 GiB is required."
        )
    if disk in live_disks():
        raise ui.ArchsetError(
            f"{disk} holds the running live system and cannot be used as target."
        )
    if is_mounted(disk):
        raise ui.ArchsetError(f"{disk} has mounted partitions; unmount them first.")
    if backing_disk("/") == disk:
        raise ui.ArchsetError(
            f"{disk} backs the running root filesystem and cannot be used as target."
        )


def part_path(disk: str, number: int) -> str:
    if disk[-1].isdigit():
        return f"{disk}p{number}"
    return f"{disk}{number}"


def wait_for(path: str, timeout: int = 15) -> None:
    if ui.DRY_RUN:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.2)
    raise ui.ArchsetError(f"Device {path} did not appear within {timeout} seconds.")


def _zero_head_tail(device: str, *, mib: int = 16) -> None:
    """Zero the first and last ``mib`` MiB of a block device or partition."""
    chunk_bytes = mib * 1024 * 1024
    if ui.DRY_RUN:
        ui.log.debug(f"DRY-RUN  zero {mib}MiB head/tail on {device}")
        return
    try:
        fd = os.open(device, os.O_WRONLY)
    except OSError as exc:
        ui.log.debug(f"zero_head_tail skipped on {device}: {exc}")
        return
    zero_buf = b"\x00" * (1024 * 1024)
    try:
        for _ in range(mib):
            os.write(fd, zero_buf)
        try:
            end_pos = os.lseek(fd, 0, os.SEEK_END)
        except OSError:
            end_pos = 0
        if end_pos > chunk_bytes:
            os.lseek(fd, end_pos - chunk_bytes, os.SEEK_SET)
            for _ in range(mib):
                os.write(fd, zero_buf)
        os.fsync(fd)
    except OSError as exc:
        ui.log.debug(f"zero_head_tail partial write on {device}: {exc}")
    finally:
        os.close(fd)


def wipe(disk: str) -> None:
    ui.warn(f"Crypto-erasing and wiping all data on {disk}")
    luks_close()
    for part in partitions(disk):
        ui.run(["umount", "-R", part], check=False)
        ui.run(["swapoff", part], check=False)
        is_luks = ui.run(
            ["cryptsetup", "isLuks", part],
            readonly=True,
            check=False,
        )
        if is_luks.returncode == 0:
            ui.info(f"Destroying LUKS keyslots on {part} (cryptsetup erase)")
            ui.run(["cryptsetup", "erase", "--batch-mode", part], check=False)
        _zero_head_tail(part, mib=16)
        ui.run(["wipefs", "-af", part], check=False)
    _zero_head_tail(disk, mib=16)
    ui.run(["wipefs", "-af", disk])
    ui.run(["sgdisk", "--zap-all", disk])
    ui.run(["blkdiscard", "-f", disk], check=False)
    ui.run(["blockdev", "--flushbufs", disk], check=False)
    ui.run(["partprobe", disk], check=False)
    ui.run(["udevadm", "settle"])
    ui.run(["sync"], check=False)


def esp_size_for_disk(size_bytes: int) -> str:
    return "2G" if size_bytes >= LARGE_DISK_ESP_THRESHOLD else ESP_SIZE


def partition(disk: str, *, esp_size: str | None = None) -> None:
    resolved_esp = esp_size or ESP_SIZE
    ui.info(f"Creating GPT with a {resolved_esp} EFI system partition on {disk}")
    ui.run(
        [
            "sgdisk",
            "--clear",
            f"--new=1:0:+{resolved_esp}",
            "--typecode=1:ef00",
            "--change-name=1:ESP",
            "--new=2:0:0",
            "--typecode=2:8309",
            "--change-name=2:ARCH",
            disk,
        ]
    )
    ui.run(["partprobe", disk], check=False)
    ui.run(["udevadm", "settle"])
    wait_for(part_path(disk, 1))
    wait_for(part_path(disk, 2))
    ui.ok(f"Partitions created: {part_path(disk, 1)}, {part_path(disk, 2)}")


def mkfs_esp(device: str) -> None:
    ui.info(f"Formatting EFI system partition: {device}")
    ui.run(["mkfs.fat", "-F32", "-n", "ESP", device])


def luks_format(device: str, passphrase: str) -> None:
    ui.info(f"Creating LUKS2 container on {device} (argon2id, passphrase-only)")
    secret = (passphrase + "\n").encode()
    ui.run(
        [
            "cryptsetup",
            "--batch-mode",
            "--verbose",
            "--type",
            "luks2",
            "--pbkdf",
            "argon2id",
            "--hash",
            "sha512",
            "--key-size",
            "512",
            "--iter-time",
            "3000",
            "--use-urandom",
            "--key-file",
            "-",
            "luksFormat",
            device,
        ],
        input_data=secret,
    )
    ui.ok(f"LUKS2 container created on {device}")


def luks_open(device: str, name: str, passphrase: str) -> None:
    ui.info(f"Unlocking {device} as /dev/mapper/{name} (with TRIM discard)")
    secret = (passphrase + "\n").encode()
    ui.run(
        [
            "cryptsetup",
            "open",
            "--allow-discards",
            device,
            name,
            "--type",
            "luks2",
            "--key-file",
            "-",
        ],
        input_data=secret,
    )
    wait_for(f"/dev/mapper/{name}")
    ui.ok(f"Device mapper active: /dev/mapper/{name}")


def luks_close(name: str = LUKS_NAME, *, strict: bool = False) -> None:
    mapper = f"/dev/mapper/{name}"
    if ui.DRY_RUN or os.path.exists(mapper):
        ui.run(["cryptsetup", "close", name], check=strict)
    if strict and not ui.DRY_RUN and os.path.exists(mapper):
        raise ui.ArchsetError(f"Device mapper {mapper} is still active after close.")


def mkfs_btrfs(device: str) -> None:
    ui.info(f"Creating btrfs filesystem on {device}")
    ui.run(["mkfs.btrfs", "-f", "-L", BTRFS_LABEL, device])
    ui.ok("btrfs filesystem created")


def create_subvolumes(device: str) -> None:
    ui.info("Creating btrfs subvolumes: " + ", ".join(name for name, _ in SUBVOLUMES))
    ui.mkdir(TMP_BTRFS)
    ui.run(["mount", "-o", MOUNT_OPTS, device, TMP_BTRFS])
    try:
        for name, _ in SUBVOLUMES:
            ui.run(["btrfs", "subvolume", "create", "-p", f"{TMP_BTRFS}/{name}"])
    finally:
        ui.run(["umount", TMP_BTRFS], check=False)
    ui.ok("btrfs subvolumes created")


def mount_all(device: str) -> None:
    ui.info(f"Mounting btrfs subvolumes from {device} on /mnt")
    ui.run(["mount", "-o", f"subvol=@,{MOUNT_OPTS}", device, "/mnt"])
    for name, mountpoint in SUBVOLUMES[1:]:
        target = f"/mnt{mountpoint}"
        ui.mkdir(target)
        options = (
            f"subvol={name},{SWAP_MOUNT_OPTS}"
            if name == "@swap"
            else f"subvol={name},{MOUNT_OPTS}"
        )
        ui.run(["mount", "-o", options, device, target])
    ui.ok("Subvolumes mounted on /mnt")


def mount_esp(device: str) -> None:
    ui.info(f"Mounting EFI system partition {device} on /mnt/boot")
    ui.mkdir("/mnt/boot")
    ui.run(
        [
            "mount",
            "-o",
            "fmask=0177,dmask=0077,nodev,nosuid,noexec",
            device,
            "/mnt/boot",
        ]
    )


def make_swapfile() -> None:
    ui.info(f"Creating {SWAP_SIZE} swapfile at /mnt/swap/swapfile")
    ui.mkdir("/mnt/swap")
    ui.run(
        [
            "btrfs",
            "filesystem",
            "mkswapfile",
            "--size",
            SWAP_SIZE,
            "/mnt/swap/swapfile",
        ]
    )
    ui.run(["swapon", "/mnt/swap/swapfile"])
    ui.ok("Swapfile created and activated")


def normalize_fstab(content: str) -> str:
    """Ensure /boot gets fsck passno=2 (with dosfstools) and btrfs mounts stay passno=0."""
    lines: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        fields = line.split()
        if len(fields) == 6:
            mountpoint, fstype = fields[1], fields[2]
            if mountpoint == "/boot" and fstype == "vfat":
                fields[5] = "2"
                lines.append("\t".join(fields))
                continue
            if fstype == "btrfs":
                fields[5] = "0"
                lines.append("\t".join(fields))
                continue
            if fstype == "swap":
                opts = fields[3].split(",")
                if not any(opt.startswith("pri=") for opt in opts):
                    opts.append("pri=-2")
                    fields[3] = ",".join(opts)
                fields[5] = "0"
                lines.append("\t".join(fields))
                continue
        lines.append(line)
    return "\n".join(lines) + "\n"


def write_fstab() -> None:
    ui.info("Generating /etc/fstab from the mounted system")
    if ui.DRY_RUN:
        ui.log.debug("DRY-RUN  genfstab -U /mnt")
        return
    result = ui.run(["genfstab", "-U", "/mnt"], readonly=True)
    if not result.stdout.strip():
        raise ui.ArchsetError("genfstab produced no output.")
    normalized = normalize_fstab(result.stdout)
    ui.mkdir("/mnt/etc")
    ui.write_text("/mnt/etc/fstab", normalized, mode=0o644)
    if "subvol=/@" not in normalized:
        raise ui.ArchsetError("Generated fstab is missing the root btrfs subvolume.")
    ui.ok("fstab written (btrfs passno=0, /boot vfat passno=2)")


def luks_uuid(device: str) -> str:
    """Return the LUKS2 superblock UUID required by sd-encrypt (rd.luks.name=)."""
    result = ui.run(
        ["blkid", "-s", "UUID", "-o", "value", device],
        readonly=True,
    )
    value = result.stdout.strip()
    if not value:
        raise ui.ArchsetError(f"Could not read LUKS UUID for {device}.")
    return value


def partuuid(device: str) -> str:
    """Return GPT PARTUUID (note: sd-encrypt uses luks_uuid(), not partuuid())."""
    result = ui.run(
        ["blkid", "-s", "PARTUUID", "-o", "value", device],
        readonly=True,
    )
    value = result.stdout.strip()
    if not value:
        raise ui.ArchsetError(f"Could not read PARTUUID for {device}.")
    return value


def flush_and_unmount(
    target_disk: str | None = None,
    *,
    strict: bool = True,
) -> None:
    """Commit Btrfs CoW transactions, flush VFS & SSD caches, unmount /mnt, and close LUKS."""
    ui.info("Flushing filesystems and committing all writes to SSD")
    if ui.DRY_RUN or os.path.ismount("/mnt"):
        ui.run(["btrfs", "filesystem", "sync", "/mnt"], check=strict)
    ui.run(["sync"], check=strict)
    ui.run(["swapoff", "/mnt/swap/swapfile"], check=False)
    if ui.DRY_RUN or os.path.ismount("/mnt"):
        ui.run(["umount", "-R", "/mnt"], check=strict)
    if strict and not ui.DRY_RUN and os.path.ismount("/mnt"):
        raise ui.ArchsetError(
            "/mnt is still mounted; refusing poweroff/reboot to prevent filesystem corruption."
        )
    luks_close(strict=strict)
    if target_disk:
        ui.run(["blockdev", "--flushbufs", target_disk], check=False)
    ui.run(["udevadm", "settle"], check=False)
    ui.run(["sync"], check=False)
    if strict:
        ui.ok("All filesystems synced, unmounted, and flushed to SSD")


def unmount_all() -> None:
    flush_and_unmount(strict=False)
