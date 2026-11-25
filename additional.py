#!/usr/bin/env python3
"""Optional additional applications manager (multi-group selector & download table)."""

from __future__ import annotations

import os
import pwd
import re
import shutil
from pathlib import Path

import hardware
import patcher
import ui

BASE_ADDITIONAL_GROUPS: dict[str, list[str]] = {
    "Browsers & Comms": [
        "firefox",
        "discord",
        "telegram-desktop",
    ],
    "Security & Productivity": [
        "keepassxc",
        "obsidian",
        "btrfs-assistant",
        "discover",
        "flatpak",
    ],
    "Media & Mobile": [
        "spotify-launcher",
        "haruna",
        "kdenlive",
        "cava",
        "yt-dlp",
        "scrcpy",
        "android-tools",
    ],
    "AI & Coding": [
        "opencode",
        "opencode-desktop",
    ],
    "Gaming (multilib)": [
        "steam",
        "lib32-vulkan-intel",
    ],
}

# Backwards-compatible alias for default Intel laptop layout
ADDITIONAL_GROUPS = BASE_ADDITIONAL_GROUPS


def build_groups(hw: hardware.HardwareProfile | None = None) -> dict[str, list[str]]:
    """Return additional package groups adapted to detected GPU multilib drivers."""
    profile = hw or hardware.detect()
    groups = {label: list(pkgs) for label, pkgs in BASE_ADDITIONAL_GROUPS.items()}
    groups["Gaming (multilib)"] = ["steam", *profile.multilib_gpu_packages()]
    return groups


def all_additional_packages(hw: hardware.HardwareProfile | None = None) -> list[str]:
    packages: list[str] = []
    for items in build_groups(hw).values():
        packages.extend(items)
    return packages


def needs_multilib(packages: list[str]) -> bool:
    return any(pkg == "steam" or pkg.startswith("lib32-") for pkg in packages)


def parse_group_selection(raw: str, group_count: int) -> list[int] | None:
    """Parse multi-select input like ``'1,3'``, ``'2-4'``, ``'all'``, or ``'none'``.

    Returns sorted 0-based indices, or ``None`` if input syntax is invalid.
    """
    cleaned = raw.strip().lower()
    if cleaned in ("", "n", "no", "none", "0", "skip"):
        return []
    if cleaned in ("a", "all", "y", "yes", "*"):
        return list(range(group_count))

    chosen: set[int] = set()
    for token in re.split(r"[\s,]+", cleaned):
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            if not (parts[0].isdigit() and parts[1].isdigit()):
                return None
            lo, hi = int(parts[0]), int(parts[1])
            if lo < 1 or hi > group_count or lo > hi:
                return None
            chosen.update(range(lo - 1, hi))
        elif token.isdigit():
            idx = int(token)
            if idx < 1 or idx > group_count:
                return None
            chosen.add(idx - 1)
        else:
            return None
    return sorted(chosen)


def _size_to_mib(raw_val: str) -> float | None:
    match = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(B|KiB|MiB|GiB)\s*$", raw_val)
    if not match:
        return None
    val = float(match.group(1))
    unit = match.group(2)
    if unit == "B":
        return val / (1024.0 * 1024.0)
    if unit == "KiB":
        return val / 1024.0
    if unit == "MiB":
        return val
    if unit == "GiB":
        return val * 1024.0
    return None


def parse_pacman_si(output: str) -> dict[str, dict[str, object]]:
    """Parse ``LC_ALL=C pacman -Si`` output into per-package metadata."""
    meta: dict[str, dict[str, object]] = {}
    current: dict[str, object] = {}

    for line in output.splitlines():
        if not line.strip():
            name = current.get("name")
            if isinstance(name, str) and name:
                meta[name] = current
            current = {}
            continue
        if ":" not in line or line.startswith(" "):
            continue
        key, val = line.split(":", 1)
        k = key.strip().lower()
        v = val.strip()
        if k == "name":
            current["name"] = v
        elif k == "repository":
            current["repo"] = v
        elif k == "version":
            current["version"] = v
        elif k == "download size":
            current["download_mib"] = _size_to_mib(v)
        elif k == "installed size":
            current["installed_mib"] = _size_to_mib(v)

    name = current.get("name")
    if isinstance(name, str) and name:
        meta[name] = current
    return meta


def inspect_packages(packages: list[str]) -> list[dict[str, object]]:
    """Query local installed set & sync DB sizes via read-only pacman calls."""
    installed_res = ui.run(
        ["pacman", "-Qq"],
        readonly=True,
        check=False,
        env_extra={"LC_ALL": "C"},
    )
    installed_set = {
        line.strip() for line in installed_res.stdout.splitlines() if line.strip()
    }

    si_res = ui.run(
        ["pacman", "-Si", *packages],
        readonly=True,
        check=False,
        env_extra={"LC_ALL": "C"},
    )
    si_map = parse_pacman_si(si_res.stdout)

    rows: list[dict[str, object]] = []
    for pkg in packages:
        info = si_map.get(pkg, {})
        rows.append(
            {
                "name": pkg,
                "repo": info.get("repo", "-"),
                "version": info.get("version", "-"),
                "download_mib": info.get("download_mib"),
                "installed_mib": info.get("installed_mib"),
                "installed": pkg in installed_set,
            }
        )
    return rows


def prompt_additional_selection(
    *,
    interactive: bool = True,
    hw: hardware.HardwareProfile | None = None,
) -> list[str]:
    """Display grouped additional packages and prompt multi-group selection."""
    groups = build_groups(hw)
    labels = list(groups.keys())
    ui.render_package_table("Additional Applications (Optional)", groups)
    if not interactive:
        return all_additional_packages(hw)

    while True:
        raw = ui.ask(
            f"Select groups to install (e.g. '1,3', 'all', or 'none')",
            default="none",
        )
        indices = parse_group_selection(raw, len(labels))
        if indices is not None:
            break
        ui.warn(f"Enter group numbers between 1 and {len(labels)} (e.g. 1,2), 'all', or 'none'.")

    if not indices:
        ui.info(
            "Skipped additional applications. You can install them anytime via: "
            "sudo python3 archset.py --additional"
        )
        return []

    selected: list[str] = []
    for idx in indices:
        selected.extend(groups[labels[idx]])
    ui.ok(f"Selected {len(selected)} package(s) across {len(indices)} group(s)")
    return selected


def resolve_target_user(explicit_user: str | None = None) -> str | None:
    """Resolve the non-root user whose ~/archset/setup.log should receive the log."""
    if explicit_user:
        return explicit_user
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    pkexec_uid = os.environ.get("PKEXEC_UID")
    if pkexec_uid and pkexec_uid.isdigit():
        try:
            entry = pwd.getpwuid(int(pkexec_uid))
            if entry.pw_name != "root":
                return entry.pw_name
        except KeyError:
            pass
    current = os.environ.get("USER")
    if current and current != "root":
        return current
    return None


def export_live_log(log_path: Path | None, username: str | None) -> None:
    """Export raw log to /home/<username>/archset/setup.log (mode 0600)."""
    if ui.DRY_RUN or log_path is None or not log_path.exists() or not username:
        return
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        ui.warn(f"User '{username}' not found; skipping ~/archset/setup.log export")
        return

    dest_dir = Path(pw.pw_dir) / "archset"
    dest_file = dest_dir / "setup.log"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(log_path, dest_file)
        os.chmod(dest_file, 0o600)
        if os.geteuid() == 0:
            os.chown(dest_dir, pw.pw_uid, pw.pw_gid)
            os.chown(dest_file, pw.pw_uid, pw.pw_gid)
        ui.ok(f"Raw setup log exported to {dest_file} (0600)")
    except OSError as exc:
        ui.warn(f"Could not export log to {dest_file}: {exc}")


def run_standalone(
    *,
    username: str | None = None,
    log_path: Path | None = None,
    assume_yes: bool = False,
) -> int:
    """Non-destructive standalone flow for ``archset.py --additional`` on a live system.

    Never imports or touches ``disk.py``.
    """
    ui.info("Running non-destructive --additional mode (storage untouched)")
    if os.geteuid() != 0 and not ui.DRY_RUN:
        raise ui.ArchsetError(
            "--additional requires root privileges (run with sudo or pkexec)."
        )

    hw = hardware.detect()
    target_user = resolve_target_user(username)
    selected = prompt_additional_selection(interactive=not assume_yes, hw=hw)
    if not selected:
        export_live_log(log_path, target_user)
        return 0

    if needs_multilib(selected):
        ui.info("Enabling [multilib] in /etc/pacman.conf for gaming/32-bit packages")
        ui.patch_file(
            "/etc/pacman.conf",
            lambda text: patcher.patch_pacman_conf(text, enable_multilib=True),
        )
        ui.run(["pacman", "-Sy", "--noconfirm"])

    plan_rows = inspect_packages(selected)
    new_count, total_dl, _total_inst = ui.render_download_plan(plan_rows)

    if not assume_yes:
        if not ui.confirm(
            f"Proceed to download & install {new_count} package(s) (~{total_dl:.1f} MiB)?",
            default=True,
        ):
            ui.info("Installation cancelled by user.")
            export_live_log(log_path, target_user)
            return 0

    ui.info(f"Installing {len(selected)} additional package(s)")
    ui.run(["pacman", "-S", "--needed", "--noconfirm", *selected])
    ui.ok("Additional applications installed")
    export_live_log(log_path, target_user)
    return 0
