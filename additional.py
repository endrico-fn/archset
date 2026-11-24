#!/usr/bin/env python3
"""Optional additional applications manager (in-install prompt & standalone --additional)."""

from __future__ import annotations

import os
import pwd
import shutil
from pathlib import Path

import patcher
import ui

ADDITIONAL_GROUPS: dict[str, list[str]] = {
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

MULTILIB_PACKAGES = {"steam", "lib32-vulkan-intel"}


def all_additional_packages() -> list[str]:
    packages: list[str] = []
    for items in ADDITIONAL_GROUPS.values():
        packages.extend(items)
    return packages


def needs_multilib(packages: list[str]) -> bool:
    return any(pkg in MULTILIB_PACKAGES for pkg in packages)


def prompt_additional_selection(*, interactive: bool = True) -> list[str]:
    """Display grouped additional packages and ask y/N confirmation."""
    ui.render_package_table("Additional Applications (Optional)", ADDITIONAL_GROUPS)
    if not interactive:
        return all_additional_packages()

    if ui.confirm("Install ALL additional applications listed above?", default=False):
        selected = all_additional_packages()
        ui.ok(f"Selected all additional applications ({len(selected)} packages)")
        return selected

    if ui.confirm("Select additional application groups individually?", default=False):
        selected: list[str] = []
        for label, packages in ADDITIONAL_GROUPS.items():
            if ui.confirm(
                f"  Install '{label}' ({', '.join(packages)})?",
                default=False,
            ):
                selected.extend(packages)
        if selected:
            ui.ok(f"Selected {len(selected)} additional package(s)")
        else:
            ui.info(
                "No additional packages selected. Run later with: sudo python3 archset.py --additional"
            )
        return selected

    ui.info(
        "Skipped additional applications. You can install them anytime via: "
        "sudo python3 archset.py --additional"
    )
    return []


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

    target_user = resolve_target_user(username)
    selected = prompt_additional_selection(interactive=not assume_yes)
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

    ui.info(f"Installing {len(selected)} additional package(s)")
    ui.run(["pacman", "-S", "--needed", "--noconfirm", *selected])
    ui.ok("Additional applications installed")
    export_live_log(log_path, target_user)
    return 0
