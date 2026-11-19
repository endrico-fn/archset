#!/usr/bin/env python3
"""Package installation, system configuration and boot setup for archset."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import configs
import disk
import ui

TARGET = "/mnt"
TIMEZONE = "Asia/Jakarta"
DEFAULT_SHELL = "/usr/bin/zsh"

BASE_PACKAGES = [
    "base",
    "base-devel",
    "sudo",
    "linux",
    "linux-firmware",
    "mkinitcpio",
    "btrfs-progs",
    "cryptsetup",
    "intel-ucode",
    "efibootmgr",
    "networkmanager",
    "wpa_supplicant",
    "wireless-regdb",
    "rate-mirrors",
    "zram-generator",
    "apparmor",
    "nftables",
    "snapper",
    "snap-pac",
    "pacman-contrib",
]

PACKAGE_GROUPS: dict[str, list[str]] = {
    "KDE Plasma": [
        "plasma-desktop",
        "plasma-login-manager",
        "plasma-nm",
        "plasma-pa",
        "plasma-systemmonitor",
        "kscreen",
        "bluedevil",
        "bluez",
        "bluez-utils",
        "kwallet-pam",
        "kwalletmanager",
        "kio-admin",
        "dolphin",
        "spectacle",
        "gwenview",
        "ark",
        "ffmpegthumbs",
        "kdegraphics-thumbnailers",
        "kinfocenter",
        "kdeplasma-addons",
        "breeze-gtk",
        "kde-gtk-config",
    ],
    "audio": [
        "pipewire",
        "pipewire-alsa",
        "pipewire-jack",
        "pipewire-pulse",
        "gst-plugin-pipewire",
        "libpulse",
        "wireplumber",
        "sof-firmware",
        "alsa-utils",
    ],
    "graphics": [
        "mesa",
        "intel-media-driver",
        "libva-intel-driver",
        "vpl-gpu-rt",
        "libvpl",
        "vulkan-intel",
    ],
    "fonts": [
        "noto-fonts",
        "ttf-jetbrains-mono-nerd",
    ],
    "terminal": [
        "kitty",
        "zsh",
        "zsh-completions",
        "zsh-autosuggestions",
        "zsh-syntax-highlighting",
        "starship",
        "git",
        "fzf",
        "zoxide",
        "eza",
        "bat",
        "fd",
        "ripgrep",
        "tmux",
        "man-db",
        "man-pages",
        "bash-completion",
    ],
    "utilities": [
        "btop",
        "wl-clipboard",
        "btrfs-assistant",
        "fwupd",
        "firefox",
        "spotify-launcher",
        "github-cli",
        "7zip",
        "unzip",
        "zip",
        "rsync",
        "tree",
        "jq",
        "lsof",
        "nano",
        "vim",
        "wget",
        "openssh",
        "smartmontools",
        "xdg-utils",
        "power-profiles-daemon",
        "tesseract-data-ind",
    ],
    "development": [
        "neovim",
        "tree-sitter-cli",
        "rustup",
        "go",
        "uv",
        "fnm",
        "pnpm",
        "mold",
        "strace",
        "hyperfine",
        "shellcheck",
        "codespell",
    ],
}

REQUIRED_SERVICES = [
    "NetworkManager.service",
    "plasmalogin.service",
    "apparmor.service",
    "nftables.service",
]

OPTIONAL_SERVICES = [
    "bluetooth.service",
    "power-profiles-daemon.service",
    "systemd-timesyncd.service",
    "fstrim.timer",
    "paccache.timer",
    "snapper-timeline.timer",
    "snapper-cleanup.timer",
    "smartd.service",
    "btrfs-scrub@-.timer",
]


def write(relative: str, content: str, mode: int = 0o644) -> None:
    path = f"{TARGET}/{relative.lstrip('/')}"
    ui.write_text(path, content, mode=mode)


def chroot(args: list[str], **kwargs) -> ui.Result:
    return ui.run(["arch-chroot", TARGET, *args], **kwargs)


def pacstrap(packages: list[str], label: str, *, init_keyring: bool = False) -> None:
    ui.info(f"Installing {label} ({len(packages)} packages)")
    cmd = ["pacstrap", "-C", "/etc/pacman.conf"]
    if init_keyring:
        cmd.append("-K")
    cmd.extend([TARGET, *packages])
    ui.run(cmd)


def _server_count(path: str = "/etc/pacman.d/mirrorlist") -> int:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip().startswith("Server"))


def select_mirrors() -> None:
    ui.info("Selecting HTTPS mirrors with reflector (Indonesia, Singapore, Japan)")
    # Prevent race conditions with the live ISO's background reflector service.
    ui.run(["systemctl", "stop", "reflector.service"], check=False)
    if shutil.which("reflector") is None:
        ui.warn("reflector is not present in the live environment; installing it")
        try:
            ui.run(["pacman", "-Sy", "--needed", "--noconfirm", "reflector"])
        except ui.CommandError as exc:
            ui.warn(
                f"Could not install reflector; using the existing mirrorlist: {exc}"
            )
    try:
        ui.run(
            [
                "reflector",
                "--country",
                "Indonesia",
                "--country",
                "Singapore",
                "--country",
                "Japan",
                "--protocol",
                "https",
                "--latest",
                "20",
                "--sort",
                "rate",
                "--save",
                "/etc/pacman.d/mirrorlist",
                "--verbose",
            ]
        )
    except ui.CommandError as exc:
        ui.warn(f"reflector failed: {exc}")
    count = _server_count()
    if count == 0:
        ui.warn("No mirrors were written; falling back to the official CDN list")
        ui.write_text("/etc/pacman.d/mirrorlist", configs.MIRRORLIST_FALLBACK)
    elif not ui.DRY_RUN:
        # Keep the official CDN as a guaranteed fallback behind the ranked list.
        text = Path("/etc/pacman.d/mirrorlist").read_text(encoding="utf-8")
        extra = [
            line
            for line in configs.MIRRORLIST_FALLBACK.splitlines()
            if line and line not in text
        ]
        if extra:
            ui.write_text(
                "/etc/pacman.d/mirrorlist",
                "\n".join(extra) + "\n",
                append=True,
            )
    count = _server_count()
    ui.ok(f"Mirrorlist contains {count} server(s)")


def install_base() -> None:
    pacstrap(BASE_PACKAGES, "base system", init_keyring=True)


def install_groups() -> None:
    chroot(["pacman", "-Sy", "--noconfirm"])
    for label, packages in PACKAGE_GROUPS.items():
        ui.info(f"Installing {label} ({len(packages)} packages)")
        chroot(["pacman", "-S", "--noconfirm", "--needed", *packages])


def copy_mirrorlist() -> None:
    ui.info("Copying the selected mirrorlist into the new system")
    ui.copy("/etc/pacman.d/mirrorlist", f"{TARGET}/etc/pacman.d/mirrorlist")


def _replace_line(text: str, pattern: str, replacement: str) -> tuple[str, bool]:
    new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    return new_text, count > 0


def configure_pacman() -> None:
    ui.info("Configuring /etc/pacman.conf")
    if ui.DRY_RUN:
        return
    path = Path(f"{TARGET}/etc/pacman.conf")
    if not path.exists():
        ui.warn("pacman.conf not found; skipping configuration")
        return
    text = path.read_text(encoding="utf-8")

    text, found = _replace_line(text, r"^#?\s*Color\s*$", "Color")
    if not found:
        text = text.replace("[options]\n", "[options]\nColor\n", 1)

    text, found = _replace_line(text, r"^#?\s*ILoveCandy\s*$", "ILoveCandy")
    if not found:
        text = text.replace("Color\n", "Color\nILoveCandy\n", 1)

    text, found = _replace_line(text, r"^#?\s*VerbosePkgLists\s*$", "VerbosePkgLists")
    if not found:
        text = text.replace("ILoveCandy\n", "ILoveCandy\nVerbosePkgLists\n", 1)

    text, found = _replace_line(
        text, r"^#?\s*ParallelDownloads\s*=.*$", "ParallelDownloads = 5"
    )
    if not found:
        text = text.replace("ILoveCandy\n", "ILoveCandy\nParallelDownloads = 5\n", 1)

    text, found = _replace_line(text, r"^#?\s*CheckSpace\s*$", "CheckSpace")
    if not found:
        text = text.replace("Color\n", "Color\nCheckSpace\n", 1)

    ui.write_text(path, text)
    ui.ok(
        "pacman.conf updated (Color, ILoveCandy, CheckSpace, VerbosePkgLists, ParallelDownloads)"
    )


def configure_locale(hostname: str, timezone: str = TIMEZONE) -> None:
    ui.info(f"Configuring locale, timezone ({timezone}) and hostname ({hostname})")
    write("/etc/locale.gen", configs.LOCALE_GEN)
    write("/etc/locale.conf", configs.LOCALE_CONF)
    write("/etc/vconsole.conf", configs.VCONSOLE_CONF)
    write("/etc/hostname", f"{hostname}\n")
    write("/etc/hosts", configs.hosts(hostname))

    chroot(["locale-gen"])
    chroot(["ln", "-sf", f"/usr/share/zoneinfo/{timezone}", "/etc/localtime"])
    try:
        chroot(["hwclock", "--systohc"])
    except ui.CommandError as exc:
        ui.warn(f"hwclock --systohc failed (continuing): {exc}")
    ui.ok("Locale, timezone and hostname configured")


def create_user(username: str, password: str) -> None:
    ui.info(f"Creating user {username} with wheel privileges")
    chroot(["useradd", "-m", "-G", "wheel", "-s", DEFAULT_SHELL, "--", username])
    chroot(
        ["chpasswd"],
        input_data=f"{username}:{password}\nroot:{password}\n",
    )
    write("/etc/sudoers.d/10-wheel", configs.SUDOERS_WHEEL, mode=0o440)

    if not ui.DRY_RUN:
        sudoers = Path(f"{TARGET}/etc/sudoers")
        if sudoers.exists():
            text = sudoers.read_text(encoding="utf-8")
            if "@includedir /etc/sudoers.d" not in text:
                ui.write_text(sudoers, "@includedir /etc/sudoers.d\n", append=True)
    ui.ok(f"User {username} created; root and user share the configured password")


def setup_zram() -> None:
    ui.info("Configuring zram swap (zstd)")
    write("/etc/systemd/zram-generator.conf", configs.ZRAM_CONF)
    ui.ok("zram-generator configured")


def setup_snapper() -> None:
    ui.info("Configuring snapper for root and home with dedicated @snapshots subvolume")
    # Prepare /.snapshots mountpoint for independent @snapshots subvolume
    snapshots_dir = f"{TARGET}/.snapshots"
    ui.run(["umount", snapshots_dir], check=False)
    if not ui.DRY_RUN:
        if os.path.ismount(snapshots_dir):
            raise ui.ArchsetError(f"Failed to unmount {snapshots_dir} before snapper setup.")
        if os.path.isdir(snapshots_dir):
            os.rmdir(snapshots_dir)

    chroot(["snapper", "--no-dbus", "-c", "root", "create-config", "/"])
    # Delete the nested subvolume snapper just created
    chroot(["btrfs", "subvolume", "delete", "/.snapshots"], check=False)
    ui.mkdir(snapshots_dir)

    # Remount @snapshots on /.snapshots
    mapper = f"/dev/mapper/{disk.LUKS_NAME}"
    ui.run(
        [
            "mount",
            "-o",
            f"subvol=@snapshots,{disk.MOUNT_OPTS}",
            mapper,
            f"{TARGET}/.snapshots",
        ]
    )
    chroot(["chmod", "750", "/.snapshots"])

    # Configure home snapper config
    config_home = f"{TARGET}/etc/snapper/configs/home"
    if not ui.DRY_RUN and not os.path.exists(config_home):
        chroot(["snapper", "--no-dbus", "-c", "home", "create-config", "/home"])

    # Patch snapper configs: ALLOW_GROUPS="wheel" and prune retention limits
    if not ui.DRY_RUN:
        for name in ("root", "home"):
            cfg = Path(f"{TARGET}/etc/snapper/configs/{name}")
            if cfg.exists():
                text = cfg.read_text(encoding="utf-8")
                text = re.sub(
                    r'^ALLOW_GROUPS=".*"',
                    'ALLOW_GROUPS="wheel"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^TIMELINE_LIMIT_HOURLY=".*"',
                    'TIMELINE_LIMIT_HOURLY="5"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^TIMELINE_LIMIT_DAILY=".*"',
                    'TIMELINE_LIMIT_DAILY="7"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^TIMELINE_LIMIT_WEEKLY=".*"',
                    'TIMELINE_LIMIT_WEEKLY="0"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^TIMELINE_LIMIT_MONTHLY=".*"',
                    'TIMELINE_LIMIT_MONTHLY="0"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^TIMELINE_LIMIT_YEARLY=".*"',
                    'TIMELINE_LIMIT_YEARLY="0"',
                    text,
                    flags=re.MULTILINE,
                )
                text = re.sub(
                    r'^NUMBER_LIMIT=".*"', 'NUMBER_LIMIT="10"', text, flags=re.MULTILINE
                )
                cfg.write_text(text, encoding="utf-8")

    ui.ok("snapper configuration created and tuned")


def enable_services() -> None:
    ui.info("Enabling system services")
    for service in REQUIRED_SERVICES:
        chroot(["systemctl", "enable", service])
    for service in OPTIONAL_SERVICES:
        try:
            chroot(["systemctl", "enable", service])
        except ui.CommandError as exc:
            ui.warn(f"Could not enable {service}: {exc}")
    ui.ok("Services enabled")


def setup_bootloader(root_partuuid: str) -> None:
    ui.info("Configuring systemd-boot with a unified kernel image")
    cmdline = " ".join(
        [
            f"cryptdevice=PARTUUID={root_partuuid}:root:allow-discards",
            "root=/dev/mapper/root",
            "zswap.enabled=0",
            "rootflags=subvol=@",
            "rw",
            "rootfstype=btrfs",
            "lsm=landlock,lockdown,yama,integrity,apparmor,bpf",
        ]
    )
    write("/etc/kernel/cmdline", cmdline + "\n")
    write("/etc/mkinitcpio.conf", configs.MKINITCPIO_CONF)
    write("/etc/mkinitcpio.d/linux.preset", configs.UKI_PRESET)
    ui.mkdir(f"{TARGET}/boot/EFI/Linux")

    try:
        chroot(["bootctl", "--variables=yes", "install"])
    except ui.CommandError as exc:
        ui.warn(f"bootctl with EFI variables failed; retrying without them: {exc}")
        try:
            chroot(["bootctl", "--variables=no", "install"])
        except ui.CommandError as exc2:
            ui.warn(f"bootctl without EFI variables failed; retrying plainly: {exc2}")
            chroot(["bootctl", "install"])

    write("/boot/loader/loader.conf", configs.LOADER_CONF)
    chroot(["mkinitcpio", "-P"])

    # Remove legacy initramfs images left over from initial linux pacstrap
    if not ui.DRY_RUN:
        for leftover in (
            f"{TARGET}/boot/initramfs-linux.img",
            f"{TARGET}/boot/initramfs-linux-fallback.img",
        ):
            try:
                Path(leftover).unlink(missing_ok=True)
            except OSError as exc:
                ui.warn(f"Could not remove leftover {leftover}: {exc}")

    ui.ok("systemd-boot installed and UKI built")


def inject_system_configs() -> None:
    ui.info("Injecting sysctl, firewall, NetworkManager and driver configurations")
    # Sysctl optimization & security
    write("/etc/sysctl.d/99-knsfd.conf", configs.SYSCTL_KNSFD)

    # Firewall (nftables)
    write("/etc/nftables.conf", configs.NFTABLES_CONF, mode=0o755)

    # NetworkManager MAC randomization, privacy & powersave
    write("/etc/NetworkManager/conf.d/nm.conf", configs.NM_CONF)

    # Hardware driver options (Intel GPU, HDA Audio, Realtek Wi-Fi & USB)
    write("/etc/modprobe.d/i915.conf", configs.MODPROBE_I915)
    write("/etc/modprobe.d/audio_powersave.conf", configs.MODPROBE_AUDIO)
    write("/etc/modprobe.d/rtw88_powersave.conf", configs.MODPROBE_RTW88)
    write("/etc/modprobe.d/usb_powersave.conf", configs.MODPROBE_USB)

    # Bluetooth performance & experimental features (battery reporting)
    write("/etc/bluetooth/main.conf", configs.BLUETOOTH_MAIN_CONF)

    # Wireless regulatory domain
    write("/etc/conf.d/wireless-regdom", configs.WIRELESS_REGDOM_CONF)

    ui.ok("System, driver and security configurations injected")


def inject_user_configs(username: str, hostname: str) -> None:
    ui.info(f"Injecting XDG dotfiles, zsh, fzf-tab, kitty, nvim and dev configs for {username}")
    home = f"/home/{username}"

    # XDG Zsh layout (~/.config/zsh/{.zshenv,.zshrc} + relative symlink ~/.zshenv)
    write(f"{home}/.config/zsh/.zshenv", configs.ZSHENV)
    write(f"{home}/.config/zsh/.zshrc", configs.ZSHRC)
    chroot(["ln", "-sfn", ".config/zsh/.zshenv", f"{home}/.zshenv"])

    # Pre-create XDG directories for shell/toolchain state & cache
    for rel_dir in (
        ".config/zsh/plugin",
        ".config/npm",
        ".cache/zsh",
        ".local/state/zsh",
        ".local/state/python",
    ):
        ui.mkdir(f"{TARGET}{home}/{rel_dir}")

    # Install fzf-tab plugin into ~/.config/zsh/plugin/fzf-tab
    fzf_tab_dir = f"{home}/.config/zsh/plugin/fzf-tab"
    if ui.DRY_RUN or not Path(f"{TARGET}{fzf_tab_dir}").exists():
        try:
            chroot(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "https://github.com/Aloxaf/fzf-tab.git",
                    fzf_tab_dir,
                ],
                timeout=60,
            )
        except ui.CommandError as exc:
            ui.warn(f"Could not clone fzf-tab (continuing without it): {exc}")

    # Systemd user environment (XDG & toolchains synced with .zshenv)
    write(f"{home}/.config/environment.d/10-env.conf", configs.ENV_D_CONF)

    # Hardened Neovim config for sudoedit / pacdiff
    write(f"{home}/.config/nvim/sudoedit.lua", configs.NVIM_SUDOEDIT_LUA)

    # Cargo mold linker config (XDG CARGO_HOME)
    write(f"{home}/.local/share/cargo/config.toml", configs.CARGO_CONFIG_TOML)

    # Terminal, KDE default terminal, and XDG Git config
    write(f"{home}/.config/kitty/kitty.conf", configs.KITTY_CONF)
    write(f"{home}/.config/kdeglobals", configs.KDE_GLOBALS_TERMINAL)
    write(
        f"{home}/.config/git/config",
        configs.gitconfig(username, f"{username}@{hostname}"),
    )

    try:
        chroot(
            [
                "starship",
                "preset",
                "nerd-font-symbols",
                "-o",
                f"{home}/.config/starship.toml",
            ]
        )
    except ui.CommandError as exc:
        ui.warn(f"starship preset failed; writing fallback configuration: {exc}")
        write(f"{home}/.config/starship.toml", configs.STARSHIP_FALLBACK)

    chroot(["chown", "-R", f"{username}:{username}", home])
    chroot(["chmod", "700", home])
    ui.ok("User configuration applied")


def verify(username: str) -> None:
    ui.info("Verifying the installation")
    if ui.DRY_RUN:
        ui.warn("Dry run enabled; verification skipped")
        return

    home = f"{TARGET}/home/{username}"
    required = {
        f"{TARGET}/etc/fstab": "fstab",
        f"{TARGET}/etc/kernel/cmdline": "kernel command line",
        f"{TARGET}/boot/EFI/Linux/arch-linux.efi": "unified kernel image",
        f"{TARGET}/etc/snapper/configs/root": "snapper root config",
        f"{TARGET}/etc/nftables.conf": "nftables configuration",
        f"{TARGET}/etc/sysctl.d/99-knsfd.conf": "sysctl optimization config",
        f"{home}/.zshenv": "zsh .zshenv symlink",
        f"{home}/.config/zsh/.zshenv": "zsh XDG .zshenv",
        f"{home}/.config/zsh/.zshrc": "zsh XDG .zshrc",
        f"{home}/.config/environment.d/10-env.conf": "systemd user environment config",
        f"{home}/.config/nvim/sudoedit.lua": "neovim sudoedit config",
        f"{home}/.local/share/cargo/config.toml": "cargo mold config",
        f"{home}/.config/git/config": "XDG git configuration",
        f"{home}/.config/kitty/kitty.conf": "kitty configuration",
        f"{home}/.config/kdeglobals": "KDE default terminal configuration",
        f"{home}/.config/starship.toml": "starship configuration",
    }
    missing = [label for path, label in required.items() if not os.path.exists(path)]
    if missing:
        raise ui.ArchsetError(
            "Installation verification failed; missing: " + ", ".join(missing)
        )

    fstab = Path(f"{TARGET}/etc/fstab").read_text(encoding="utf-8")
    if "subvol=/@" not in fstab:
        raise ui.ArchsetError("fstab does not reference the root btrfs subvolume.")

    shell = chroot(["getent", "passwd", username], check=False).stdout.strip()
    if DEFAULT_SHELL not in shell:
        raise ui.ArchsetError(f"Default shell for {username} is not zsh.")

    ui.ok("Installation verified")


def copy_log(log_path: str | Path) -> None:
    if ui.DRY_RUN or log_path is None:
        return
    destination = Path(f"{TARGET}/var/log/archset")
    try:
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(log_path, destination / Path(log_path).name)
        ui.ok(f"Installation log copied to {destination}")
    except OSError as exc:
        ui.warn(f"Could not copy the installation log: {exc}")
