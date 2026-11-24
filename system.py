#!/usr/bin/env python3
"""Phased package installation, drop-in/line-patch config injection, and UKI boot setup."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import configs
import disk
import patcher
import ui

TARGET = "/mnt"
TIMEZONE = "Asia/Jakarta"
DEFAULT_SHELL = "/usr/bin/zsh"

# Phase 1: Base OS, kernel, LUKS2, Btrfs, UKI, and recovery/audit essentials
BASE_PACKAGES = [
    "base",
    "base-devel",
    "sudo",
    "linux",
    "linux-firmware",
    "intel-ucode",
    "mkinitcpio",
    "btrfs-progs",
    "dosfstools",
    "cryptsetup",
    "efibootmgr",
    "zram-generator",
    "snapper",
    "snap-pac",
    "pacman-contrib",
    "arch-audit",
]

# Subsequent structured package phases installed inside arch-chroot
INSTALL_PHASES: dict[str, list[str]] = {
    "Network, Wi-Fi, Bluetooth & Security": [
        "networkmanager",
        "wpa_supplicant",
        "wireless-regdb",
        "bluez",
        "bluez-utils",
        "nftables",
        "apparmor",
        "audit",
        "dnscrypt-proxy",
        "wireguard-tools",
        "rate-mirrors",
    ],
    "Graphics Drivers & Audio": [
        "mesa",
        "intel-media-driver",
        "vulkan-intel",
        "libvpl",
        "pipewire",
        "pipewire-alsa",
        "pipewire-jack",
        "pipewire-pulse",
        "gst-plugin-pipewire",
        "libpulse",
        "wireplumber",
        "alsa-utils",
        "power-profiles-daemon",
        "fwupd",
    ],
    "Desktop Environment (KDE Plasma) & Fonts": [
        "plasma-desktop",
        "plasma-login-manager",
        "plasma-nm",
        "plasma-pa",
        "plasma-systemmonitor",
        "kscreen",
        "bluedevil",
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
        "noto-fonts",
        "noto-fonts-cjk",
        "ttf-jetbrains-mono-nerd",
        "ttf-sarasa-gothic",
    ],
    "Terminal, Shell, Core Utilities & Development": [
        "kitty",
        "zsh",
        "zsh-completions",
        "zsh-autosuggestions",
        "zsh-syntax-highlighting",
        "starship",
        "neovim",
        "neovide",
        "git",
        "github-cli",
        "fzf",
        "zoxide",
        "eza",
        "bat",
        "fd",
        "ripgrep",
        "tmux",
        "btop",
        "wl-clipboard",
        "lazygit",
        "lnav",
        "trash-cli",
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
        "man-db",
        "man-pages",
        "bash-completion",
        "smartmontools",
        "xdg-utils",
        "tesseract-data-ind",
        "rustup",
        "go",
        "uv",
        "fnm",
        "pnpm",
        "mold",
        "strace",
        "hyperfine",
    ],
}

REQUIRED_SERVICES = [
    "NetworkManager.service",
    "NetworkManager-dispatcher.service",
    "plasmalogin.service",
    "apparmor.service",
    "auditd.service",
    "nftables.service",
    "systemd-resolved.service",
    "dnscrypt-proxy.service",
]

OPTIONAL_SERVICES = [
    "bluetooth.service",
    "power-profiles-daemon.service",
    "systemd-timesyncd.service",
    "systemd-oomd.service",
    "systemd-boot-update.service",
    "fstrim.timer",
    "paccache.timer",
    "snapper-timeline.timer",
    "snapper-cleanup.timer",
    "btrfs-scrub@-.timer",
]

MASKED_SERVICES = [
    "systemd-tpm2-setup.service",
    "systemd-tpm2-setup-early.service",
]


def target_path(relative: str) -> str:
    return f"{TARGET}/{relative.lstrip('/')}"


def write(relative: str, content: str, mode: int = 0o644) -> None:
    ui.write_text(target_path(relative), content, mode=mode)


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


def refresh_iso_keyring() -> None:
    """Refresh archlinux-keyring on the live ISO to prevent PGP failures on older ISOs."""
    ui.info("Refreshing archlinux-keyring in live environment")
    try:
        ui.run(["pacman", "-Sy", "--noconfirm", "--needed", "archlinux-keyring"])
    except ui.CommandError as exc:
        ui.warn(f"Could not refresh archlinux-keyring (continuing): {exc}")


def install_base() -> None:
    pacstrap(BASE_PACKAGES, "base & filesystem stack", init_keyring=True)


def install_phases(additional_packages: list[str] | None = None) -> None:
    chroot(["pacman", "-Sy", "--noconfirm"])
    for label, packages in INSTALL_PHASES.items():
        ui.info(f"Installing phase: {label} ({len(packages)} packages)")
        chroot(["pacman", "-S", "--noconfirm", "--needed", *packages])
    if additional_packages:
        ui.info(
            f"Installing phase: Additional Applications ({len(additional_packages)} packages)"
        )
        chroot(["pacman", "-S", "--noconfirm", "--needed", *additional_packages])


def copy_mirrorlist() -> None:
    ui.info("Copying the selected mirrorlist into the new system")
    ui.copy("/etc/pacman.d/mirrorlist", target_path("/etc/pacman.d/mirrorlist"))


def configure_pacman(*, enable_multilib: bool = False) -> None:
    ui.info("Patching /etc/pacman.conf (targeted line edits)")
    ui.patch_file(
        target_path("/etc/pacman.conf"),
        lambda text: patcher.patch_pacman_conf(text, enable_multilib=enable_multilib),
    )
    extra = " + [multilib]" if enable_multilib else ""
    ui.ok(f"pacman.conf patched (Color, ILoveCandy, CheckSpace, VerbosePkgLists, ParallelDownloads{extra})")


def configure_locale(hostname: str, timezone: str = TIMEZONE) -> None:
    ui.info(f"Configuring locale, timezone ({timezone}) and hostname ({hostname})")
    ui.patch_file(
        target_path("/etc/locale.gen"),
        lambda text: patcher.patch_line(
            text, r"^#?\s*en_US\.UTF-8\s+UTF-8\s*$", "en_US.UTF-8 UTF-8"
        ),
        default_if_missing=configs.LOCALE_GEN,
    )
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


def create_user(username: str, user_password: str, root_password: str) -> None:
    ui.info(f"Creating user {username} (wheel) with separate root & user passwords")
    chroot(["useradd", "-m", "-G", "wheel", "-s", DEFAULT_SHELL, "--", username])
    chroot(
        ["chpasswd"],
        input_data=f"{username}:{user_password}\nroot:{root_password}\n",
    )
    write("/etc/sudoers.d/10-wheel", configs.SUDOERS_WHEEL, mode=0o440)
    write("/etc/sudoers.d/20-umask", configs.SUDOERS_UMASK, mode=0o440)

    if not ui.DRY_RUN:
        sudoers = Path(target_path("/etc/sudoers"))
        if sudoers.exists():
            text = sudoers.read_text(encoding="utf-8")
            if "@includedir /etc/sudoers.d" not in text:
                ui.write_text(sudoers, "@includedir /etc/sudoers.d\n", append=True)
    ui.ok(f"User {username} and root credentials configured")


def setup_snapper() -> None:
    ui.info("Configuring snapper for root and home with @snapshots subvolume")
    snapshots_dir = target_path("/.snapshots")
    ui.run(["umount", snapshots_dir], check=False)
    if not ui.DRY_RUN:
        if os.path.ismount(snapshots_dir):
            raise ui.ArchsetError(
                f"Failed to unmount {snapshots_dir} before snapper setup."
            )
        if os.path.isdir(snapshots_dir):
            os.rmdir(snapshots_dir)

    chroot(["snapper", "--no-dbus", "-c", "root", "create-config", "/"])
    chroot(["btrfs", "subvolume", "delete", "/.snapshots"], check=False)
    ui.mkdir(snapshots_dir)

    mapper = f"/dev/mapper/{disk.LUKS_NAME}"
    ui.run(
        [
            "mount",
            "-o",
            f"subvol=@snapshots,{disk.MOUNT_OPTS}",
            mapper,
            snapshots_dir,
        ]
    )
    chroot(["chmod", "750", "/.snapshots"])

    config_home = target_path("/etc/snapper/configs/home")
    if ui.DRY_RUN or not os.path.exists(config_home):
        chroot(["snapper", "--no-dbus", "-c", "home", "create-config", "/home"])

    for name in ("root", "home"):
        ui.patch_file(
            target_path(f"/etc/snapper/configs/{name}"),
            patcher.patch_snapper_config,
        )

    ui.ok("snapper configs patched (root & home)")


def enable_services() -> None:
    ui.info("Enabling required/optional services and masking TPM2 setup units")
    for service in REQUIRED_SERVICES:
        chroot(["systemctl", "enable", service])
    for service in OPTIONAL_SERVICES:
        try:
            chroot(["systemctl", "enable", service])
        except ui.CommandError as exc:
            ui.warn(f"Could not enable {service}: {exc}")
    for service in MASKED_SERVICES:
        chroot(["systemctl", "mask", service], check=False)
    ui.ok("Services enabled and TPM2 units masked")


def inject_system_configs() -> None:
    ui.info("Injecting drop-ins, nftables ruleset, and targeted system config patches")
    for src_rel, dst_abs, mode in configs.SYSTEM_STATIC_FILES:
        write(dst_abs, configs.load_file(src_rel), mode=mode)

    # Targeted line-patching on upstream-owned config files (preserving defaults/comments)
    ui.patch_file(
        target_path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml"),
        patcher.patch_dnscrypt_toml,
    )
    ui.patch_file(
        target_path("/etc/conf.d/pacman-contrib"),
        lambda text: patcher.patch_conf_kv(text, "PACCACHE_ARGS", '"-k2"'),
        default_if_missing='PACCACHE_ARGS="-k2"\n',
    )
    ui.patch_file(
        target_path("/etc/conf.d/wireless-regdom"),
        lambda text: patcher.patch_conf_kv(text, "WIRELESS_REGDOM", '"ID"'),
        default_if_missing='WIRELESS_REGDOM="ID"\n',
    )
    ui.patch_file(
        target_path("/etc/apparmor/parser.conf"),
        patcher.patch_apparmor_parser_conf,
    )
    ui.patch_file(
        target_path("/etc/login.defs"),
        patcher.patch_login_defs,
    )
    ui.patch_file(
        target_path("/etc/pam.d/system-auth"),
        patcher.patch_pam_system_auth,
    )

    ui.ok("System drop-ins, nftables, and line-patched configs applied")


def setup_bootloader(luks_uuid: str) -> None:
    ui.info("Configuring systemd-boot + UKI (mkinitcpio drop-in: systemd + sd-encrypt)")
    # Drop-in override: never overwrite upstream /etc/mkinitcpio.conf
    write(
        configs.MKINITCPIO_DROPIN_DST,
        configs.load_file(configs.MKINITCPIO_DROPIN_SRC),
        mode=0o644,
    )
    # Modular kernel command-line drop-ins read by mkinitcpio UKI builder
    write("/etc/cmdline.d/10-root.conf", configs.cmdline_root(luks_uuid), mode=0o644)
    write(
        configs.CMDLINE_SECURITY_DST,
        configs.load_file(configs.CMDLINE_SECURITY_SRC),
        mode=0o644,
    )
    write(
        configs.CMDLINE_BOOT_UI_DST,
        configs.load_file(configs.CMDLINE_BOOT_UI_SRC),
        mode=0o644,
    )

    # Ensure stale /etc/kernel/cmdline does not shadow /etc/cmdline.d/*.conf
    if not ui.DRY_RUN:
        Path(target_path("/etc/kernel/cmdline")).unlink(missing_ok=True)

    # Targeted line-patch on /etc/mkinitcpio.d/linux.preset (preserves comments)
    ui.patch_file(
        target_path("/etc/mkinitcpio.d/linux.preset"),
        lambda text: patcher.patch_linux_preset(text, fallback=True),
    )

    ui.mkdir(target_path("/boot/EFI/Linux"))

    try:
        chroot(["bootctl", "--variables=yes", "install"])
    except ui.CommandError as exc:
        ui.warn(f"bootctl with EFI variables failed; retrying without them: {exc}")
        try:
            chroot(["bootctl", "--variables=no", "install"])
        except ui.CommandError as exc2:
            ui.warn(f"bootctl without EFI variables failed; retrying plainly: {exc2}")
            chroot(["bootctl", "install"])

    ui.patch_file(
        target_path("/boot/loader/loader.conf"),
        patcher.patch_loader_conf,
        default_if_missing=configs.LOADER_CONF,
    )
    chroot(["mkinitcpio", "-P"])

    if not ui.DRY_RUN:
        for leftover in (
            target_path("/boot/initramfs-linux.img"),
            target_path("/boot/initramfs-linux-fallback.img"),
        ):
            try:
                Path(leftover).unlink(missing_ok=True)
            except OSError as exc:
                ui.warn(f"Could not remove leftover {leftover}: {exc}")

    ui.ok("systemd-boot installed and sd-encrypt UKI built")


def inject_user_configs(username: str, hostname: str) -> None:
    ui.info(
        f"Injecting dotfiles (zsh, kitty, KDE, GTK, fontconfig) and cloning nvim for {username}"
    )
    home = f"/home/{username}"

    for src_rel, home_rel, mode in configs.USER_STATIC_FILES:
        write(f"{home}/{home_rel}", configs.load_file(src_rel), mode=mode)

    chroot(["ln", "-sfn", ".config/zsh/.zshenv", f"{home}/.zshenv"])

    for rel_dir in (
        ".config/zsh/plugin",
        ".cache/zsh",
        ".local/state/zsh",
        ".local/state/python",
        "archset",
    ):
        ui.mkdir(target_path(f"{home}/{rel_dir}"))

    # Clone full public Neovim config (already includes sudoedit.lua); fallback if offline
    nvim_dir = f"{home}/.config/nvim"
    if ui.DRY_RUN or not Path(target_path(nvim_dir)).exists():
        try:
            chroot(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    configs.NVIM_REPO_URL,
                    nvim_dir,
                ],
                timeout=90,
            )
            ui.ok(f"Cloned Neovim config from {configs.NVIM_REPO_URL}")
        except ui.CommandError as exc:
            ui.warn(
                f"Could not clone {configs.NVIM_REPO_URL}; writing fallback sudoedit.lua: {exc}"
            )
            write(f"{nvim_dir}/sudoedit.lua", configs.NVIM_SUDOEDIT_LUA)

    # Install fzf-tab plugin into ~/.config/zsh/plugin/fzf-tab
    fzf_tab_dir = f"{home}/.config/zsh/plugin/fzf-tab"
    if ui.DRY_RUN or not Path(target_path(fzf_tab_dir)).exists():
        try:
            chroot(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    configs.FZF_TAB_REPO_URL,
                    fzf_tab_dir,
                ],
                timeout=60,
            )
        except ui.CommandError as exc:
            ui.warn(f"Could not clone fzf-tab (continuing without it): {exc}")

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
    ui.ok("User dotfiles and desktop appearance applied")


def finalize_dns_symlink() -> None:
    """Point /etc/resolv.conf to systemd-resolved stub AFTER all chroot network ops finish."""
    ui.info("Finalizing /etc/resolv.conf symlink for systemd-resolved")
    chroot(["ln", "-sf", "/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf"])
    ui.ok("/etc/resolv.conf symlinked to stub-resolv.conf")


def verify(username: str) -> None:
    ui.info("Verifying the installation")
    if ui.DRY_RUN:
        ui.warn("Dry run enabled; verification skipped")
        return

    home = f"{TARGET}/home/{username}"
    required = {
        target_path("/etc/fstab"): "fstab",
        target_path(configs.MKINITCPIO_DROPIN_DST): "mkinitcpio sd-encrypt drop-in",
        target_path("/etc/cmdline.d/10-root.conf"): "root LUKS cmdline drop-in",
        target_path(configs.CMDLINE_SECURITY_DST): "security cmdline drop-in",
        target_path(configs.CMDLINE_BOOT_UI_DST): "quiet boot UI & no-TPM2 cmdline drop-in",
        target_path("/boot/EFI/Linux/arch-linux.efi"): "default unified kernel image",
        target_path("/boot/loader/loader.conf"): "systemd-boot loader.conf",
        target_path("/etc/snapper/configs/root"): "snapper root config",
        target_path("/etc/nftables.conf"): "nftables configuration",
        target_path("/etc/sysctl.d/99-knsfd.conf"): "sysctl hardening config",
        target_path("/etc/sudoers.d/20-umask"): "sudoers 0022 umask override",
        target_path("/etc/systemd/resolved.conf.d/10-dnscrypt.conf"): "resolved dnscrypt drop-in",
        target_path("/etc/NetworkManager/dispatcher.d/10-enforce-no-ipv6.sh"): "NM IPv6 disable hook",
        f"{home}/.zshenv": "zsh .zshenv symlink",
        f"{home}/.config/zsh/.zshenv": "zsh XDG .zshenv",
        f"{home}/.config/zsh/.zshrc": "zsh XDG .zshrc",
        f"{home}/.config/environment.d/10-env.conf": "systemd user environment config",
        f"{home}/.config/nvim/sudoedit.lua": "neovim sudoedit config",
        f"{home}/.local/share/cargo/config.toml": "cargo mold config",
        f"{home}/.config/git/config": "XDG git configuration",
        f"{home}/.config/kitty/kitty.conf": "kitty configuration",
        f"{home}/.config/kdeglobals": "KDE globals & theme",
        f"{home}/.local/share/color-schemes/BreezeDarkMod.colors": "BreezeDarkMod color scheme",
        f"{home}/.config/starship.toml": "starship configuration",
    }
    missing = [label for path, label in required.items() if not os.path.exists(path)]
    if missing:
        raise ui.ArchsetError(
            "Installation verification failed; missing: " + ", ".join(missing)
        )

    fstab = Path(target_path("/etc/fstab")).read_text(encoding="utf-8")
    if "subvol=/@" not in fstab:
        raise ui.ArchsetError("fstab does not reference the root btrfs subvolume.")

    root_cmd = Path(target_path("/etc/cmdline.d/10-root.conf")).read_text(encoding="utf-8")
    if "rd.luks.name=" not in root_cmd:
        raise ui.ArchsetError("10-root.conf does not contain rd.luks.name= for sd-encrypt.")

    # AppArmor v4 unix-chkpwd requires /etc/shadow & /etc/gshadow to be readable by root
    # and never world-accessible (allows 0600, 0400, or 0640; blocks 0000 and world-readable).
    for shadow_rel in ("/etc/shadow", "/etc/gshadow"):
        shadow_path = Path(target_path(shadow_rel))
        if not shadow_path.exists():
            raise ui.ArchsetError(
                f"Installation verification failed; missing: {shadow_rel}"
            )
        mode = shadow_path.stat().st_mode & 0o777
        if (mode & 0o400) == 0 or (mode & 0o007) != 0:
            raise ui.ArchsetError(
                f"{shadow_rel} has unsafe mode {oct(mode)} (must be root-readable and not world-accessible)."
            )

    shell = chroot(["getent", "passwd", username], check=False).stdout.strip()
    if DEFAULT_SHELL not in shell:
        raise ui.ArchsetError(f"Default shell for {username} is not zsh.")

    ui.ok("Installation verified")


def export_logs(log_path: str | Path | None, username: str) -> None:
    """Copy raw command+output log into /var/log/archset and /home/<user>/archset/setup.log."""
    if ui.DRY_RUN or log_path is None:
        return
    src = Path(log_path)
    if not src.exists():
        return

    sys_dest = Path(target_path("/var/log/archset"))
    user_dest_dir = Path(target_path(f"/home/{username}/archset"))
    user_dest_file = user_dest_dir / "setup.log"

    try:
        sys_dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, sys_dest / src.name)
        os.chmod(sys_dest / src.name, 0o600)
        ui.ok(f"System installation log copied to {sys_dest / src.name}")
    except OSError as exc:
        ui.warn(f"Could not copy log to {sys_dest}: {exc}")

    try:
        user_dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, user_dest_file)
        os.chmod(user_dest_file, 0o600)
        chroot(["chown", "-R", f"{username}:{username}", f"/home/{username}/archset"], check=False)
        ui.ok(f"Raw user log exported to /home/{username}/archset/setup.log (0600)")
    except OSError as exc:
        ui.warn(f"Could not export user log to {user_dest_file}: {exc}")
