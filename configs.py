#!/usr/bin/env python3
"""Static file registry and dynamic config generators for archset."""

from __future__ import annotations

from pathlib import Path

FILES_DIR = Path(__file__).resolve().parent / "files"

NVIM_REPO_URL = "https://github.com/endrico-fn/nvim.git"
FZF_TAB_REPO_URL = "https://github.com/Aloxaf/fzf-tab.git"

# (relative path under files/, destination path in target root, chmod mode)
SYSTEM_STATIC_FILES: list[tuple[str, str, int]] = [
    ("etc/nftables.conf", "/etc/nftables.conf", 0o600),
    ("etc/sysctl.d/99-knsfd.conf", "/etc/sysctl.d/99-knsfd.conf", 0o644),
    ("etc/NetworkManager/conf.d/nm.conf", "/etc/NetworkManager/conf.d/nm.conf", 0o644),
    (
        "etc/NetworkManager/dispatcher.d/10-enforce-no-ipv6.sh",
        "/etc/NetworkManager/dispatcher.d/10-enforce-no-ipv6.sh",
        0o755,
    ),
    (
        "etc/systemd/resolved.conf.d/10-dnscrypt.conf",
        "/etc/systemd/resolved.conf.d/10-dnscrypt.conf",
        0o644,
    ),
    (
        "etc/systemd/journald.conf.d/00-journal-size.conf",
        "/etc/systemd/journald.conf.d/00-journal-size.conf",
        0o644,
    ),
    (
        "etc/systemd/coredump.conf.d/00-limit.conf",
        "/etc/systemd/coredump.conf.d/00-limit.conf",
        0o644,
    ),
    (
        "etc/systemd/system/wpa_supplicant.service.d/10-hardening.conf",
        "/etc/systemd/system/wpa_supplicant.service.d/10-hardening.conf",
        0o644,
    ),
    ("etc/systemd/zram-generator.conf", "/etc/systemd/zram-generator.conf", 0o644),
    ("etc/security/limits.d/10-coredump.conf", "/etc/security/limits.d/10-coredump.conf", 0o644),
    ("etc/audit/rules.d/30-archset.rules", "/etc/audit/rules.d/30-archset.rules", 0o640),
    ("etc/modprobe.d/i915.conf", "/etc/modprobe.d/i915.conf", 0o644),
    ("etc/modprobe.d/audio_powersave.conf", "/etc/modprobe.d/audio_powersave.conf", 0o644),
    ("etc/modprobe.d/rtw88_powersave.conf", "/etc/modprobe.d/rtw88_powersave.conf", 0o644),
    ("etc/modprobe.d/usb_powersave.conf", "/etc/modprobe.d/usb_powersave.conf", 0o644),
    ("etc/modprobe.d/blacklist-unused.conf", "/etc/modprobe.d/blacklist-unused.conf", 0o644),
    ("etc/initcpio/install/sd-archrelius", "/etc/initcpio/install/sd-archrelius", 0o644),
    ("usr/local/src/archrelius-askpw.c", "/usr/local/src/archrelius-askpw.c", 0o644),
    ("usr/local/bin/importwgp", "/usr/local/bin/importwgp", 0o755),
]

ASKPW_SRC_DST = "/usr/local/src/archrelius-askpw.c"
ASKPW_BIN_DST = "/usr/local/lib/systemd/archrelius-askpw"
ASKPW_CC_ARGS: list[str] = [
    "gcc",
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-fPIE",
    "-pie",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=3",
    "-Wl,-z,relro,-z,now",
    ASKPW_SRC_DST,
    "-o",
    ASKPW_BIN_DST,
]

# Bootloader / UKI drop-ins (written in setup_bootloader)
MKINITCPIO_DROPIN_SRC = "etc/mkinitcpio.conf.d/10-archset.conf"
MKINITCPIO_DROPIN_DST = "/etc/mkinitcpio.conf.d/10-archset.conf"
CMDLINE_SECURITY_SRC = "etc/cmdline.d/20-security.conf"
CMDLINE_SECURITY_DST = "/etc/cmdline.d/20-security.conf"
CMDLINE_BOOT_UI_SRC = "etc/cmdline.d/30-boot-ui.conf"
CMDLINE_BOOT_UI_DST = "/etc/cmdline.d/30-boot-ui.conf"

# (relative path under files/, relative path under /home/<user>/, chmod mode)
USER_STATIC_FILES: list[tuple[str, str, int]] = [
    ("home/.config/kitty/kitty.conf", ".config/kitty/kitty.conf", 0o644),
    ("home/.config/zsh/.zshenv", ".config/zsh/.zshenv", 0o644),
    ("home/.config/zsh/.zshrc", ".config/zsh/.zshrc", 0o644),
    ("home/.config/environment.d/10-env.conf", ".config/environment.d/10-env.conf", 0o644),
    ("home/.config/fontconfig/fonts.conf", ".config/fontconfig/fonts.conf", 0o644),
    ("home/.config/gtk-3.0/settings.ini", ".config/gtk-3.0/settings.ini", 0o644),
    ("home/.config/gtk-4.0/settings.ini", ".config/gtk-4.0/settings.ini", 0o644),
    ("home/.config/kdeglobals", ".config/kdeglobals", 0o644),
    ("home/.config/breezerc", ".config/breezerc", 0o644),
    ("home/.config/kwinrc", ".config/kwinrc", 0o644),
    ("home/.config/kcminputrc", ".config/kcminputrc", 0o644),
    ("home/.config/kscreenlockerrc", ".config/kscreenlockerrc", 0o644),
    ("home/.config/ksmserverrc", ".config/ksmserverrc", 0o644),
    ("home/.config/baloofilerc", ".config/baloofilerc", 0o644),
    ("home/.config/klipperrc", ".config/klipperrc", 0o644),
    ("home/.config/dolphinrc", ".config/dolphinrc", 0o644),
    (
        "home/.local/share/color-schemes/BreezeDarkMod.colors",
        ".local/share/color-schemes/BreezeDarkMod.colors",
        0o644,
    ),
    ("home/.local/share/cargo/config.toml", ".local/share/cargo/config.toml", 0o644),
]

MIRRORLIST_FALLBACK = """\
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
"""

LOCALE_GEN = "en_US.UTF-8 UTF-8\n"
LOCALE_CONF = "LANG=en_US.UTF-8\n"
VCONSOLE_CONF = "KEYMAP=us\nFONT=default8x16\n"
SUDOERS_WHEEL = "%wheel ALL=(ALL:ALL) ALL\n"
SUDOERS_UMASK = "Defaults umask = 0022\nDefaults umask_override\n"

LOADER_CONF = """\
timeout 3
console-mode max
editor no
"""

STARSHIP_FALLBACK = """\
"$schema" = 'https://starship.rs/config-schema.json'

add_newline = false
format = "$username$hostname$directory$git_branch$git_status$cmd_duration$line_break$character"

[character]
success_symbol = "[>](bold green)"
error_symbol = "[>](bold red)"
"""

# Fallback only: used if cloning https://github.com/endrico-fn/nvim.git fails.
NVIM_SUDOEDIT_LUA = """\
-- ~/.config/nvim/sudoedit.lua
-- Minimal, isolated, hardened Neovim configuration for sudoedit (no plugins, no state leaks)

local opt = vim.opt

opt.undofile = false
opt.swapfile = false
opt.backup = false
opt.writebackup = false
opt.shada = ""
opt.shadafile = "NONE"
opt.modeline = false
opt.exrc = false
opt.secure = true
opt.loadplugins = false
opt.clipboard = ""

opt.number = true
opt.relativenumber = false
opt.cursorline = true
opt.tabstop = 4
opt.softtabstop = 4
opt.shiftwidth = 4
opt.expandtab = true
opt.wrap = true
opt.signcolumn = "no"
opt.termguicolors = true
opt.laststatus = 2
opt.statusline = " %f %m%r %= %l/%L:%c "

vim.cmd("syntax on")
vim.cmd("filetype plugin indent on")

vim.keymap.set("n", "<Esc>", "<cmd>nohlsearch<cr>", { silent = true, desc = "Clear highlight" })
"""

GITCONFIG_TEMPLATE = """\
[user]
\tname = __NAME__
\temail = __EMAIL__
[init]
\tdefaultBranch = main
[core]
\teditor = nvim
\tpager = less -FRX
[color]
\tui = auto
[fetch]
\tprune = true
[rerere]
\tenabled = true
[diff]
\tcolorMoved = zebra
[push]
\tautoSetupRemote = true
[pull]
\trebase = true
[rebase]
\tautoStash = true
[alias]
\tst = status
\tco = checkout
\tsw = switch
\tbr = branch
\tci = commit
\tunstage = reset HEAD --
\tlast = log -1 HEAD --stat
\tlg = log --graph --abbrev-commit --decorate --format=format:'%C(bold blue)%h%C(reset) - %C(bold green)(%ar)%C(reset) %C(white)%s%C(reset) %C(dim white)- %an%C(reset)%C(auto)%d%C(reset)' --all
"""


def file_path(rel_path: str) -> Path:
    return FILES_DIR / rel_path.lstrip("/")


def load_file(rel_path: str) -> str:
    return file_path(rel_path).read_text(encoding="utf-8")


def cmdline_root(luks_uuid: str) -> str:
    """Kernel cmdline snippet for systemd + sd-encrypt (LUKS2 passphrase-only)."""
    return (
        f"rd.luks.name={luks_uuid}=root "
        f"rd.luks.options={luks_uuid}=discard "
        "root=/dev/mapper/root rootflags=subvol=@ rw rootfstype=btrfs\n"
    )


def hosts(hostname: str) -> str:
    return (
        "127.0.0.1\tlocalhost\n"
        f"127.0.1.1\t{hostname}.localdomain\t{hostname}\n"
    )


def gitconfig(name: str, email: str) -> str:
    return GITCONFIG_TEMPLATE.replace("__NAME__", name).replace("__EMAIL__", email)
