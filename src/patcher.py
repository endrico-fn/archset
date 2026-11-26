#!/usr/bin/env python3
"""Targeted, idempotent line-patching helpers for upstream Arch config files.

archset follows a strict configuration injection hierarchy:
1. Drop-in directories (``/etc/*.d/*.conf``) whenever supported by the package.
2. Targeted line-patching via this module for files without drop-in support
   (pacman.conf, dnscrypt-proxy.toml, linux.preset, snapper configs, conf.d,
   apparmor/parser.conf, login.defs, pam.d/system-auth).
3. Full-file writes only for ``/etc/nftables.conf`` and user-owned dotfiles.
"""

from __future__ import annotations

import re


def patch_line(
    text: str,
    pattern: str,
    replacement: str,
    *,
    anchor: str | None = None,
    append_if_missing: bool = True,
) -> str:
    """Replace the first matching line, or insert after ``anchor`` / append."""
    new_text, count = re.subn(
        pattern,
        lambda _m: replacement,
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count > 0:
        return new_text

    if anchor is not None:
        anchor_match = re.search(anchor, text, flags=re.MULTILINE)
        if anchor_match is not None:
            insert_at = anchor_match.end()
            rest = text[insert_at:]
            if rest.startswith("\n"):
                return text[:insert_at] + "\n" + replacement + rest
            return text[:insert_at] + "\n" + replacement + "\n" + rest

    if not append_if_missing:
        return text

    if text and not text.endswith("\n"):
        text += "\n"
    return text + replacement + "\n"


def patch_conf_kv(text: str, key: str, value: str) -> str:
    """Set ``key=value`` in a shell-style ``/etc/conf.d/*`` file."""
    escaped = re.escape(key)
    return patch_line(
        text,
        rf"^#?\s*{escaped}\s*=.*$",
        f"{key}={value}",
        append_if_missing=True,
    )


def patch_pacman_conf(text: str, *, enable_multilib: bool = False) -> str:
    """Enable standard QoL options (and optionally [multilib]) in pacman.conf."""
    text = patch_line(text, r"^#?\s*Color\s*$", "Color", anchor=r"^\[options\]\s*$")
    text = patch_line(text, r"^#?\s*ILoveCandy\s*$", "ILoveCandy", anchor=r"^Color\s*$")
    text = patch_line(text, r"^#?\s*CheckSpace\s*$", "CheckSpace", anchor=r"^ILoveCandy\s*$")
    text = patch_line(
        text, r"^#?\s*VerbosePkgLists\s*$", "VerbosePkgLists", anchor=r"^CheckSpace\s*$"
    )
    text = patch_line(
        text,
        r"^#?\s*ParallelDownloads\s*=.*$",
        "ParallelDownloads = 5",
        anchor=r"^VerbosePkgLists\s*$",
    )

    if enable_multilib:
        # Uncomment standard Arch [multilib] block if commented, without duplicating.
        if not re.search(r"^\[multilib\]\s*$", text, flags=re.MULTILINE):
            commented_block = re.compile(
                r"^#\[multilib\][ \t]*\n#Include[ \t]*=[ \t]*/etc/pacman\.d/mirrorlist[ \t]*$",
                flags=re.MULTILINE,
            )
            if commented_block.search(text):
                text = commented_block.sub(
                    "[multilib]\nInclude = /etc/pacman.d/mirrorlist",
                    text,
                    count=1,
                )
            else:
                if text and not text.endswith("\n"):
                    text += "\n"
                text += "\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n"

    return text


def patch_dnscrypt_toml(text: str) -> str:
    """Patch only required keys in upstream /etc/dnscrypt-proxy/dnscrypt-proxy.toml."""
    updates = [
        (
            r"^#?\s*server_names\s*=.*$",
            "server_names = ['quad9-doh-ip4-port443-filter-pri', 'mullvad-doh']",
        ),
        (
            r"^#?\s*listen_addresses\s*=.*$",
            "listen_addresses = ['127.0.0.1:5300']",
        ),
        (r"^#?\s*ipv6_servers\s*=.*$", "ipv6_servers = false"),
        (r"^#?\s*require_nofilter\s*=.*$", "require_nofilter = false"),
        (r"^#?\s*use_syslog\s*=.*$", "use_syslog = true"),
        (
            r"^#?\s*bootstrap_resolvers\s*=.*$",
            "bootstrap_resolvers = ['9.9.9.9:53', '149.112.112.112:53']",
        ),
        (r"^#?\s*ignore_system_dns\s*=.*$", "ignore_system_dns = true"),
        (r"^#?\s*netprobe_address\s*=.*$", "netprobe_address = '9.9.9.9:53'"),
        (r"^#?\s*block_ipv6\s*=.*$", "block_ipv6 = true"),
    ]
    for pattern, replacement in updates:
        text = patch_line(text, pattern, replacement, append_if_missing=True)
    return text


def patch_linux_preset(text: str, *, fallback: bool = True) -> str:
    """Switch /etc/mkinitcpio.d/linux.preset to UKI mode via targeted line edits."""
    presets_val = "PRESETS=('default' 'fallback')" if fallback else "PRESETS=('default')"
    text = patch_line(text, r"^#?\s*PRESETS=.*$", presets_val)

    # Comment out legacy initramfs images so only UKIs are produced.
    text = re.sub(
        r"^(default_image=.*)$",
        r"#\1",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^(fallback_image=.*)$",
        r"#\1",
        text,
        count=1,
        flags=re.MULTILINE,
    )

    text = patch_line(
        text,
        r"^#?\s*default_uki=.*$",
        'default_uki="/boot/EFI/Linux/arch-linux.efi"',
        anchor=r"^#?default_image=.*$",
    )
    text = patch_line(
        text,
        r"^#?\s*default_options=.*$",
        'default_options=""',
        anchor=r"^default_uki=.*$",
    )

    if fallback:
        text = patch_line(
            text,
            r"^#?\s*fallback_uki=.*$",
            'fallback_uki="/boot/EFI/Linux/arch-linux-fallback.efi"',
            anchor=r"^#?fallback_image=.*$",
        )
        text = patch_line(
            text,
            r"^#?\s*fallback_options=.*$",
            'fallback_options="-S autodetect,sd-archrelius"',
            anchor=r"^fallback_uki=.*$",
        )

    return text


def patch_snapper_config(text: str) -> str:
    """Tune snapper retention limits and wheel access without rewriting the file."""
    updates = {
        "ALLOW_GROUPS": '"wheel"',
        "NUMBER_MIN_AGE": '"3600"',
        "NUMBER_LIMIT": '"15"',
        "NUMBER_LIMIT_IMPORTANT": '"10"',
        "TIMELINE_MIN_AGE": '"3600"',
        "TIMELINE_LIMIT_HOURLY": '"5"',
        "TIMELINE_LIMIT_DAILY": '"7"',
        "TIMELINE_LIMIT_WEEKLY": '"0"',
        "TIMELINE_LIMIT_MONTHLY": '"0"',
        "TIMELINE_LIMIT_QUARTERLY": '"0"',
        "TIMELINE_LIMIT_YEARLY": '"0"',
        "EMPTY_PRE_POST_MIN_AGE": '"3600"',
    }
    for key, value in updates.items():
        text = patch_conf_kv(text, key, value)
    return text


def patch_loader_conf(text: str) -> str:
    """Ensure hardened systemd-boot /boot/loader/loader.conf directives."""
    text = patch_line(text, r"^#?\s*timeout\s+.*$", "timeout 3")
    text = patch_line(text, r"^#?\s*console-mode\s+.*$", "console-mode max")
    text = patch_line(text, r"^#?\s*editor\s+.*$", "editor no")
    return text


def patch_apparmor_parser_conf(text: str) -> str:
    """Enable AppArmor binary policy caching and fast compression."""
    text = patch_line(
        text,
        r"^#?[ \t]*write-cache[ \t]*$",
        "write-cache",
        append_if_missing=True,
    )
    text = patch_line(
        text,
        r"^#?[ \t]*Optimize=compress-fast[ \t]*$",
        "Optimize=compress-fast",
        append_if_missing=True,
    )
    return text


def patch_login_defs(text: str, *, umask: str = "027") -> str:
    """Tighten default UMASK in /etc/login.defs without touching prose comments."""
    return patch_line(
        text,
        r"^#?[ \t]*UMASK[ \t]+[0-7]{3,4}[ \t]*(?:#.*)?$",
        f"UMASK\t\t{umask}",
        append_if_missing=True,
    )


def patch_pam_system_auth(text: str) -> str:
    """Remove standalone `nullok` from active pam_unix.so lines in /etc/pam.d/system-auth."""
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if not stripped.startswith("#") and "pam_unix.so" in line:
            line = re.sub(r"[ \t]+nullok(?=[ \t\r\n]|$)", "", line)
        out_lines.append(line)
    return "".join(out_lines)
