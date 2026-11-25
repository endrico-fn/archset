# archset

Opinionated, hardened Arch Linux installer written in Python (stdlib only). Run it from the official Arch ISO, or invoke `--additional` anytime on an installed system to add optional desktop applications.

> [!WARNING]
> Full installation mode **erases the entire target disk**. Hardware drivers/microcode (`intel-ucode` / `amd-ucode`, `i915` / `amdgpu` / VM `mesa`, Realtek `rtw88`) are auto-detected via `sysfs`, while `lockdown=integrity` targets in-tree signed kernel modules (no unsigned DKMS). Read the code and run `--dry-run` first.

## Target Architecture (v2.0)

| Item | Value |
|---|---|
| Firmware | UEFI only (no Secure Boot, no TPM2) |
| Hardware | Auto-detected CPU microcode (`intel-ucode` / `amd-ucode` / VM skip), GPU stack (`i915` + `intel-media-driver` + `vulkan-intel` + `libvpl` on Intel, `amdgpu` + `vulkan-radeon` on AMD, `mesa` in VMs), conditional `rtw88_powersave.conf` |
| Partitions | 1 GiB ESP (`/boot`, `fmask=0177,dmask=0077,nodev,nosuid,noexec`) + LUKS2 (`argon2id`, passphrase-only) |
| Filesystem | Btrfs: `@`, `@home`, `@log`, `@pkg`, `@snapshots`, `@swap` (`zstd:3`) |
| Boot & UKI | `systemd-boot` (`editor no`, `systemd-boot-update.service`) + UKI via `/etc/mkinitcpio.conf.d/10-archset.conf` (`systemd` + `sd-encrypt` + `sd-archrelius` 4-mode `Tab`-switchable `#64beaf` animated `ARCHRELIUS` TUI; fallback UKI keeps stock `systemd` prompt) + `/etc/cmdline.d/` (`10-root`, `20-security`, `30-boot-ui` quiet boot + `systemd.tpm2_measured_os=0`) |
| Swap | `zram` (`zstd`) + 4 GiB Btrfs swapfile |
| Network & DNS | IPv6 permanently disabled (`sysctl` + `nftables` + NM dispatcher), `dnscrypt-proxy` (`mullvad-doh` + `quad9-doh-ip4-port443-filter-pri`) + `systemd-resolved`, `wireguard-tools` + `importwgp` |
| Desktop | KDE Plasma (Wayland, `BreezeDarkMod`, accent `#64beaf`, `ShadowNone`, lightweight KWin, Baloo disabled), GTK3/4 dark, `fontconfig`, `kitty`, `zsh` + `starship` + `fzf-tab` |
| Editor & Dev | `git clone https://github.com/endrico-fn/nvim.git` (fallback `sudoedit.lua`), `rustup` (`mold`), `go`, `uv`, `fnm`, `pnpm` (XDG-compliant) |
| Security | AppArmor (`write-cache` + `Optimize=compress-fast`), `auditd` + `30-archset.rules` (root-only `0700` logs), sandboxed `wpa_supplicant.service`, kernel cmdline hardening (`audit=1`, `lockdown=integrity`, `init_on_alloc=1`, `slab_nomerge`, `vsyscall=none`, `randomize_kstack_offset=on`), `UMASK 027` + `sudoers` `0022` override, `pam_unix` without `nullok`, core dumps disabled (`coredump.conf.d` + `limits.d`), rare protocol/FireWire module blacklist, `/etc/shadow` safe mode check, hardened `nftables` (`0600`, Strong Host Model, DNS anti-bypass), `sysctl` (`unprivileged_bpf_disabled=1`, `mmap_rnd_bits=32`, `ptrace_scope=1`), `snapper`, `arch-audit`, `dosfstools`, separate `root` & `user` passwords, `fcntl.flock` anti-double-run guard |
| Raw Logs | Exported with mode `0600` (secrets redacted) to `/var/log/archset/` and `/home/$USER/archset/setup.log` |

## Usage

### Full Install (from Arch ISO as root)
```bash
pacman -Sy --needed git
git clone https://github.com/endrico-fn/archset.git
cd archset
python3 archset.py --dry-run
python3 archset.py
```

### Install Additional Applications Later (non-destructive, on installed system)
```bash
sudo python3 archset.py --additional
```

### Run Automated Tests (stdlib `unittest`)
```bash
python3 -m unittest discover -s tests -v
```

## Layout

- `archset.py` – CLI entry point, lock guard, input prompts, and orchestration
- `hardware.py` – stdlib `sysfs`/`/proc` auto-detection for CPU microcode, GPU KMS/Vulkan, VM, and Realtek Wi-Fi
- `disk.py` – disk discovery, LUKS2, Btrfs subvolumes, fstab normalization, mounts
- `system.py` – phased package installs, drop-in/line-patch config injection, UKI boot, dotfiles, log export
- `additional.py` – multi-group selector, live `pacman -Si` download size table, and standalone `--additional` mode
- `patcher.py` – targeted, idempotent line-patching helpers (preserves upstream defaults/comments)
- `configs.py` – static file registry (`files/`) and dynamic config generators
- `ui.py` – TUI prompts, package tables, `InstanceLock`, secret-redacting raw logger, subprocess runner
- `files/` – clean mirror of `/etc` drop-ins, `nftables.conf`, `importwgp`, and user dotfiles
- `tests/` – automated stdlib `unittest` suite

## License

MIT
