# archset

Opinionated, hardened Arch Linux installer written in Python (stdlib only), strictly engineered for **Intel CPU + Intel GPU (`i915` & `xe`)** hardware. Run it from the official Arch ISO, or invoke `--additional` / `--export-backup` anytime on an installed system.

> [!WARNING]
> Full installation and `--uninstall` modes **cryptographically erase the entire target disk** (`cryptsetup erase` + 16 MiB head/tail zeroing + `blkdiscard`). Hardware is strictly validated for Intel (`intel-ucode`, dynamic `i915` / `xe` early KMS, `intel-media-driver`, `vulkan-intel`, `libvpl` + `vpl-gpu-rt`, `sof-firmware`, `thermald`). Hybrid NVIDIA dGPUs are automatically blacklisted (`nouveau`/`nova_core`) under `lockdown=integrity`. Read the code and run `--dry-run` first.

## Target Architecture (v2.0 — Intel-Only)

| Item | Value |
|---|---|
| Firmware | UEFI only (no Secure Boot, no TPM2) |
| Hardware | **Strict Intel-only** (`GenuineIntel` CPU + `0x8086` GPU; `--allow-vm` for QEMU testing), dynamic `i915` vs `xe` DRM driver detection, `intel-media-driver` + `vulkan-intel` + `libvpl` + `vpl-gpu-rt`, `sof-firmware` + `thermald`, accurate `rtw88` driver detection, adaptive HiDPI console font (`ter-v32n` >= 2560px) |
| Mirrors | HTTPS **Singapore & Indonesia** via `reflector` (with official CDN fallback) |
| Partitions | Adaptive ESP (`2 GiB` on >= 64 GiB disks, `1 GiB` on smaller disks; `/boot`, `fmask=0177,dmask=0077,nodev,nosuid,noexec`) + LUKS2 (`argon2id`, passphrase-only) |
| Filesystem | Btrfs: `@`, `@home`, `@log`, `@pkg`, `@snapshots`, `@home_snapshots`, `@swap` (`zstd:3`, wheel-accessible Snapper) |
| Boot & UKI | `systemd-boot` (`editor no`, `systemd-boot-update.service`) + UKI via `/etc/mkinitcpio.conf.d/10-archset.conf` (`systemd` + `sd-encrypt` + `sd-archrelius` `#64beaf` Quantum animated `ARCHRELIUS` TUI customizable via `/etc/archrelius.conf` with `--preview` mode & `password_feedback`) + `/etc/cmdline.d/` (`10-root`, `20-security`, `30-boot-ui`) |
| Swap | `zram` (`min(ram, 8192)`, `zstd`, `pri=100`, `swappiness=80`) + 4 GiB Btrfs fallback swapfile (`pri=-2`) |
| Network & DNS | IPv6 permanently disabled (`sysctl` + `nftables` + `nm.conf` + NM dispatcher), `dnscrypt-proxy` (`quad9-doh-ip4-port443-filter-pri` + `mullvad-doh`) + `systemd-resolved`, `wireguard-tools` + `importwgp` |
| Desktop | KDE Plasma (Wayland, `BreezeDarkMod`, accent `#64beaf`, `xdg-desktop-portal-kde`/`gtk`), GTK3/4 dark, `fontconfig`, `kitty`, `zsh` + `starship` + `fzf-tab` |
| Editor & Dev | `git clone https://github.com/endrico-fn/nvim.git` (fallback `sudoedit.lua`), `rustup` (`mold`), `go`, `uv`, `fnm`, `pnpm` (XDG-compliant) |
| Post-Install & Flush | Interactive `[ 1 ] Enter arch-chroot`, `[ 2 ] Stay in Live ISO`, `* [ 3 ] Poweroff System`, `[ 4 ] Reboot System` backed by a 6-stage SSD hardware commit (`btrfs filesystem sync` -> `sync` -> `swapoff` -> `umount -R` -> `cryptsetup close` -> `blockdev --flushbufs`) |
| Security | AppArmor (`write-cache` + `Optimize=compress-fast`), `auditd` + `30-archset.rules`, sandboxed `wpa_supplicant.service`, kernel cmdline hardening (`audit=1`, `lockdown=integrity`, `init_on_alloc=1`, `slab_nomerge`, `vsyscall=none`, `randomize_kstack_offset=on`), `UMASK 027` + `sudoers` `0022`, `pam_unix` without `nullok`, core dumps disabled, rare protocol/FireWire blacklist, targeted USB HID nosuspend udev rule (`S0ix`-safe), hardened `nftables` (`0600`), `snapper`, `arch-audit`, `fcntl.flock` anti-double-run guard |

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

### Export Migration Backup Before Switching Devices (non-destructive)
```bash
sudo python3 archset.py --export-backup
```

### Decommission / Uninstall Disk & Clean UEFI Entries (from Arch ISO)
```bash
python3 archset.py --uninstall
```

### Preview ARCHRELIUS LUKS TUI Live on Installed System
```bash
/usr/local/lib/systemd/archrelius-askpw --preview
```

### Run Automated Tests (stdlib `unittest`)
```bash
python3 -m unittest discover -s tests -v
```

## Layout

- `archset.py` – CLI entry point, preflight/ISO orchestration, interactive review, post-install `[ 1 ]..[ 4 ]` menu & power actions
- `src/hardware.py` – strict Intel-only `sysfs`/`/proc` detection (`i915` vs `xe`, HiDPI DRM modes, `rtw88`, `sof`/HDA, hybrid NVIDIA guard)
- `src/disk.py` – disk discovery, cryptographic LUKS2 erase + `blkdiscard`, adaptive ESP, Btrfs subvolumes, 6-stage SSD flush
- `src/system.py` – SG/ID HTTPS mirror selection, retry-backed phased installs, Snapper (`@snapshots` & `@home_snapshots`), UKI boot, dotfiles, verification
- `src/additional.py` – multi-group `[ 1 ]..[ 5 ]` selector, live `pacman -Si` download size table, and standalone `--additional` mode
- `src/maintenance.py` – Live-ISO `--uninstall` (crypto-erase + `efibootmgr` cleanup) and `--export-backup` (`0600` migration bundle)
- `src/patcher.py` – targeted, idempotent line-patching helpers (preserves upstream defaults/comments)
- `src/configs.py` – static file registry (`files/`) and dynamic config generators
- `src/ui.py` – `[ N ]` bracket menus, streaming subprocess runner with live timer & retries, `InstanceLock`, secret-redacting logger
- `files/` – clean mirror of `/etc` drop-ins, `archrelius-askpw.c`, `sd-archrelius`, `nftables.conf`, `importwgp`, and user dotfiles
- `tests/` – automated stdlib `unittest` suite (`test_archset.py`, `test_patcher.py`, `test_importwgp.py`)

## License

MIT
