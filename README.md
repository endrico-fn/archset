# archset

Opinionated, single-purpose Arch Linux installer written in Python (stdlib only). Run it from the official Arch ISO.

> [!WARNING]
> archset **erases the entire target disk**. It is tuned for one specific setup and Intel hardware (microcode, i915, Realtek rtw88). Read the code and use `--dry-run` first.

## Target layout

| Item | Value |
|---|---|
| Firmware | UEFI only |
| Partitions | 1 GiB ESP (`/boot`) + LUKS2 (argon2id) |
| Filesystem | btrfs: `@`, `@home`, `@log`, `@pkg`, `@snapshots`, `@swap` (zstd:3) |
| Boot | systemd-boot + unified kernel image (UKI) |
| Swap | zram (zstd) + 4 GiB btrfs swapfile |
| Desktop | KDE Plasma (Wayland), kitty, zsh + starship + fzf-tab |
| Security | AppArmor, nftables, hardened sysctl, snapper |
| Dev | rustup, go, uv, fnm, pnpm, neovim (XDG-compliant paths) |

## Usage (from the Arch ISO, as root)

```bash
pacman -Sy --needed git
git clone https://github.com/endrico-fn/archset.git
cd archset
python archset.py --dry-run     # inspect every command first
python archset.py               # real install
```

Options: `--disk /dev/nvme0n1`, `--hostname`, `--username`, `--timezone` (default `Asia/Jakarta`), `--log-dir`, `--dry-run`, `--force`.

Logs are written to `/var/log/archset` (passwords are never logged) and copied into the new system.

## Layout of the source

- `archset.py` – entry point and flow
- `disk.py` – partitioning, LUKS2, btrfs, mounts
- `system.py` – pacstrap, services, bootloader, config injection
- `configs.py` – config file contents (zsh, kitty, sysctl, nftables, ...)
- `ui.py` – prompts, logging, subprocess helpers

## License

MIT
