#!/usr/bin/env python3
"""Static file contents injected by archset into the new system."""

from __future__ import annotations

KITTY_CONF = """\
# ~/.config/kitty/kitty.conf
# Reference: https://sw.kovidgoyal.net/kitty/conf/

# Fonts
font_family      JetBrainsMono Nerd Font Mono
font_size        9.0

# Cursor & Mouse
cursor_shape     beam
url_color        #56b88d
copy_on_select   clipboard

# Performance & Audio (Wayland-optimized)
input_delay      1
enable_audio_bell no
scrollback_lines 10000
strip_trailing_spaces smart
confirm_os_window_close 0

# Layout & Window Splits
enabled_layouts        splits:split_axis=horizontal,stack
window_border_width    1pt
window_padding_width   6
placement_strategy     center
inactive_text_alpha    0.75

# Tab Bar
tab_bar_style          powerline
tab_powerline_style    slanted
tab_title_template     "{index}: {title[title.rfind('/')+1:]}"
active_tab_font_style  bold

# Color Scheme (Neutral Deep Dark Grey & Accent #56b88d)
background              #141414
foreground              #e0e0e0

selection_background    #56b88d
selection_foreground    #141414

cursor                  #56b88d
cursor_text_color       #141414

active_border_color     #56b88d
inactive_border_color   #262626
bell_border_color       #e5c07b

active_tab_background   #56b88d
active_tab_foreground   #141414
inactive_tab_background #1f1f1f
inactive_tab_foreground #888888
tab_bar_background      #0d0d0d

# 16-Color ANSI Palette
color0  #1f1f1f
color8  #525252
color1  #e06c75
color9  #f07178
color2  #56b88d
color10 #6ee7b7
color3  #e5c07b
color11 #f0d192
color4  #61afef
color12 #7cc0f7
color5  #c678dd
color13 #d492e8
color6  #56b6c2
color14 #6bcad6
color7  #cccccc
color15 #ffffff

# Keybindings (Splits & Navigation)
map alt+shift+v launch --location=vsplit --cwd=current
map alt+shift+s launch --location=hsplit --cwd=current
map alt+shift+r layout_action rotate
map alt+shift+z toggle_layout stack

map alt+shift+h neighboring_window left
map alt+shift+j neighboring_window down
map alt+shift+k neighboring_window up
map alt+shift+l neighboring_window right

map ctrl+alt+h move_window left
map ctrl+alt+j move_window down
map ctrl+alt+k move_window up
map ctrl+alt+l move_window right

map ctrl+alt+left  resize_window narrower 3
map ctrl+alt+right resize_window wider 3
map ctrl+alt+up    resize_window taller 3
map ctrl+alt+down  resize_window shorter 3
map ctrl+alt+0     resize_window reset
"""

ZSHENV = r"""# ~/.config/zsh/.zshenv (symlinked from ~/.zshenv)
# Environment variables for all zsh shells (interactive and non-interactive)
# Reference: https://wiki.archlinux.org/title/Zsh#Startup/Shutdown_files

# ---------- XDG Base Directory ----------
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_STATE_HOME="$HOME/.local/state"

# ---------- Zsh XDG ----------
export ZDOTDIR="$XDG_CONFIG_HOME/zsh"

# ---------- Toolchains & Applications (XDG) ----------
export CARGO_HOME="$XDG_DATA_HOME/cargo"
export RUSTUP_HOME="$XDG_DATA_HOME/rustup"
export GOPATH="$XDG_DATA_HOME/go"
export GOMODCACHE="$XDG_CACHE_HOME/go/mod"
export GOTOOLCHAIN="local"
export NPM_CONFIG_USERCONFIG="$XDG_CONFIG_HOME/npm/npmrc"
export NPM_CONFIG_CACHE="$XDG_CACHE_HOME/npm"
export PYTHON_HISTORY="$XDG_STATE_HOME/python/history"
export PYTHONPYCACHEPREFIX="$XDG_CACHE_HOME/python"
export NODE_REPL_HISTORY="$XDG_STATE_HOME/node_repl_history"
export ANDROID_USER_HOME="$XDG_DATA_HOME/android"
export PNPM_HOME="$XDG_DATA_HOME/pnpm"

# ---------- Editor & Pager ----------
export EDITOR='nvim'
export VISUAL='nvim'
export SUDO_EDITOR="nvim --noplugin -u $XDG_CONFIG_HOME/nvim/sudoedit.lua"
export PAGER='less -R'
export MANPAGER='less -R'
export BAT_THEME='ansi'
export LESS='-R'

# ---------- PATH ----------
typeset -U path PATH
path=(
  "$CARGO_HOME/bin"
  "$GOPATH/bin"
  "$PNPM_HOME/bin"
  "$HOME/.local/bin"
  "$XDG_DATA_HOME/fnm/aliases/default/bin"
  $path
)
export PATH
"""

ZSHRC = r"""# ~/.config/zsh/.zshrc — Interactive Zsh configuration
# Documentation: https://wiki.archlinux.org/title/Zsh

# ---------- Interactive Prompt Options ----------
export SPROMPT="zsh: correct '%R' to '%r' [nyae]? "

# ---------- History (XDG State) ----------
mkdir -p "$XDG_STATE_HOME/zsh"
HISTFILE="$XDG_STATE_HOME/zsh/history"
HISTSIZE=50000
SAVEHIST=50000
setopt SHARE_HISTORY
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_SAVE_NO_DUPS
setopt HIST_FIND_NO_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_REDUCE_BLANKS
setopt EXTENDED_HISTORY
setopt HIST_NO_STORE

# ---------- Shell Options ----------
setopt AUTO_CD
setopt AUTO_PUSHD
setopt PUSHD_IGNORE_DUPS
setopt PUSHD_SILENT
setopt EXTENDED_GLOB
setopt INTERACTIVE_COMMENTS
setopt NO_BEEP
setopt CORRECT
setopt COMPLETE_IN_WORD
setopt ALWAYS_TO_END
setopt AUTO_MENU
setopt AUTO_LIST
setopt LIST_PACKED

# ---------- Completion System (XDG Cache) ----------
(( $+commands[dircolors] )) && eval "$(dircolors -b)"

autoload -Uz compinit
mkdir -p "$XDG_CACHE_HOME/zsh"
() {
  local zcompdump="$XDG_CACHE_HOME/zsh/zcompdump-$ZSH_VERSION"
  local -a stale=($zcompdump(Nmh+24))
  if [[ ! -f "$zcompdump" ]] || (( $#stale )); then
    compinit -d "$zcompdump"
  else
    compinit -C -d "$zcompdump"
  fi
  { [[ -f "$zcompdump.zwc" && "$zcompdump" -ot "$zcompdump.zwc" ]] || zcompile "$zcompdump" } &!
}

zstyle ':completion:*' menu no
zstyle ':completion:*' matcher-list \
  'm:{a-zA-Z}={A-Za-z}' \
  'r:|[._-]=* r:|=*' \
  'l:|=* r:|=*'
zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"
zstyle ':completion:*' group-name ''
zstyle ':completion:*' verbose yes
zstyle ':completion:*:descriptions' format '[%d]'
zstyle ':completion:*:messages'     format '%F{purple}-- %d --%f'
zstyle ':completion:*:warnings'     format '%F{red}-- no matches found --%f'
zstyle ':completion:*:corrections'  format '%F{yellow}!- %d (errors: %e) -!%f'
zstyle ':completion:*' use-cache on
zstyle ':completion:*' cache-path "$XDG_CACHE_HOME/zsh/zcompcache"
zstyle ':completion:*' rehash true
zstyle ':completion:*:*:*:*:processes' command 'ps -u $USER -o pid,user,%cpu,%mem,command -w -w'
zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#) ([0-9a-z-]#)*=01;34=0=01'

# ---------- fzf-tab styles ----------
zstyle ':fzf-tab:complete:cd:*' fzf-preview 'eza -1 --color=always -- $realpath'
zstyle ':fzf-tab:complete:__zoxide_z:*' fzf-preview 'eza -1 --color=always -- $realpath'
zstyle ':fzf-tab:complete:(kill|ps):argument-rest' fzf-preview '[[ $group == "[process ID]" ]] && ps --pid=$word -o cmd --no-headers -w -w'
zstyle ':fzf-tab:complete:(kill|ps):argument-rest' fzf-flags --preview-window=down:3:wrap
zstyle ':fzf-tab:*' switch-group '<' '>'

# ---------- Keybindings ----------
bindkey -e

# Shift-Tab reverse completion
bindkey '^[[Z' reverse-menu-complete

# Word navigation (Ctrl+Arrows and Alt+Arrows)
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^[[1;3C' forward-word
bindkey '^[[1;3D' backward-word
bindkey '^[[5C' forward-word
bindkey '^[[5D' backward-word

# Line navigation (Home, End, Delete)
bindkey '^[[H' beginning-of-line
bindkey '^[OH' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^[OF' end-of-line
bindkey '^[[3~' delete-char

# History search with Arrow Up / Down
autoload -Uz up-line-or-beginning-search down-line-or-beginning-search
zle -N up-line-or-beginning-search
zle -N down-line-or-beginning-search
bindkey '^[[A' up-line-or-beginning-search
bindkey '^[[B' down-line-or-beginning-search
bindkey '^[OA' up-line-or-beginning-search
bindkey '^[OB' down-line-or-beginning-search

# ---------- fzf (must load before fzf-tab) ----------
[[ -r /usr/share/fzf/key-bindings.zsh ]] && source /usr/share/fzf/key-bindings.zsh

# ---------- fzf-tab (must load after compinit & fzf, before autosuggestions & syntax-highlighting) ----------
[[ -r "$ZDOTDIR/plugin/fzf-tab/fzf-tab.plugin.zsh" ]] && source "$ZDOTDIR/plugin/fzf-tab/fzf-tab.plugin.zsh"

# ---------- Autosuggestions ----------
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'
ZSH_AUTOSUGGEST_STRATEGY=(history completion)
bindkey '^ ' autosuggest-accept
source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh

# ---------- zoxide ----------
(( $+commands[zoxide] )) && eval "$(zoxide init zsh)"

# ---------- starship ----------
if [[ "$TERM" != "dumb" ]] && (( $+commands[starship] )); then
  eval "$(starship init zsh)"
fi

# ---------- fnm (Fast Node Manager) ----------
if (( $+commands[fnm] )); then
  eval "$(fnm env --shell zsh --use-on-cd)"
fi

# ---------- Aliases ----------
alias vim='nvim'
alias v='nvim'
alias rm='rm -I'
alias cp='cp -i'
alias mv='mv -i'
alias ln='ln -i'

# Modern CLI replacements
alias ls='eza --group-directories-first'
alias ll='eza -lah --group-directories-first --git'
alias la='eza -a --group-directories-first'
alias lt='eza --tree --level=2'
alias cat='bat --style=plain --paging=never'

# Arch Linux Package Management
alias pacup='sudo pacman -Syu'
alias pacin='sudo pacman -S'
alias pacrm='sudo pacman -Rns'
alias pacsearch='pacman -Ss'
alias pacinfo='pacman -Si'
alias orphans='pacman -Qdtq'
alias pacdiff='DIFFPROG="nvim --noplugin -u $XDG_CONFIG_HOME/nvim/sudoedit.lua -d" pacdiff -s'
alias pacclean='sudo pacman -Sc'
alias checkup='checkupdates'
alias hwipe=': >| "$HISTFILE" && exec zsh'

# ---------- Syntax Highlighting (Must be loaded last) ----------
source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
"""

ENV_D_CONF = """\
XDG_CONFIG_HOME=${HOME}/.config
XDG_CACHE_HOME=${HOME}/.cache
XDG_DATA_HOME=${HOME}/.local/share
XDG_STATE_HOME=${HOME}/.local/state
ZDOTDIR=${HOME}/.config/zsh
CARGO_HOME=${HOME}/.local/share/cargo
RUSTUP_HOME=${HOME}/.local/share/rustup
GOPATH=${HOME}/.local/share/go
GOMODCACHE=${HOME}/.cache/go/mod
GOTOOLCHAIN=local
NPM_CONFIG_USERCONFIG=${HOME}/.config/npm/npmrc
NPM_CONFIG_CACHE=${HOME}/.cache/npm
PNPM_HOME=${HOME}/.local/share/pnpm
PYTHON_HISTORY=${HOME}/.local/state/python/history
PYTHONPYCACHEPREFIX=${HOME}/.cache/python
NODE_REPL_HISTORY=${HOME}/.local/state/node_repl_history
ANDROID_USER_HOME=${HOME}/.local/share/android
"""

NVIM_SUDOEDIT_LUA = """\
-- ~/.config/nvim/sudoedit.lua
-- Minimal, isolated, hardened Neovim configuration for sudoedit (no plugins, no state leaks)

local opt = vim.opt

-- Data security & privacy
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

-- Basic editor usability
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

CARGO_CONFIG_TOML = """\
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
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


def gitconfig(name: str, email: str) -> str:
    return GITCONFIG_TEMPLATE.replace("__NAME__", name).replace("__EMAIL__", email)


STARSHIP_FALLBACK = """\
"$schema" = 'https://starship.rs/config-schema.json'

add_newline = false
format = "$username$hostname$directory$git_branch$git_status$cmd_duration$line_break$character"

[character]
success_symbol = "[>](bold green)"
error_symbol = "[>](bold red)"
"""

ZRAM_CONF = """\
[zram0]
compression-algorithm = zstd
"""

MIRRORLIST_FALLBACK = """\
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
"""

LOCALE_GEN = "en_US.UTF-8 UTF-8\n"

LOCALE_CONF = "LANG=en_US.UTF-8\n"

VCONSOLE_CONF = "KEYMAP=us\nFONT=default8x16\n"

MKINITCPIO_CONF = """\
MODULES=(i915)
BINARIES=()
FILES=()
HOOKS=(base udev keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems)
"""

UKI_PRESET = """\
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default' 'fallback')

default_uki="/boot/EFI/Linux/arch-linux.efi"
default_options="--splash /usr/share/systemd/bootctl/splash-arch.bmp"

fallback_uki="/boot/EFI/Linux/arch-linux-fallback.efi"
fallback_options="-S autodetect"
"""

LOADER_CONF = """\
timeout 3
console-mode max
editor no
"""

SUDOERS_WHEEL = "%wheel ALL=(ALL:ALL) ALL\n"


def hosts(hostname: str) -> str:
    return (
        "127.0.0.1\tlocalhost\n"
        "::1\t\tlocalhost\n"
        f"127.0.1.1\t{hostname}.localdomain\t{hostname}\n"
    )


SYSCTL_KNSFD = """\
# --- Virtual Memory & ZRAM Optimization ---
vm.swappiness = 180
vm.page-cluster = 0
vm.watermark_boost_factor = 0
vm.watermark_scale_factor = 125

# --- Desktop I/O Smoothness (Btrfs + LUKS) ---
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10

# --- Fileless Malware Defense (JIT & Container Friendly) ---
vm.memfd_noexec = 1

# --- VFS & Filesystem Integrity Protection ---
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# --- Kernel Surface & Memory Layout Hardening ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.io_uring_disabled = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 2
kernel.yama.ptrace_scope = 2

# --- Hardware Protection ---
dev.tty.ldisc_autoload = 0

# --- eBPF Subsystem Hardening ---
net.core.bpf_jit_harden = 2

# --- Network Robustness & Path MTU Discovery ---
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- TCP Performance & Congestion Control (BBR + FQ, Disable TFO Tracking) ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 0

# --- Network IPv4 Interface Security (Anti-Spoofing & Redirects) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.*.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.*.send_redirects = 0

net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.*.rp_filter = 2

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.*.accept_source_route = 0

# --- ARP Poisoning Defense ---
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.*.arp_ignore = 1

net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.*.arp_announce = 2

# --- Disable IPv6 Globally (Prevent VPN & WebRTC Leaks) ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
"""

NFTABLES_CONF = """\
#!/usr/bin/nft -f
# Simple & safe workstation firewall ruleset (IPv4/IPv6)

destroy table inet filter
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    # Early drop of invalid packets
    ct state invalid drop comment "early drop of invalid connections"

    # Accept established and related traffic
    ct state { established, related } accept comment "allow tracked connections"

    # Allow loopback traffic
    iif "lo" accept comment "allow from loopback"

    # Allow critical ICMPv4 PMTUD errors & rate-limited ping
    icmp type {
      destination-unreachable,
      time-exceeded,
      parameter-problem
    } accept comment "allow critical ICMPv4 PMTUD errors"
    icmp type echo-request limit rate 5/second burst 10 packets accept comment "allow rate-limited ping"
    icmp type echo-request counter drop comment "drop excessive ping floods"

    # Rate-limit rejected unicast packets
    pkttype host limit rate 10/second counter reject with icmpx type admin-prohibited
    counter
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
"""

NM_CONF = """\
[device-mac-randomization]
wifi.scan-rand-mac-address=yes

[connection-mac-randomization]
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable

[connection]
# 2 = Enable RFC 4941 and prefer temporary addresses for outbound connections
ipv6.ip6-privacy=2

# Do not leak machine hostname to DHCP servers
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false

# 2 = Disable Wi-Fi powersave for stability on Realtek adapters
wifi.powersave=2
"""

MODPROBE_I915 = """\
# Intel Graphics Power & Display Optimization
options i915 enable_fbc=1 fastboot=1 enable_guc=2
"""

MODPROBE_AUDIO = """\
# Intel High Definition Audio Power Saving
options snd_hda_intel power_save=1 power_save_controller=Y
"""

MODPROBE_RTW88 = """\
# Realtek rtw88 Wi-Fi Stability (disable deep LPS & PCIe ASPM)
options rtw88_core disable_lps_deep=y
options rtw88_pci disable_aspm=y
"""

MODPROBE_USB = """\
# Disable USB autosuspend for input/peripheral stability
options usbcore autosuspend=-1
"""

BLUETOOTH_MAIN_CONF = """\
[General]
AutoEnable=true
FastConnectable=true
Experimental=true
"""

WIRELESS_REGDOM_CONF = """\
WIRELESS_REGDOM="ID"
"""

KDE_GLOBALS_TERMINAL = """\
[General]
TerminalApplication=kitty
TerminalService=kitty.desktop
"""
