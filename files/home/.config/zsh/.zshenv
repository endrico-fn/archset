# ~/.zshenv — Environment variables for all zsh shells (interactive and non-interactive)
# Reference: https://wiki.archlinux.org/title/Zsh#Startup/Shutdown_files

# ---------- Standar XDG Base Directory ----------
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_STATE_HOME="$HOME/.local/state"

# ---------- Zsh XDG ----------
export ZDOTDIR="$XDG_CONFIG_HOME/zsh"

# ---------- Toolchain & Aplikasi (XDG) ----------
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
