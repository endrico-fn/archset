# ~/.config/zsh/.zshrc — Interactive Zsh configuration
# Documentation: https://wiki.archlinux.org/title/zsh

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
# Safe core operations per Arch Linux sysadmin best practices
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
alias nvid='neovide'

# ---------- Syntax Highlighting (Must be loaded last) ----------
source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
