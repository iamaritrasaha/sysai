# Loaded only inside a SysAI-owned child Zsh. This file is not added to .zshrc.
autoload -Uz add-zsh-hook
typeset -g SYSAI_COMMAND_ACTIVE=0

function _sysai_preexec() {
  SYSAI_COMMAND_ACTIVE=1
  command "$SYSAI_EXECUTABLE" __hook begin "$1" "$PWD" >/dev/null 2>&1
}

function _sysai_precmd() {
  local command_status=$?
  if (( SYSAI_COMMAND_ACTIVE )); then
    SYSAI_COMMAND_ACTIVE=0
    command "$SYSAI_EXECUTABLE" __hook complete "$command_status" "$PWD" >/dev/null 2>&1
  fi
  return $command_status
}

add-zsh-hook preexec _sysai_preexec
add-zsh-hook precmd _sysai_precmd

# A session-only wrapper lets `sysai stop` return to the parent shell cleanly.
function sysai() {
  if [[ "$1" == "stop" ]]; then
    command "$SYSAI_EXECUTABLE" __session stop
    local stop_status=$?
    if (( stop_status == 0 )); then
      builtin exit 0
    fi
    return $stop_status
  fi
  command "$SYSAI_EXECUTABLE" "$@"
}

