# Loaded only inside a SysAI-owned child Bash, from a temporary session
# rcfile. This file is never appended to ~/.bashrc, ~/.profile, or
# ~/.bash_profile: everything it installs lives and dies with the session.

# Sourcing this twice in one shell would double every hook event.
if [ -n "${__sysai_integration_loaded:-}" ]; then
  return 0
fi
__sysai_integration_loaded=1

# A top-level command is in flight (begin was reported, complete was not).
__sysai_command_active=0
# Armed by __sysai_arm as the last step of PROMPT_COMMAND, cleared by the
# first DEBUG firing after it. Bash raises DEBUG before every simple
# command; this flag is what collapses that stream into exactly one
# "command started" event per line entered at the prompt.
__sysai_armed=0
__sysai_last_entered=""
__sysai_last_history_number=""

__sysai_hook() {
  command "$SYSAI_EXECUTABLE" __hook "$@" >/dev/null 2>&1
}

# Restores the exit status and `$_` that the interrupted shell had, so
# SysAI's bookkeeping stays invisible to the user's prompt and scripts.
__sysai_restore() {
  return "${1:-0}"
}

# Recovers the whole line the user entered rather than the single simple
# command Bash is about to run. `history 1` holds the complete top-level
# entry: pipelines, `&&`/`||` lists, and multi-line compound commands are
# one entry, so `dmesg | grep amdgpu` stays one SysAI record.
__sysai_capture_entered_command() {
  local entry number="" text=""
  entry=$(HISTTIMEFORMAT='' builtin history 1 2>/dev/null)
  while [[ $entry == [[:space:]]* ]]; do entry=${entry#?}; done
  while [[ $entry == [0-9]* ]]; do number+=${entry:0:1}; entry=${entry#?}; done
  if [[ -n $number ]]; then
    # `history` marks a modified entry with a trailing `*`.
    [[ $entry == '*'* ]] && entry=${entry#?}
    while [[ $entry == [[:space:]]* ]]; do entry=${entry#?}; done
    text=$entry
  fi
  if [[ -z $text ]]; then
    # History is unavailable or empty; the simple command is all we have.
    text=${BASH_COMMAND:-}
  elif [[ $number == "$__sysai_last_history_number" && $text != "${BASH_COMMAND:-}"* ]]; then
    # The line was kept out of history (HISTCONTROL=ignorespace, HISTIGNORE),
    # so `history 1` still holds an older, unrelated entry. Reporting a stale
    # command would be worse than reporting only the simple command.
    text=${BASH_COMMAND:-}
  else
    __sysai_last_history_number=$number
  fi
  __sysai_last_entered=$text
}

__sysai_debug_trap() {
  local status=$? previous_argument=${1:-}
  if (( BASH_SUBSHELL != 0 )) || [[ -n ${COMP_LINE:-} ]]; then
    # Subshells and programmable completion are not user commands.
    __sysai_restore "$status" "$previous_argument"
    return 0
  fi
  # Under `set -o functrace` the trap is inherited into functions; SysAI's
  # own helpers must never report themselves as a user command.
  case "${FUNCNAME[1]:-}" in
    __sysai_*|sysai)
      __sysai_restore "$status" "$previous_argument"
      return 0
      ;;
  esac
  # SysAI's own PROMPT_COMMAND entries. These run with the trap still armed
  # whenever the user just pressed Enter on an empty line.
  case "${BASH_COMMAND:-}" in
    __sysai_precmd*|__sysai_arm*)
      __sysai_restore "$status" "$previous_argument"
      return 0
      ;;
  esac
  if ! __sysai_prompt_command_installed; then
    # Something replaced PROMPT_COMMAND outright, so the completion and
    # arming hooks are gone and only the DEBUG trap is left to notice.
    # Reinstall and resynchronise instead of silently stopping. This firing
    # is deliberately not reported: it may be the replacement
    # PROMPT_COMMAND itself rather than anything the user typed.
    __sysai_install_prompt_command
    __sysai_armed=1
    __sysai_restore "$status" "$previous_argument"
    return 0
  fi
  if (( __sysai_armed == 0 )); then
    __sysai_restore "$status" "$previous_argument"
    return 0
  fi
  __sysai_armed=0
  __sysai_capture_entered_command
  if [[ -n $__sysai_last_entered ]]; then
    __sysai_command_active=1
    __sysai_hook begin "$__sysai_last_entered" "$PWD"
  fi
  __sysai_restore "$status" "$previous_argument"
  return 0
}

# Runs first in PROMPT_COMMAND: the command has finished and `$?` is its
# real top-level exit status.
__sysai_precmd() {
  local status=$?
  # Disarm for the rest of the prompt sequence. A real command already
  # disarmed the trap when it started; doing it here as well means that on
  # an empty prompt line the user's own PROMPT_COMMAND entries, which run
  # after this one, can never be mistaken for a typed command.
  __sysai_armed=0
  if (( __sysai_command_active )); then
    __sysai_command_active=0
    __sysai_hook complete "$status" "$PWD"
  fi
  return "$status"
}

# Runs last in PROMPT_COMMAND, immediately before Bash draws the prompt and
# reads the next line, so the next DEBUG firing is the user's command.
__sysai_arm() {
  local status=$?
  __sysai_prompt_command_installed || __sysai_install_prompt_command
  __sysai_armed=1
  return "$status"
}

__sysai_prompt_command_is_array() {
  local declaration
  declaration=$(declare -p PROMPT_COMMAND 2>/dev/null) || return 1
  [[ $declaration == declare\ -*a* ]]
}

__sysai_prompt_command_installed() {
  # Cheap on the hot path: element 0 of an array, or the first line of a
  # string, is SysAI's precmd whenever SysAI installed it.
  [[ ${PROMPT_COMMAND[0]:-} == __sysai_precmd* ]]
}

# Preserves whatever PROMPT_COMMAND the user already had, in its existing
# form: an array stays an array, a string stays a string, and an unset
# PROMPT_COMMAND becomes a string. SysAI's own entries are stripped first,
# so re-running this can never register the hooks twice.
__sysai_install_prompt_command() {
  local entry kept=()
  if __sysai_prompt_command_is_array; then
    for entry in "${PROMPT_COMMAND[@]}"; do
      case "$entry" in
        __sysai_precmd|__sysai_arm) ;;
        *) kept+=("$entry") ;;
      esac
    done
    PROMPT_COMMAND=(__sysai_precmd ${kept[@]+"${kept[@]}"} __sysai_arm)
    return 0
  fi
  entry=${PROMPT_COMMAND:-}
  entry=${entry#__sysai_precmd}
  entry=${entry#$'\n'}
  entry=${entry%__sysai_arm}
  entry=${entry%$'\n'}
  if [ -n "$entry" ]; then
    PROMPT_COMMAND="__sysai_precmd
${entry}
__sysai_arm"
  else
    PROMPT_COMMAND="__sysai_precmd
__sysai_arm"
  fi
  return 0
}

# A session-only wrapper so `sysai stop` returns to the parent shell
# cleanly. Every other form goes straight to the real SysAI executable.
sysai() {
  if [ "${1:-}" = "stop" ]; then
    command "$SYSAI_EXECUTABLE" __session stop
    local stop_status=$?
    if [ "$stop_status" -eq 0 ]; then
      builtin exit 0
    fi
    return "$stop_status"
  fi
  command "$SYSAI_EXECUTABLE" "$@"
}

__sysai_install_prompt_command

# SysAI needs the DEBUG trap to know when a command starts. A pre-existing
# DEBUG trap cannot be chained onto reliably, because a saved trap body can
# only be re-run by evaluating its text, and SysAI never evaluates stored
# shell text. The documented policy is therefore to take the trap over for
# the session and say so out loud rather than replace it silently: the
# user's ~/.bashrc is untouched and any new shell gets the original back.
#
# `trap -p DEBUG` reports nothing once a sourced file is running, so the
# SysAI session rcfile captures any pre-existing trap into
# __sysai_previous_debug_trap at its own top level before sourcing this file.
if [ -n "${__sysai_previous_debug_trap:-}" ]; then
  SYSAI_REPLACED_DEBUG_TRAP=$__sysai_previous_debug_trap
  printf '%s\n' \
    "SysAI: a DEBUG trap from your shell startup was replaced for this session only." \
    "SysAI: ~/.bashrc is unchanged and the original trap is active again in any new shell." \
    "SysAI: the replaced definition is kept in \$SYSAI_REPLACED_DEBUG_TRAP." >&2
fi
unset __sysai_previous_debug_trap
trap '__sysai_debug_trap "$_"' DEBUG
