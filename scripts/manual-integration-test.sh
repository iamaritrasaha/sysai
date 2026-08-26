#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUN_DIR=$(mktemp -d)
trap 'rm -rf -- "$RUN_DIR"' EXIT HUP INT TERM
mkdir -p "$RUN_DIR/sysai"
cp "$PROJECT_DIR/config/default.toml" "$RUN_DIR/sysai/config.toml"

printf '%s\n' "Starting a real PTY-backed SysAI/Bash integration test."
printf '%s\n' "It runs one success, one exit-7 failure, then 'sysai explain', then exits."
printf '%s\n' "The failure and explain invoke local Qwen; if the configured model exposes"
printf '%s\n' "reasoning, a live 'SysAI . thinking' box streams before each answer."
(
  # SysAI intentionally flushes pending terminal input while switching to raw mode.
  sleep 2
  printf 'printf "integration-success\\n"\n'
  sleep 1
  printf 'sh -c '\''printf "integration-failure\\n" >&2; exit 7'\''\n'
  sleep 30
  printf 'sysai explain\n'
  sleep 30
  printf 'sysai stop\n'
) | XDG_CONFIG_HOME="$RUN_DIR" script -qfec "$PROJECT_DIR/bin/sysai" /dev/null
