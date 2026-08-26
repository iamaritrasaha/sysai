#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_ROOT="${SYSAI_INSTALL_ROOT:-$HOME/.local}"
LIB_DIR="$INSTALL_ROOT/lib/sysai-terminal"
BIN_DIR="$INSTALL_ROOT/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sysai"

case "$LIB_DIR" in
  "$INSTALL_ROOT"/lib/sysai-terminal) ;;
  *) printf '%s\n' "Refusing unexpected install path: $LIB_DIR" >&2; exit 1 ;;
esac

CONFIG_ROOT=${XDG_CONFIG_HOME:-$HOME/.config}
for managed_path in "$INSTALL_ROOT" "$INSTALL_ROOT/lib" "$LIB_DIR" "$BIN_DIR" "$BIN_DIR/sysai" "$CONFIG_ROOT" "$CONFIG_DIR"; do
  if [ -L "$managed_path" ]; then
    printf '%s\n' "Refusing symlinked managed path: $managed_path" >&2
    exit 1
  fi
done

if [ -x /bin/bash ]; then
  BASH_BIN=/bin/bash
else
  BASH_BIN=$(command -v bash 2>/dev/null || true)
fi
if [ -z "$BASH_BIN" ]; then
  printf '%s\n' "SysAI requires Bash 5.x, but no bash executable was found." >&2
  exit 1
fi
BASH_MAJOR=$("$BASH_BIN" --version 2>/dev/null | sed -n '1s/^GNU bash, version \([0-9][0-9]*\).*/\1/p')
if [ -n "$BASH_MAJOR" ] && [ "$BASH_MAJOR" -lt 5 ]; then
  printf '%s\n' "SysAI requires Bash 5.x; found version $BASH_MAJOR at $BASH_BIN." >&2
  exit 1
fi

mkdir -p "$INSTALL_ROOT/lib" "$BIN_DIR" "$CONFIG_DIR"
STAGE_DIR=$(mktemp -d "$INSTALL_ROOT/lib/.sysai-terminal.XXXXXX")
STAGE_BIN=$(mktemp "$BIN_DIR/.sysai.XXXXXX")
trap 'rm -rf -- "$STAGE_DIR"; rm -f -- "$STAGE_BIN"' EXIT HUP INT TERM
mkdir "$STAGE_DIR/sysai"
cp "$PROJECT_DIR"/src/sysai/*.py "$STAGE_DIR/sysai/"
cp "$PROJECT_DIR"/src/sysai/*.md "$PROJECT_DIR"/src/sysai/*.bash "$STAGE_DIR/sysai/"
cp "$PROJECT_DIR/bin/sysai" "$STAGE_BIN"
chmod 755 "$STAGE_DIR" "$STAGE_DIR/sysai"
chmod 644 "$STAGE_DIR/sysai"/*
chmod 755 "$STAGE_BIN"

rm -rf -- "$LIB_DIR"
mv -- "$STAGE_DIR" "$LIB_DIR"
mv -f -- "$STAGE_BIN" "$BIN_DIR/sysai"

if [ ! -e "$CONFIG_DIR/config.toml" ]; then
  cp "$PROJECT_DIR/config/default.toml" "$CONFIG_DIR/config.toml"
  chmod 600 "$CONFIG_DIR/config.toml"
fi
if [ ! -e "$CONFIG_DIR/env" ]; then
  cp "$PROJECT_DIR/config/env.example" "$CONFIG_DIR/env"
  chmod 600 "$CONFIG_DIR/env"
fi

printf '%s\n' "SysAI installed at $BIN_DIR/sysai"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf '%s\n' "Add $BIN_DIR to PATH if it is not already available." ;;
esac
printf '%s\n' "No changes were made to ~/.bashrc, ~/.profile, or ~/.bash_profile."
