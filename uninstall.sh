#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_ROOT="${SYSAI_INSTALL_ROOT:-$HOME/.local}"
LIB_DIR="$INSTALL_ROOT/lib/sysai-terminal"
BIN_PATH="$INSTALL_ROOT/bin/sysai"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sysai"

case "$LIB_DIR" in
  "$INSTALL_ROOT"/lib/sysai-terminal) ;;
  *) printf '%s\n' "Refusing unexpected uninstall path: $LIB_DIR" >&2; exit 1 ;;
esac

for managed_path in "$INSTALL_ROOT" "$INSTALL_ROOT/lib" "$LIB_DIR" "$INSTALL_ROOT/bin" "$BIN_PATH"; do
  if [ -L "$managed_path" ]; then
    printf '%s\n' "Refusing symlinked managed path: $managed_path" >&2
    exit 1
  fi
done

if [ -x "$PROJECT_DIR/bin/sysai" ] && [ -d "$PROJECT_DIR/src/sysai" ]; then
  "$PROJECT_DIR/bin/sysai" stop >/dev/null 2>&1 || true
fi
rm -f -- "$BIN_PATH"
rm -rf -- "$LIB_DIR"
printf '%s\n' "SysAI program files removed."
printf '%s\n' "Configuration was preserved at $CONFIG_DIR"
printf '%s\n' "Remove that directory manually if you also want to delete your settings."
