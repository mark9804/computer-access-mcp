#!/usr/bin/env bash
# Uninstall computer-history-mcp (and legacy computer-access-mcp):
#   1. Stop running daemon, stdio proxy, collector, and key-store processes.
#   2. Revoke all keys (macOS Keychain master keys, Windows DPAPI keys, admin tokens,
#      and MCP client lease tokens).
#   3. Delete both current (computer-history-mcp) and legacy (computer-access-mcp)
#      encrypted history stores, custom data directories, and runtime lock directories.
#   4. Uninstall global npm/pnpm links and remove local repo build artifacts.

set -euo pipefail

APP_NAMES=("computer-history-mcp" "computer-access-mcp")
KEYCHAIN_SERVICES=("com.computer-history.mcp" "com.computer-access.mcp")
KEY_FILENAMES=("admin.token" "auth-leases.json" "restart-resume.json" "master.key.dpapi")
BUILD_PATHS=(
  "dist"
  "native-bin"
  "native/macos/.build"
  "native/macos/collector/.build"
  "native/macos/contract/.build"
  "native/macos/key-store/.build"
  "fixtures/macos/app/.build"
  "native/windows/target"
)

DRY_RUN=0
ASSUME_YES=0
KEEP_BUILD=0
CUSTOM_DATA_DIRS=()
DATA_DIRS=()
LOCK_DIRS=()
TARGET_PIDS=()
TARGET_CMDS=()
WARNINGS=0

OS_NAME="$(uname -s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [options]

Stops running computer-history-mcp / computer-access-mcp processes, revokes all
encryption and authentication keys, deletes current and legacy encrypted stores,
and removes installed CLI links and local build outputs.

Options:
  -y, --yes             Skip interactive confirmation prompt
      --dry-run         Print planned actions without modifying anything
      --data-dir PATH   Also revoke keys and delete a custom data directory (repeatable)
      --keep-build      Keep local build outputs (dist/, native-bin/, native build dirs)
  -h, --help            Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -y|--yes)
      ASSUME_YES=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --keep-build)
      KEEP_BUILD=1
      shift
      ;;
    --data-dir)
      if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        echo "error: --data-dir requires a non-empty path" >&2
        exit 2
      fi
      CUSTOM_DATA_DIRS+=("$2")
      shift 2
      ;;
    --data-dir=*)
      val="${1#*=}"
      if [ -z "$val" ]; then
        echo "error: --data-dir requires a non-empty path" >&2
        exit 2
      fi
      CUSTOM_DATA_DIRS+=("$val")
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

normalize_path() {
  local raw="$1"
  local path="$raw"
  # Resolve relative paths against PWD without dereferencing leaf symlinks.
  case "$path" in
    /*) ;;
    *) path="$PWD/$path" ;;
  esac
  while [ "$path" != "/" ] && [ "${path%/}" != "$path" ]; do
    path="${path%/}"
  done
  printf '%s' "$path"
}

is_safe_target_dir() {
  local path="$1"
  [ -n "$path" ] || return 1

  # Must be an absolute path with no parent-directory traversal components.
  case "$path" in
    /*) ;;
    *) return 1 ;;
  esac
  case "/$path/" in
    */../*) return 1 ;;
  esac

  # Never dereference or delete symlinks as data directories.
  if [ -L "$path" ]; then
    return 1
  fi

  # Must have at least two path components (never / or top-level /Users, /tmp, etc.).
  local rest="${path#/}"
  case "$rest" in
    */*) ;;
    *) return 1 ;;
  esac

  # Refuse home directory and standard OS / XDG container roots.
  if [ -n "${HOME:-}" ]; then
    local home_norm
    home_norm="$(normalize_path "$HOME")"
    case "$path" in
      "$home_norm"|"$home_norm/Library"|"$home_norm/Library/Application Support"|"$home_norm/.local"|"$home_norm/.local/share"|"$home_norm/AppData"|"$home_norm/AppData/Local")
        return 1
        ;;
    esac
  fi

  if [ -n "${XDG_DATA_HOME:-}" ]; then
    local xdg_norm
    xdg_norm="$(normalize_path "$XDG_DATA_HOME")"
    if [ "$path" = "$xdg_norm" ]; then
      return 1
    fi
  fi

  case "$path" in
    /private/tmp|/private/var|/usr/local|/opt/homebrew)
      return 1
      ;;
  esac

  return 0
}

append_unique_data_dir() {
  local raw="$1"
  local strict="${2:-0}"
  [ -n "$raw" ] || return 0

  local path
  path="$(normalize_path "$raw")"
  if ! is_safe_target_dir "$path"; then
    if [ "$strict" -eq 1 ]; then
      echo "error: refusing unsafe or symlinked data directory: $raw" >&2
      exit 1
    fi
    echo "warning: skipping unsafe or symlinked data directory: $raw" >&2
    WARNINGS=$((WARNINGS + 1))
    return 0
  fi

  if [ "${#DATA_DIRS[@]}" -gt 0 ]; then
    local existing
    for existing in "${DATA_DIRS[@]}"; do
      if [ "$existing" = "$path" ]; then
        return 0
      fi
    done
  fi
  DATA_DIRS+=("$path")
}

collect_data_dirs() {
  local base_dir=""
  case "$OS_NAME" in
    Darwin)
      if [ -n "${HOME:-}" ]; then
        base_dir="$HOME/Library/Application Support"
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*)
      if [ -n "${LOCALAPPDATA:-}" ]; then
        if command -v cygpath >/dev/null 2>&1; then
          base_dir="$(cygpath -u "$LOCALAPPDATA")"
        else
          base_dir="$LOCALAPPDATA"
        fi
      elif [ -n "${HOME:-}" ]; then
        base_dir="$HOME/AppData/Local"
      fi
      ;;
    *)
      if [ -n "${XDG_DATA_HOME:-}" ]; then
        base_dir="$XDG_DATA_HOME"
      elif [ -n "${HOME:-}" ]; then
        base_dir="$HOME/.local/share"
      fi
      ;;
  esac

  if [ -n "$base_dir" ]; then
    local app
    for app in "${APP_NAMES[@]}"; do
      append_unique_data_dir "$base_dir/$app" 0
    done
  fi

  if [ -n "${COMPUTER_HISTORY_DATA_DIR:-}" ]; then
    append_unique_data_dir "$COMPUTER_HISTORY_DATA_DIR" 0
  fi
  if [ -n "${COMPUTER_ACCESS_DATA_DIR:-}" ]; then
    append_unique_data_dir "$COMPUTER_ACCESS_DATA_DIR" 0
  fi

  if [ "${#CUSTOM_DATA_DIRS[@]}" -gt 0 ]; then
    local custom
    for custom in "${CUSTOM_DATA_DIRS[@]}"; do
      append_unique_data_dir "$custom" 1
    done
  fi

  if [ "$OS_NAME" = "Darwin" ]; then
    local uid
    uid="$(id -u)"
    LOCK_DIRS=(
      "/private/tmp/dsh-computer-history-$uid"
      "/private/tmp/dsh-computer-access-$uid"
    )
  fi
}

matches_project_process() {
  local cmd="$1"
  case "$cmd" in
    *uninstall.sh*)
      return 1
      ;;
    */computer-history-collector|*/computer-history-collector\ *|computer-history-collector|computer-history-collector\ *|*/computer-history-collector.exe|*/computer-history-collector.exe\ *|computer-history-collector.exe|computer-history-collector.exe\ *)
      return 0
      ;;
    */computer-access-collector|*/computer-access-collector\ *|computer-access-collector|computer-access-collector\ *|*/computer-access-collector.exe|*/computer-access-collector.exe\ *|computer-access-collector.exe|computer-access-collector.exe\ *)
      return 0
      ;;
    */computer-history-key-store|*/computer-history-key-store\ *|computer-history-key-store|computer-history-key-store\ *|*/computer-history-key-store.exe|*/computer-history-key-store.exe\ *|computer-history-key-store.exe|computer-history-key-store.exe\ *)
      return 0
      ;;
    */computer-access-key-store|*/computer-access-key-store\ *|computer-access-key-store|computer-access-key-store\ *|*/computer-access-key-store.exe|*/computer-access-key-store.exe\ *|computer-access-key-store.exe|computer-access-key-store.exe\ *)
      return 0
      ;;
    *computer-history-mcp\ serve*|*computer-history-mcp\ stdio*|*computer-access-mcp\ serve*|*computer-access-mcp\ stdio*)
      return 0
      ;;
    *dist/server/cli.js\ serve*|*dist/server/cli.js\ stdio*|*src/server/cli.ts\ serve*|*src/server/cli.ts\ stdio*)
      return 0
      ;;
    *dist\\server\\cli.js\ serve*|*dist\\server\\cli.js\ stdio*|*src\\server\\cli.ts\ serve*|*src\\server\\cli.ts\ stdio*)
      return 0
      ;;
  esac
  return 1
}

collect_running_processes() {
  local ps_output
  ps_output="$(ps -ax -o pid=,command= 2>/dev/null || true)"
  [ -n "$ps_output" ] || return 0

  local line pid cmd
  while IFS= read -r line; do
    # Trim leading spaces and split into PID + command line.
    line="${line#"${line%%[![:space:]]*}"}"
    [ -n "$line" ] || continue
    pid="${line%%[[:space:]]*}"
    cmd="${line#"$pid"}"
    cmd="${cmd#"${cmd%%[![:space:]]*}"}"

    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    if [ "$pid" -eq "$$" ] || [ "$pid" -eq "$PPID" ]; then
      continue
    fi
    if matches_project_process "$cmd"; then
      TARGET_PIDS+=("$pid")
      TARGET_CMDS+=("$cmd")
    fi
  done <<< "$ps_output"
}

is_repo_checkout() {
  local pkg_json="$SCRIPT_DIR/package.json"
  [ -f "$pkg_json" ] && grep -qE '"name"[[:space:]]*:[[:space:]]*"(computer-history-mcp|computer-access-mcp)"' "$pkg_json"
}

print_plan() {
  echo "computer-history-mcp uninstall plan"
  echo "-----------------------------------"

  if [ "${#TARGET_PIDS[@]}" -gt 0 ]; then
    echo "Running processes to stop (${#TARGET_PIDS[@]}):"
    local i=0
    while [ "$i" -lt "${#TARGET_PIDS[@]}" ]; do
      echo "  - PID ${TARGET_PIDS[$i]}: ${TARGET_CMDS[$i]}"
      i=$((i + 1))
    done
  else
    echo "Running processes to stop: none"
  fi

  if [ "$OS_NAME" = "Darwin" ]; then
    echo "macOS Keychain services to revoke:"
    local service
    for service in "${KEYCHAIN_SERVICES[@]}"; do
      if command -v security >/dev/null 2>&1 && security find-generic-password -s "$service" >/dev/null 2>&1; then
        echo "  - $service (present)"
      else
        echo "  - $service (not found)"
      fi
    done
  fi

  echo "Data directories (keys, leases, and encrypted stores) to delete:"
  if [ "${#DATA_DIRS[@]}" -gt 0 ]; then
    local dir
    for dir in "${DATA_DIRS[@]}"; do
      if [ -d "$dir" ]; then
        echo "  - $dir (exists)"
      else
        echo "  - $dir (not present)"
      fi
    done
  else
    echo "  - none"
  fi

  if [ "${#LOCK_DIRS[@]}" -gt 0 ]; then
    echo "Runtime lock directories to delete:"
    local lock_dir
    for lock_dir in "${LOCK_DIRS[@]}"; do
      if [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ]; then
        echo "  - $lock_dir (exists)"
      else
        echo "  - $lock_dir (not present)"
      fi
    done
  fi

  echo "Package / build cleanup:"
  echo "  - Global npm/pnpm links for: ${APP_NAMES[*]} (if installed)"
  if [ "$KEEP_BUILD" -eq 1 ]; then
    echo "  - Local repo build artifacts: kept (--keep-build)"
  elif is_repo_checkout; then
    echo "  - Local repo build artifacts under $SCRIPT_DIR: dist/, native-bin/, native build caches"
  else
    echo "  - Local repo build artifacts: skipped (not running inside repository root)"
  fi
}

stop_processes() {
  echo "[1/4] Stopping running processes..."
  if [ "${#TARGET_PIDS[@]}" -eq 0 ]; then
    echo "  no matching processes running"
    return 0
  fi

  local pid
  for pid in "${TARGET_PIDS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "  [dry-run] would send SIGTERM to PID $pid"
    else
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done

  if [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi

  # Wait up to 3 seconds for graceful shutdown before SIGKILL.
  local attempt=0
  while [ "$attempt" -lt 15 ]; do
    local alive=0
    for pid in "${TARGET_PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
        break
      fi
    done
    [ "$alive" -eq 0 ] && break
    sleep 0.2
    attempt=$((attempt + 1))
  done

  for pid in "${TARGET_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      echo "  forcing SIGKILL on PID $pid"
      kill -KILL "$pid" 2>/dev/null || true
    else
      echo "  stopped PID $pid"
    fi
  done
}

revoke_keychain_service() {
  local service="$1"
  if ! command -v security >/dev/null 2>&1; then
    echo "  warning: macOS 'security' CLI not found; cannot delete Keychain service $service" >&2
    WARNINGS=$((WARNINGS + 1))
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    if security find-generic-password -s "$service" >/dev/null 2>&1; then
      echo "  [dry-run] would delete all Keychain master key item(s) for service: $service"
    else
      echo "  [dry-run] no Keychain item found for service: $service"
    fi
    return 0
  fi

  local removed=0
  local rc=0
  while [ "$removed" -lt 64 ]; do
    if security delete-generic-password -s "$service" >/dev/null 2>&1; then
      removed=$((removed + 1))
    else
      rc=$?
      # Exit status 44 corresponds to errSecItemNotFound on macOS.
      if [ "$rc" -eq 44 ]; then
        break
      fi
      echo "  warning: failed to delete Keychain item for service '$service' (exit code $rc)" >&2
      WARNINGS=$((WARNINGS + 1))
      return 0
    fi
  done

  if [ "$removed" -gt 0 ]; then
    echo "  revoked $removed Keychain master key item(s) for service: $service"
  else
    echo "  no Keychain item found for service: $service"
  fi
}

revoke_keys() {
  echo "[2/4] Revoking master keys, admin tokens, and MCP client leases..."

  if [ "$OS_NAME" = "Darwin" ]; then
    local service
    for service in "${KEYCHAIN_SERVICES[@]}"; do
      revoke_keychain_service "$service"
    done
  fi

  if [ "${#DATA_DIRS[@]}" -gt 0 ]; then
    local dir key_file target
    for dir in "${DATA_DIRS[@]}"; do
      [ -d "$dir" ] || continue
      for key_file in "${KEY_FILENAMES[@]}"; do
        target="$dir/$key_file"
        if [ -e "$target" ] || [ -L "$target" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then
            echo "  [dry-run] would revoke/remove $target"
          else
            rm -f "$target"
            echo "  revoked $target"
          fi
        fi
      done
    done
  fi
}

delete_stores() {
  echo "[3/4] Deleting current and legacy history stores and runtime locks..."

  if [ "${#DATA_DIRS[@]}" -gt 0 ]; then
    local dir
    for dir in "${DATA_DIRS[@]}"; do
      if [ ! -e "$dir" ]; then
        echo "  not present: $dir"
        continue
      fi
      if ! is_safe_target_dir "$dir"; then
        echo "  warning: refusing to delete unsafe path: $dir" >&2
        WARNINGS=$((WARNINGS + 1))
        continue
      fi
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [dry-run] would delete data directory: $dir"
      else
        rm -rf "$dir"
        echo "  deleted data directory: $dir"
      fi
    done
  fi

  if [ "${#LOCK_DIRS[@]}" -gt 0 ]; then
    local lock_dir
    for lock_dir in "${LOCK_DIRS[@]}"; do
      if [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
          echo "  [dry-run] would delete runtime lock directory: $lock_dir"
        else
          rm -rf "$lock_dir"
          echo "  deleted runtime lock directory: $lock_dir"
        fi
      fi
    done
  fi
}

uninstall_packages_and_builds() {
  echo "[4/4] Uninstalling global CLI packages and local build artifacts..."
  local removed_any=0

  if command -v pnpm >/dev/null 2>&1; then
    local pnpm_root
    pnpm_root="$(pnpm root -g 2>/dev/null || true)"
    if [ -n "$pnpm_root" ]; then
      local pkg
      for pkg in "${APP_NAMES[@]}"; do
        if [ -e "$pnpm_root/$pkg" ] || [ -L "$pnpm_root/$pkg" ]; then
          removed_any=1
          if [ "$DRY_RUN" -eq 1 ]; then
            echo "  [dry-run] would run: pnpm remove -g $pkg"
          elif pnpm remove -g "$pkg" >/dev/null 2>&1; then
            echo "  removed global pnpm package: $pkg"
          else
            echo "  warning: pnpm remove -g $pkg failed" >&2
            WARNINGS=$((WARNINGS + 1))
          fi
        fi
      done
    fi
  fi

  if command -v npm >/dev/null 2>&1; then
    local npm_root
    npm_root="$(npm root -g 2>/dev/null || true)"
    if [ -n "$npm_root" ]; then
      local pkg
      for pkg in "${APP_NAMES[@]}"; do
        if [ -e "$npm_root/$pkg" ] || [ -L "$npm_root/$pkg" ]; then
          removed_any=1
          if [ "$DRY_RUN" -eq 1 ]; then
            echo "  [dry-run] would run: npm uninstall -g $pkg"
          elif npm uninstall -g "$pkg" >/dev/null 2>&1; then
            echo "  removed global npm package: $pkg"
          else
            echo "  warning: npm uninstall -g $pkg failed" >&2
            WARNINGS=$((WARNINGS + 1))
          fi
        fi
      done
    fi
  fi

  if [ "$KEEP_BUILD" -eq 0 ] && is_repo_checkout; then
    local rel target
    for rel in "${BUILD_PATHS[@]}"; do
      target="$SCRIPT_DIR/$rel"
      if [ -e "$target" ] && [ ! -L "$target" ]; then
        removed_any=1
        if [ "$DRY_RUN" -eq 1 ]; then
          echo "  [dry-run] would delete build directory: $target"
        else
          rm -rf "$target"
          echo "  deleted build directory: $target"
        fi
      fi
    done
  fi

  if [ "$removed_any" -eq 0 ]; then
    echo "  no global CLI packages or local build outputs found"
  fi
}

main() {
  collect_data_dirs
  collect_running_processes
  print_plan
  echo ""

  if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    if [ ! -t 0 ]; then
      echo "error: non-interactive stdin; re-run with --yes to confirm deletion or --dry-run to preview" >&2
      exit 1
    fi
    printf "This permanently revokes all keys and deletes retained history stores. Continue? [y/N] "
    local reply=""
    read -r reply || true
    case "$reply" in
      y|Y|yes|YES) ;;
      *)
        echo "Aborted. No files or keys were modified."
        exit 0
        ;;
    esac
    echo ""
  fi

  stop_processes
  revoke_keys
  delete_stores
  uninstall_packages_and_builds

  echo ""
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run complete. No files, processes, or keys were modified."
  elif [ "$WARNINGS" -gt 0 ]; then
    echo "Uninstall finished with $WARNINGS warning(s); review the messages above."
  else
    echo "Uninstall complete."
  fi

  cat <<'EOF'

Manual follow-up (optional):
  - Remove "computer-history" / "computer-access" entries from your AI client MCP config (Antigravity, Claude, Cursor).
  - On macOS, revoke Accessibility / Input Monitoring permissions in System Settings -> Privacy & Security if no longer needed.
  - Delete the cloned repository folder if you do not plan to rebuild from source.
EOF

  if [ "$WARNINGS" -gt 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    exit 1
  fi
}

main
