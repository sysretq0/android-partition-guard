#!/bin/sh
# setup.sh - integrate Partition Guard into a kernel tree.
#
# Run with cwd = repo-sync root (the dir containing common/):
#   setup.sh [--cleanup | <commit-or-tag>]
#
# Symlinks security/partition-guard at the driver, hooks security/Makefile
# and security/Kconfig (idempotent), and appends partition_guard to the LSM
# default list (verified). Full clone: keeps .git for pinning/versioning.
set -eu

GKI_ROOT=$(pwd)
NAME="partition-guard"
REPO_URL="https://github.com/sysretq0/android-partition-guard"

initialize_variables() {
    if [ -d "$GKI_ROOT/security" ]; then
        SECURITY_DIR="$GKI_ROOT/security"
    elif [ -d "$GKI_ROOT/common/security" ]; then
        SECURITY_DIR="$GKI_ROOT/common/security"
    else
        echo '[ERROR] "security/" directory not found.'
        exit 127
    fi

    SECURITY_MAKEFILE=$SECURITY_DIR/Makefile
    SECURITY_KCONFIG=$SECURITY_DIR/Kconfig
}

perform_cleanup() {
    echo "[+] Cleaning up Partition Guard..."
    [ -L "$SECURITY_DIR/partition-guard" ] && rm -f "$SECURITY_DIR/partition-guard" && echo "[-] Symlink removed."
    grep -q "partition-guard" "$SECURITY_MAKEFILE" 2>/dev/null && sed -i '/partition-guard/d' "$SECURITY_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "security/partition-guard/Kconfig" "$SECURITY_KCONFIG" 2>/dev/null && sed -i '/security\/partition-guard\/Kconfig/d' "$SECURITY_KCONFIG" && echo "[-] Kconfig reverted."
    grep -q "partition_guard" "$SECURITY_KCONFIG" 2>/dev/null && sed -i 's/,partition_guard//g' "$SECURITY_KCONFIG" && echo "[-] LSM list reverted."
    grep -q "GUARD_NO_OPEN" "$GKI_ROOT/$NAME/kernel/src/Makefile" 2>/dev/null && sed -i '/GUARD_NO_OPEN/d' "$GKI_ROOT/$NAME/kernel/src/Makefile" && echo "[-] compat flag reverted."
}

setup_guard() {
    echo "[+] Setting up Partition Guard..."
    if [ -d "$NAME/.git" ]; then
        ( cd "$NAME"
          git fetch origin +refs/heads/*:refs/remotes/origin/* >/dev/null 2>&1 || true
          if [ -n "${1-}" ]; then
              git fetch origin "$1" || true
              git checkout -q "$1"
          else
              git checkout -q main || git checkout -q master || true
              git pull --ff-only || true
          fi
        )
        echo "[+] Repository updated."
    elif [ ! -d "$NAME" ]; then
        if [ -n "${1-}" ]; then
            git clone --branch "$1" "$REPO_URL" "$NAME"
        else
            git clone "$REPO_URL" "$NAME"
        fi
        echo "[+] Repository cloned."
    fi

    # Modern LSM infrastructure required (all GKI 5.10+ have it).
    if ! grep -q "DEFINE_LSM" "$SECURITY_DIR/../include/linux/lsm_hooks.h" 2>/dev/null; then
        echo "[ERROR] Modern LSM infrastructure not found."
        exit 1
    fi

    cd "$SECURITY_DIR"
    if command -v realpath >/dev/null 2>&1; then
        rel="$(realpath --relative-to="$SECURITY_DIR" "$GKI_ROOT/$NAME/kernel/src" 2>/dev/null || true)"
    else
        rel="$GKI_ROOT/$NAME/kernel/src"
    fi
    [ -n "$rel" ] || rel="$GKI_ROOT/$NAME/kernel/src"
    ln -sfn "$rel" partition-guard
    echo "[+] Symlink created."

    grep -q "partition-guard/" "$SECURITY_MAKEFILE" || \
        printf '\nobj-$(CONFIG_PARTITION_GUARD) += partition-guard/\n' >> "$SECURITY_MAKEFILE"
    echo "[+] Makefile updated."

    if ! grep -q "security/partition-guard/Kconfig" "$SECURITY_KCONFIG"; then
        awk '
            /^endmenu[[:space:]]*$/ { last_match = NR }
            { lines[NR] = $0 }
            END {
                for (i = 1; i <= NR; i++) {
                    if (i == last_match) print "source \"security/partition-guard/Kconfig\""
                    print lines[i]
                }
            }
        ' "$SECURITY_KCONFIG" > "$SECURITY_KCONFIG.tmp" && mv "$SECURITY_KCONFIG.tmp" "$SECURITY_KCONFIG"
        echo "[+] Kconfig updated."
    else
        echo "[-] Kconfig already modified."
    fi

    # Activate in the LSM default list (verified below). Scoped to the
    # LSM stanza; appends after the selinux token present on all trees.
    sed -i '/^config LSM$/,/^help$/ { /^[[:space:]]*default/ { /partition_guard/! s/selinux/selinux,partition_guard/ } }' "$SECURITY_KCONFIG"
    if grep -q "partition_guard" "$SECURITY_KCONFIG"; then
        echo "[+] LSM list includes partition_guard."
    else
        echo "[ERROR] LSM list update failed (no selinux token in defaults?)."
        exit 1
    fi

    # Compat probe: test the declaration's ARITY, not its name. The name
    # alone is ambiguous: 1-arg public (<=5.17), 2-arg public (5.18
    # through the hiding after 6.2), private extern (later). A name-only
    # grep would call 1-arg against a public 2-arg decl and fail the
    # build. Probe the tree, never guess versions. Idempotent append.
    DECL=$(grep "blkdev_get_no_open" "$SECURITY_DIR/../include/linux/blkdev.h" 2>/dev/null | head -1)
    case "$DECL" in
        *bool*)
            FLAG="GUARD_NO_OPEN_2ARG" ;;
        *dev_t*)
            FLAG="GUARD_NO_OPEN_1ARG" ;;
        *)
            FLAG="" ;;
    esac
    if [ -n "$FLAG" ]; then
        grep -q "$FLAG" "$GKI_ROOT/$NAME/kernel/src/Makefile" || \
            printf "\nccflags-y += -D%s\n" "$FLAG" >> "$GKI_ROOT/$NAME/kernel/src/Makefile"
        echo "[+] blkdev_get_no_open: $FLAG."
    else
        echo "[+] blkdev_get_no_open: private, extern path."
    fi

    echo "[+] Done."
}

if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_guard
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_guard "$@"
fi
