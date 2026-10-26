#!/bin/sh
# Bootstrap php_guard: cari interpreter Python (>=3.6) lalu jalankan php_guard.py.
# Bila Python tak ada, tawarkan memasangnya (minta konfirmasi, butuh root/sudo).
# Jalankan: sudo sh php_guard.sh scan   (argumen diteruskan apa adanya)
set -eu

unset CDPATH
DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SCRIPT="$DIR/php_guard.py"

find_py() {
    for c in python3 /usr/libexec/platform-python \
             python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python; do
        cmd=$(command -v "$c" 2>/dev/null) || continue
        if "$cmd" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
            printf '%s' "$cmd"
            return 0
        fi
    done
    return 1
}

PY=$(find_py || true)

if [ -z "${PY:-}" ]; then
    echo "php_guard: python3 (>=3.6) tidak ditemukan di server ini." >&2

    if command -v apt-get >/dev/null 2>&1; then
        INSTALL="apt-get update && apt-get install -y python3"
    elif command -v dnf >/dev/null 2>&1; then
        INSTALL="dnf install -y python3"
    elif command -v yum >/dev/null 2>&1; then
        INSTALL="yum install -y python3"
    elif command -v zypper >/dev/null 2>&1; then
        INSTALL="zypper --non-interactive install python3"
    elif command -v apk >/dev/null 2>&1; then
        INSTALL="apk add --no-cache python3"
    else
        echo "php_guard: package manager tak dikenali. Pasang python3 manual lalu ulangi." >&2
        exit 97
    fi

    SUDO=""
    if [ "$(id -u)" != 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo "
        else
            echo "php_guard: perlu root untuk memasang. Jalankan ulang sebagai root/sudo." >&2
            exit 97
        fi
    fi

    printf "Pasang python3 sekarang? Perintah: %s%s  [y/N] " "$SUDO" "$INSTALL" >&2
    if [ -r /dev/tty ]; then
        read -r ans </dev/tty || ans=""
    else
        read -r ans || ans=""
    fi
    case "$ans" in
        y | Y | yes | YES | Yes)
            sh -c "$SUDO$INSTALL" || { echo "php_guard: instalasi python3 gagal." >&2; exit 97; }
            ;;
        *)
            echo "php_guard: dibatalkan. Butuh python3 untuk menjalankan scan." >&2
            exit 97
            ;;
    esac

    PY=$(find_py || true)
    if [ -z "${PY:-}" ]; then
        echo "php_guard: python3 masih tak ditemukan setelah instalasi." >&2
        exit 97
    fi
fi

exec "$PY" "$SCRIPT" "$@"
