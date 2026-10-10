#!/bin/sh
# Fetch (or update) the latest version and run it. Arguments are passed through.
set -e

if ! command -v python3 >/dev/null 2>&1; then
    if command -v pacman >/dev/null 2>&1; then sudo pacman -S --needed python
    elif command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y python3
    else echo "Please install Python 3.10+" >&2; exit 1
    fi
fi

dir="${XDG_CACHE_HOME:-$HOME/.cache}/absolutely-proprietary-src"
if [ -d "$dir/.git" ]; then
    git -C "$dir" pull --quiet
else
    git clone --quiet https://github.com/vmavromatis/absolutely-proprietary.git "$dir"
fi
cd "$dir"
exec python3 -m absolutely_proprietary "$@"
