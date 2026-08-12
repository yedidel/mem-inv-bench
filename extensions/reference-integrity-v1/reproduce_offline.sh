#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$HERE/src/reproduce.py" --root "$HERE"

