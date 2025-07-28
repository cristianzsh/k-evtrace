#!/bin/bash

set -e
set -u

echo "==================="
echo " Building k-evtrace"
echo "==================="

MAIN="k-evtrace.py"
OUTDIR="build"

# Clean previous build
rm -rf "$OUTDIR"

# Build with Nuitka
python3 -m nuitka \
  --standalone \
  --onefile \
  --follow-imports \
  --output-dir="$OUTDIR" \
  --include-package=Evtx \
  --include-package=tqdm \
  --include-package=tabulate \
  --include-package=yaml \
  --include-package=requests \
  "$MAIN"
