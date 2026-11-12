#!/bin/sh
# cryptship transform recipe: compile Python sources to bytecode and remove the
# source, so the sealed payload (and anything a memory dump recovers) contains
# .pyc, not readable .py. cryptship runs this with CWD = a copy of the app dir
# and $CRYPTSHIP_SRC set. Requires python3 wherever `cryptship pack` runs.
#
#   cryptship pack --in app --transform-cmd "sh scripts/compile-python.sh" ...
#
# For stronger protection (native code, far harder to decompile) use Nuitka
# instead, e.g. --transform-cmd "python3 -m nuitka --module app.py && rm app.py".
set -e

python3 -m compileall -b -q .
find . -name '*.py' -type f -delete
find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "compiled $(find . -name '*.pyc' | wc -l | tr -d ' ') module(s) to bytecode; removed .py source"
