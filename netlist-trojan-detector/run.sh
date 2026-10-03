#!/bin/bash
#
# IIS5008 HW3 - run script
#
# Usage: bash run.sh <design.v> <output.txt>
#
# Invoked once per test case by the grader. The script must write the
# result file at the path given in $2. Feel free to replace this with a
# different language / different binary, as long as the interface and
# the output format are preserved.
#
set -e

if [ $# -ne 2 ]; then
    echo "usage: bash run.sh <design.v> <output.txt>" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$SCRIPT_DIR/detector" "$1" "$2"
