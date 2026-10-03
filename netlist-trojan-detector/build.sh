#!/bin/bash
#
# IIS5008 HW3 - build script
#
# Compile your detector. Invoked once by the grader before running any
# test cases. Replace with whatever build command your detector needs.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

g++ -O3 -std=c++17 -pthread -o detector detector.cpp

echo "[build.sh] detector built successfully"
