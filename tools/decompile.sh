#!/usr/bin/env bash
# Headless decompilation, no GUI needed. Usage (WSL): tools/decompile.sh <binary>
# Dumps every function's decompiled C to <binary>.decomp.c (then just grep/less it).
set -e
bin="$(realpath "$1")"
proj_dir=$(mktemp -d)
scripts_dir="$(dirname "$(realpath "$0")")"
~/ghidra/support/analyzeHeadless "$proj_dir" tmpproj -import "$bin" \
  -scriptPath "$scripts_dir" -postScript GhidraDecompAll.java "${bin}.decomp.c" \
  -deleteProject 2>&1 | tail -30
echo "---"
echo "decompiled C: ${bin}.decomp.c"
grep -n "^// ---- main\|^// ---- .*main" "${bin}.decomp.c" 2>/dev/null | head -5
