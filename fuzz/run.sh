#!/bin/bash
# Runs all fuzz targets in parallel. Usage: fuzz/run.sh [seconds per target, default 3600]
# Needs: rustup toolchain install nightly; cargo install cargo-fuzz
set -euo pipefail
cd "$(dirname "$0")"
SECS="${1:-3600}"
mkdir -p corpus/open_archive corpus/cbor corpus/index corpus/recovery corpus/transform corpus/encrypted logs
cp -n seeds/*.archy corpus/open_archive/ 2>/dev/null || true
cp -n seeds/*.archy corpus/recovery/ 2>/dev/null || true
cp -n seeds/transform-*.bin corpus/transform/ 2>/dev/null || true
cp -n seeds/encrypted*.archy corpus/encrypted/ 2>/dev/null || true
cargo +nightly fuzz build -O
pids=()
for t in open_archive cbor index recovery transform encrypted; do
    cargo +nightly fuzz run -O "$t" "corpus/$t" -- -max_total_time="$SECS" -max_len=262144 -rss_limit_mb=4096 \
        -print_final_stats=1 > "logs/$t.log" 2>&1 &
    pids+=($!)
done
status=0
for p in "${pids[@]}"; do wait "$p" || status=1; done
for t in open_archive cbor index recovery transform encrypted; do echo "== $t"; grep -E "Done|stat::number_of_executed_units|ERROR|crash" "logs/$t.log" | tail -3; done
exit $status
