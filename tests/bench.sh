#!/bin/sh
# Usage: bench.sh <verifier> <driver> [runs]
# 750,000 transactions, 100,000 wallets, 2,000 blocks. Every run is also checked for correctness by the driver.
v=$1; d=$2; runs=${3:-5}
for i in $(seq 1 "$runs"); do
    $d "$v" 42 750000 2000 100000
done | tee /tmp/bench_runs.txt
echo "median of $runs runs:"
for key in total_ms ready_ms query_ms max_rss_mb; do
    sed -n "s/.*$key=\([0-9.]*\).*/\1/p" /tmp/bench_runs.txt | sort -n | awk -v k=$key '{a[NR]=$1} END {printf "  %s=%s\n", k, a[int((NR+1)/2)]}'
done
