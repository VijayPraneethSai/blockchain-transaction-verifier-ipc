#!/bin/sh
# Usage: run_tests.sh <verifier> <driver>
# Small cases are also checked against the slow brute-force reading of the definition (--brute),
# which tests the driver's own calculation. Larger cases use the faster per-wallet lists.
v=$1; d=$2; fail=0; n=0
for s in $(seq 1 60); do
    t=$((50 + s * 13)); b=$((5 + s % 17)); w=$((3 + s * 3))
    n=$((n + 1)); $d "$v" "$s" "$t" "$b" "$w" --brute >/dev/null || { echo "FAIL small seed $s"; fail=$((fail + 1)); }
done
for s in $(seq 100 110); do
    n=$((n + 1)); $d "$v" "$s" 20000 60 500 >/dev/null || { echo "FAIL medium seed $s"; fail=$((fail + 1)); }
done
# negative security values behave like 0; a corrupt wallet count is refused
for s in 200 201 202; do
    n=$((n + 1)); $d "$v" "$s" 500 20 30 --negative-sec >/dev/null || { echo "FAIL negative security seed $s"; fail=$((fail + 1)); }
    n=$((n + 1)); $d "$v" "$s" 500 20 30 --bad-count >/dev/null || { echo "FAIL bad count seed $s"; fail=$((fail + 1)); }
done
# lines longer than 128 bytes
for s in 300 301 302; do
    n=$((n + 1)); $d "$v" "$s" 2000 20 100 --long-lines >/dev/null || { echo "FAIL long lines seed $s"; fail=$((fail + 1)); }
done
# one wallet, one transaction: every block hits the same wallet, and self transfers dominate
n=$((n + 1)); $d "$v" 7 1 5 1 --brute >/dev/null || { echo "FAIL single wallet"; fail=$((fail + 1)); }
if [ "$fail" -ne 0 ]; then echo "$fail of $n cases failed"; exit 1; fi
echo "all $n cases passed"
