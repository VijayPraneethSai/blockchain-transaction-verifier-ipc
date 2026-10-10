# Blockchain transaction verifier

A C program that answers "how much suspicious money touches these wallets?" for a stream of blocks, using System V shared
memory and message queues. It was a course project; I later added a test driver, fixed the bugs it found, and sped up the
loading step.

## The problem

The verifier is given a file of transactions (`timestamp hash sender receiver amount`) and then serves one request per
block:

- The block's wallets are in a shared memory segment, encrypted with a rotation cipher.
- The decryption key and a *security value* arrive on a message queue.
- A transaction is suspicious if its hash starts with at least `security value` zeros.
- The reply is the total amount of suspicious transactions that involve the block's wallets. A wallet that appears twice in a
  block counts twice, and a transaction between two wallets of the block counts for both. A transaction a wallet sends to
  itself counts once for that wallet.

## Design

Answering a query by scanning every transaction would cost O(transactions) per wallet. Instead the transactions are
indexed once:

- Each wallet has an array `totals[k]`: the amount of its transactions whose hash has exactly `k` leading zeros. After
  loading, the array is turned into suffix sums, so `totals[k]` becomes "at least `k` zeros". A query for one wallet is
  then one hash lookup and one array read.
- The wallets are kept in a chained hash table (FNV-1a).
- For each block, a second small hash table counts how often each wallet occurs, and the reply is the sum over those
  wallets of `count * totals[security value]`.

Loading is O(transactions). A block costs O(wallets in the block), at most 100, with an O(1) lookup each.

```
src/main.c          input parsing, shared memory, message loop
src/wallet_index.c  per-wallet totals (hash table + suffix sums)
src/block_counts.c  per-block wallet counts
src/protocol.h      shared memory layout and message structs
tests/driver.c      generates cases, plays the harness, checks every reply
```

## Build and test

Linux only (System V IPC).

```
make          # builds bin/verifier
make test     # 81 randomized cases, each reply checked
sh tests/bench.sh bin/verifier bin/driver 5
```

The course harness is not part of this repository, so `tests/driver.c` stands in for it: it writes the input files,
creates the shared memory and queue, starts the verifier, sends one request per block and compares every reply with a
second implementation that keeps a list of transactions per wallet. Small cases are also compared with the slowest
reading of the definition (`--brute`). I broke the verifier on purpose in four ways (dropping the self-transfer
correction, an off-by-one on the security value, the wrong rotation, no wallet counting) and the suite caught each one.
The suite also passes under AddressSanitizer and UBSan.

## Bugs the tests found

- No argument crashed with a segfault, and a long test number overflowed a stack buffer.
- A negative security value read outside the array and returned garbage. It now behaves like 0, since every hash has at
  least that many leading zeros.
- A corrupt wallet count in shared memory (negative, or above 100) overflowed a stack buffer. It is now refused.
- Transaction lines longer than 128 bytes were cut in the middle, so the sums came out wrong or 0. This only shows with
  long timestamps or large amounts.

## Speed

Measured on a 2 vCPU shared Linux container with gcc 13.3 (`-O2`), 750,000 transactions, 100,000 wallets and 2,000
blocks. Each row is the median of 5 runs of `tests/bench.sh`, and every run is also verified for correctness. The machine
is noisy; single runs varied by about 20%.

| Version | Total | Load + index | 2,000 queries | Peak memory |
|---|---:|---:|---:|---:|
| Before (split into modules, bugs fixed) | 4.10 s | 3.59 s | 0.51 s | 307 MB |
| Split lines by hand instead of `sscanf` | 3.46 s | 3.01 s | 0.48 s | 307 MB |
| One cumulative array per wallet instead of six | 2.45 s | 2.00 s | 0.45 s | 76 MB |
| 262,139 buckets instead of 10,007 | 1.16 s | 0.77 s | 0.39 s | 76 MB |

What I learned from this:

- A call-graph profile (callgrind) put `sscanf` at 57% of the instructions, so I expected it to dominate. Removing it saved
  about 15% of the wall time. Instruction counts do not show cache misses.
- The wallet records were 3 KB each and the table had about ten wallets per bucket, so every lookup walked a chain of
  records scattered across memory. Shrinking the record and lengthening the table saved far more than the parsing change.

## Limits

- The wallet table has a fixed size. With millions of wallets, the chains would grow again.
- The sum is returned as a `long`, so totals above 2^63 would wrap.
- Test cases come from my own generator, so the results here do not reproduce the course's own tests.
