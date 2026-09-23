# Performance

What one decision costs, and what one ledger file can carry. Measured with
[`benchmarks/bench_engine.py`](../benchmarks/bench_engine.py); run it on the
machine you would deploy to before quoting any of these numbers.

```bash
python benchmarks/bench_engine.py --requests 1000 --procs 1,2,4
```

## What is measured

One request is what the gateway does for an agent's call:

- `submit_intent` — verify the agent's signature, evaluate the grant, reserve
  budget, sign the receipt and append it to the chain;
- `execute` — claim the execution, call the upstream, record the result, sign
  and chain it again.

The upstream is a stub that answers at once, so this is Mandate's own cost:
no network, no upstream latency, no HTTP in front. Signing the intent is the
agent's work and is not timed. Workers are separate processes on one SQLite
file, as `mandate gateway serve --workers N` runs them.

## Results

Intel Xeon @ 2.10 GHz, 4 vCPUs, ext4, Python 3.13, SQLite 3.45 — a small
cloud VM. 1000 requests per worker, every one authorized and executed:

| workers | requests | req/s | p50 | p95 | p99 | max | errors |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1000 | 245 | 3.6 ms | 5.7 ms | 7.6 ms | 25 ms | 0 |
| 2 | 2000 | 249 | 3.6 ms | 6.8 ms | 58 ms | 735 ms | 0 |
| 4 | 4000 | 231 | 3.8 ms | 8.8 ms | 185 ms | 1.7 s | 0 |

Split for one worker: `submit_intent` p50 1.4 ms, `execute` p50 2.2 ms. Half
the calls denied (`--scenario mixed`) runs at 367 req/s on one worker — a
denial is signed and chained too, but never executed.

## What the numbers say

**One decision costs a few milliseconds.** Next to an upstream that takes
tens or hundreds, the gateway is not where the time goes.

**Throughput is one writer's, however many workers.** Every request writes
the ledger (reservation, receipt, chain entry) inside `BEGIN IMMEDIATE`, and
SQLite admits one writer at a time. More workers do not add throughput; they
queue for the lock, and that queue is the tail: p99 grows from 8 ms to 185 ms
at four workers. Use workers for concurrency of slow upstream calls, not for
decision throughput.

**Overload is refused, not waved through.** A writer waits up to
`busy_timeout` (5 s) for the lock. Beyond that the request fails — HTTP 503
from the engine's storage error, or a 500 when it is the rate limiter's write
that times out — and nothing is authorized or sent. No run above reached that
point.

## Limits of the method

- No HTTP layer, no TLS, no network hop: add the gateway's own overhead and
  the upstream's latency to these numbers.
- A disk-backed file. On `tmpfs` fsync costs nothing and the numbers flatter
  a real deployment; the script says so when the store is on one.
- One VM, one run each. Variance between runs is visible in the tail.
- A ledger one process writes at a time is a design choice, not an accident:
  one file an auditor can copy and verify without a key. A deployment that
  needs more than a few hundred decisions a second needs a different ledger
  backend, which Mandate does not have today.
