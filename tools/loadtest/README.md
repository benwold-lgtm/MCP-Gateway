# Load-test harness (F-22)

A self-contained async load generator for the Device MCP Gateway. No dependencies beyond
`httpx` (already a gateway runtime dependency). For the full methodology — warmup, finding
the knee, recording a baseline, interpreting against SLOs — see
[`docs/load-testing.md`](../../docs/load-testing.md).

## Run

```bash
pip install -e .

# End-to-end tool-call latency/throughput
python -m tools.loadtest.loadgen toolcall \
  --base-url http://localhost:8000 --device my-sensor \
  --tool get_readings --arguments '{"sensor_id": 1}' \
  --api-key "$MCP_GATEWAY_API_KEY" \
  --concurrency 20 --rps 200 --duration 300 --out baseline.json

# Device-registration throughput
python -m tools.loadtest.loadgen register \
  --base-url http://localhost:8000 --api-key "$MCP_GATEWAY_API_KEY" \
  --target-url http://stub-device:8080 --concurrency 10 --duration 60
```

`python -m tools.loadtest.loadgen --help` lists all flags.

## Workloads

- **`toolcall`** — each virtual client opens an SSE stream, reads its session `endpoint`,
  then POSTs `tools/call` messages and times the round-trip to the result event. Requires
  a registered `--device` and a valid `--tool`.
- **`register`** — each client POSTs `/v1/devices` with generated hostnames. Use a cheap
  `--target-url` (it only needs to be reachable; registration latency is the metric).

## Notes

- `--rps` caps the **aggregate** offered rate (token bucket) across all clients; `0` =
  open loop (as fast as concurrency allows).
- Point devices at a **fixed-latency stub** to measure the gateway's own overhead; point at
  a real/faithful mock to capacity-plan.
- This is a load (performance) tool only — fault injection / chaos is **F-63**, separate.
- The pure helpers (percentiles, SSE parsing, stats) are unit-tested in
  `tests/test_loadgen.py`; the networked workloads need a live gateway.
