#!/usr/bin/env python3
"""Closed-loop local load test: replay controlled telemetry at increasing target
rates and record the full processing envelope until the highest *stable* rate is
found. Measures flows/sec, Mbps, backlog/drops, p50/p95/p99 alert latency, CPU and
peak memory. Synchronous in-process path (Redis stream lag is measured separately by
the live worker's metrics endpoint). This is NOT a PCAP/Mbps network benchmark.

Usage:  python3 -m eval.loadtest --duration 30 --rates 2000,5000,10000,20000,40000
"""
from __future__ import annotations
import argparse, json, platform, resource, sys, time
from pathlib import Path
from engine.stream_consumer import Pipeline

MB = 1_000_000
PEAK_RSS_DIVISOR = 1024 if sys.platform == "darwin" else 1  # ru_maxrss: bytes on macOS, KB on Linux


def load_pool(paths):
    """Read scenario JSONL(s) into a list of (event, byte_len)."""
    pool = []
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if line.strip():
                pool.append((json.loads(line), len(line.encode())))
    if not pool:
        raise SystemExit("no events loaded from " + ", ".join(paths))
    return pool


def run_step(pool, target_eps, duration):
    """Feed events paced at target_eps for `duration` wall-seconds; measure what the
    pipeline actually sustained. If it can't keep up, unfed events count as drops."""
    engine = Pipeline()
    lats, processed, bytes_done, alerts = [], 0, 0, 0
    ru0 = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    deadline = t0 + duration
    n = len(pool)
    interval = 1.0 / target_eps
    next_send = t0
    i = 0
    while True:
        now = time.perf_counter()
        if now >= deadline:
            break
        if now < next_send:                    # ahead of schedule → pipeline is keeping up
            time.sleep(min(next_send - now, deadline - now))
            continue
        event, blen = pool[i % n]
        i += 1
        ing = time.perf_counter()
        alerts += len(engine.process(event))
        lats.append((time.perf_counter() - ing) * 1000)
        processed += 1
        bytes_done += blen
        next_send += interval
    elapsed = max(time.perf_counter() - t0, 1e-9)
    ru1 = resource.getrusage(resource.RUSAGE_SELF)
    offered = int(duration * target_eps)
    dropped = max(0, offered - processed)
    lats.sort()
    q = lambda f: round(lats[int((len(lats) - 1) * f)], 3) if lats else None
    cpu_s = (ru1.ru_utime + ru1.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
    achieved = processed / elapsed
    return {
        "target_eps": target_eps,
        "achieved_eps": round(achieved, 1),
        "achieved_mbps": round(bytes_done * 8 / elapsed / MB, 3),
        "offered": offered, "processed": processed, "dropped": dropped,
        "drop_pct": round(dropped / offered * 100, 2) if offered else 0.0,
        "alerts": alerts,
        "latency_ms": {"p50": q(.5), "p95": q(.95), "p99": q(.99)},
        "cpu_pct": round(cpu_s / elapsed * 100, 1),
        "peak_rss_mb": round(ru1.ru_maxrss / PEAK_RSS_DIVISOR / 1024, 1),
        # stable = sustained >=95% of offered flows/sec and lost <1% (tolerates generator jitter)
        "stable": achieved >= target_eps * 0.95 and (dropped / offered * 100 if offered else 0) < 1.0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", nargs="+", default=[
        "traffic-gen/scenarios/ddos.jsonl", "traffic-gen/scenarios/recon.jsonl",
        "traffic-gen/scenarios/c2.jsonl", "traffic-gen/scenarios/dns.jsonl",
        "traffic-gen/scenarios/exfil.jsonl", "traffic-gen/scenarios/benign.jsonl"])
    ap.add_argument("--rates", default="2000,5000,10000,20000,40000",
                    help="comma-separated target flows/sec steps")
    ap.add_argument("--duration", type=float, default=5.0, help="wall-seconds per step")
    ap.add_argument("--output", default="artifacts/loadtest.json")
    a = ap.parse_args()

    pool = load_pool(a.scenario)
    rates = [int(x) for x in a.rates.split(",") if x.strip()]
    steps = [run_step(pool, r, a.duration) for r in rates]
    stable = [s for s in steps if s["stable"]]
    cmd = "python3 -m eval.loadtest --duration %g --rates %s" % (a.duration, a.rates)
    out = {
        "definition": "closed-loop synthetic-telemetry ingestion to in-memory alert creation; "
                      "highest stable rate = last step sustaining >=95% of offered flows/sec with <1% drops",
        "command": cmd,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "cpu_count": __import__("os").cpu_count()},
        "pool_events": len(pool),
        "steps": steps,
        "highest_stable_eps": max((s["target_eps"] for s in stable), default=0),
        "warning": "Not a PCAP Mbps network benchmark. Redis-consumer stream lag/drops under the "
                   "deployed path are exposed by the worker at /api/dashboard/summary.pipeline; "
                   "run scripts/run_pcap_replay.sh with live Zeek for production-like proof.",
    }
    Path("artifacts").mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(out, indent=2))
    md = ["# Load Test — Local Processing Envelope", "", out["definition"], "",
          "Command: `%s`" % cmd, "",
          "Environment: %s · Python %s · %s CPUs" % (out["environment"]["platform"],
          out["environment"]["python"], out["environment"]["cpu_count"]), "",
          "| Target f/s | Achieved | Mbps | Drops | p50 ms | p95 ms | p99 ms | CPU% | RSS MB | Stable |",
          "|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|"]
    for s in steps:
        L = s["latency_ms"]
        md.append("| %d | %.0f | %.3f | %d (%.1f%%) | %s | %s | %s | %.1f | %.1f | %s |" % (
            s["target_eps"], s["achieved_eps"], s["achieved_mbps"], s["dropped"], s["drop_pct"],
            L["p50"], L["p95"], L["p99"], s["cpu_pct"], s["peak_rss_mb"], "✓" if s["stable"] else "—"))
    md += ["", "Highest stable rate: **%d flows/sec**." % out["highest_stable_eps"], "", out["warning"]]
    Path("artifacts/loadtest.md").write_text("\n".join(md) + "\n")
    print(json.dumps({k: out[k] for k in ("command", "highest_stable_eps", "pool_events")}, indent=2))
    print("wrote", a.output, "and artifacts/loadtest.md")


if __name__ == "__main__":
    main()
