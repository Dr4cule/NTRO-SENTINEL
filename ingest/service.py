"""24/7 ingest service: live capture + file replay -> one detection Pipeline -> AlertStore.

Single writer (one consumer thread) so the tamper-evident hash chain stays serialized while
many sources feed it. Everything it stores lands in the same artifacts/sentinel.db the API/
dashboard already reads, so alerts show up live (WebSocket polls the store every ~1s).

Sources (any combination, run together):
  --live IFACE     sniff a NIC continuously (needs root / CAP_NET_RAW)
  --watch DIR      drop .pcap/.pcapng or .jsonl/Zeek-json files in; ingested then moved to processed/
  --file PATH      ingest a file now (repeatable); with --once, ingest those and exit

  python -m ingest.service --file capture.pcap --once          # one-shot: populate dashboard, exit
  python -m ingest.service --live eth0 --watch artifacts/inbox # 24/7: live + drop-in files
"""
from __future__ import annotations
import argparse, json, os, queue, sys, tempfile, threading, time
from pathlib import Path
from engine.stream_consumer import Pipeline
from engine.metrics import StreamMetrics
from alertstore.store import AlertStore
from ingest.pcap_to_events import ingest_packet, _conn_event, build_events
from ingest.tailer import normalize

STOP = threading.Event()
PCAP_EXT = {'.pcap', '.pcapng', '.cap'}

def consumer(q, store, pipeline, metrics, stop=STOP):
    """The ONLY writer to the store -> hash chain stays consistent. `stop` defaults to the
    global STOP (live/CLI runs); an upload passes its own event so repeated calls are isolated."""
    last_metric = 0.0
    while not (stop.is_set() and q.empty()):
        try: e = q.get(timeout=.5)
        except queue.Empty: continue
        t = time.perf_counter()
        alerts = pipeline.process(e)
        for a in alerts: store.append(a)
        metrics.observe((time.perf_counter() - t) * 1000, len(alerts))
        now = time.time()
        if now - last_metric >= 2: store.metric(**metrics.snapshot()); last_metric = now
        q.task_done()
    store.metric(**metrics.snapshot())

def ingest_file(path, q):
    """Replay a pcap or a line-delimited Zeek/event JSON file into the queue."""
    p = Path(path)
    if p.suffix.lower() in PCAP_EXT:
        for e in build_events(str(p), int(os.getenv('MAX_PACKETS', '2000000'))): q.put(e)
    else:
        with p.open() as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    q.put(rec if 'kind' in rec else normalize(rec, p.stem))
    print(f'[file] ingested {p}', file=sys.stderr)

_UPLOAD_LOCK = threading.Lock()
MAX_UPLOAD_BYTES = 300 * 1024 * 1024  # ponytail: whole upload buffered in RAM; stream to disk if >300MB captures matter

def ingest_upload(filename, data):
    """Analyze one uploaded capture/log end-to-end: parse -> detect -> append to the same
    artifacts/sentinel.db the dashboard reads. Serialized (one writer at a time) so the
    tamper-evident hash chain stays consistent. Returns {'file','alerts_added','total_alerts'}."""
    if not data: raise ValueError('empty upload')
    if len(data) > MAX_UPLOAD_BYTES: raise ValueError(f'upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB cap')
    name = Path(filename or 'upload.jsonl').name
    suffix = Path(name).suffix.lower()
    if suffix not in PCAP_EXT and suffix not in {'.jsonl', '.json', '.log'}: suffix = '.jsonl'  # unknown -> line-json
    with _UPLOAD_LOCK:
        store, pipeline, metrics = AlertStore(), Pipeline(), StreamMetrics()
        before = store.summary()['total_alerts']
        q = queue.Queue(maxsize=100000); stop = threading.Event()
        ct = threading.Thread(target=consumer, args=(q, store, pipeline, metrics, stop), daemon=True); ct.start()
        with tempfile.NamedTemporaryFile(suffix=suffix) as tf:
            tf.write(data); tf.flush()
            try: ingest_file(tf.name, q); q.join()
            finally: stop.set(); ct.join(timeout=60)
        total = store.summary()['total_alerts']
    return {'file': name, 'alerts_added': total - before, 'total_alerts': total}

def watch_inbox(inbox, q, seen):
    box = Path(inbox); (box / 'processed').mkdir(parents=True, exist_ok=True)
    print(f'[watch] drop pcap/jsonl into {box}', file=sys.stderr)
    while not STOP.is_set():
        for p in sorted(box.glob('*')):
            if p.is_file() and p.name not in seen:
                seen.add(p.name)
                try: ingest_file(p, q); p.rename(box / 'processed' / p.name)
                except Exception as ex: print(f'[watch] {p.name} failed: {ex}', file=sys.stderr)
        STOP.wait(2)

class LiveCapture:
    """Streaming flow assembler over a live NIC. Flows are emitted as conn events once idle
    (finalization latency ~= idle seconds), matching how Zeek closes a connection."""
    def __init__(self, iface, q, idle=10, max_flows=50000):
        self.iface, self.q, self.idle, self.max_flows = iface, q, idle, max_flows
        self.flows = {}; self.lock = threading.Lock(); self.sniffer = None
    def _on(self, pkt):
        dns_out = []
        with self.lock: ingest_packet(pkt, self.flows, dns_out)
        for d in dns_out: self.q.put(d)
    def _flush(self, now, final=False):
        with self.lock:
            over = len(self.flows) > self.max_flows  # bound memory on 24/7 runs
            due = list(self.flows) if (final or over) else [k for k, f in self.flows.items() if now - f['last'] >= self.idle]
            for k in due: self.q.put(_conn_event(k, self.flows.pop(k)))
    def _flush_loop(self):
        while not STOP.is_set(): STOP.wait(max(self.idle / 2, 1)); self._flush(time.time())
        self._flush(time.time(), final=True)
    def start(self):
        from scapy.all import AsyncSniffer
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            print('[live] warning: not root — live capture usually needs root or CAP_NET_RAW', file=sys.stderr)
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self._on, store=False); self.sniffer.start()
        threading.Thread(target=self._flush_loop, daemon=True).start()
        print(f'[live] capturing on {self.iface}', file=sys.stderr)

def main():
    ap = argparse.ArgumentParser(description='24/7 ingest: live capture + file replay -> dashboard')
    ap.add_argument('--live', metavar='IFACE', help='sniff this interface continuously (needs root)')
    ap.add_argument('--watch', metavar='DIR', help='watch dir for drop-in pcap/jsonl files')
    ap.add_argument('--file', action='append', default=[], help='ingest a file now (repeatable)')
    ap.add_argument('--once', action='store_true', help='ingest --file args, then exit (no live/watch)')
    args = ap.parse_args()
    q = queue.Queue(maxsize=100000)
    store, pipeline, metrics = AlertStore(), Pipeline(), StreamMetrics()
    ct = threading.Thread(target=consumer, args=(q, store, pipeline, metrics), daemon=True); ct.start()
    for fp in args.file: ingest_file(fp, q)
    if args.once:
        q.join(); STOP.set(); ct.join(timeout=10)
        print(f'[service] done: {store.summary()["total_alerts"]} alerts in store', file=sys.stderr); return
    if args.watch: threading.Thread(target=watch_inbox, args=(args.watch, q, set()), daemon=True).start()
    live = None
    if args.live:
        live = LiveCapture(args.live, q)
        try: live.start()
        except Exception as ex: print(f'[live] disabled: {ex}', file=sys.stderr); live = None
    print('[service] running — Ctrl-C to stop. Dashboard: http://localhost:8000', file=sys.stderr)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print('\n[service] draining…', file=sys.stderr); STOP.set()
        if live and live.sniffer:
            try: live.sniffer.stop()  # scapy can't always stop an AsyncSniffer socket cleanly
            except Exception:
                exc = getattr(live.sniffer, 'exception', None)
                if exc: print(f'[live] sniffer error: {exc!r}', file=sys.stderr)
        ct.join(timeout=5)  # daemon sniffer thread dies with us; bounded drain won't hang on a live socket

if __name__ == '__main__':
    main()

