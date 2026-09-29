"""Attack traffic against the monitored test segment (10.99.0.2), for a live end-to-end demo.

Both shapes need a peer that genuinely completes flows, which is why they run against the veth
segment rather than an unrouted TEST-NET address:

  exfiltration  N separate sessions, ~1MB out each, sink never replies with a body
                -> outbound >=500KB, ratio >=5, sessions >=3  (T1041)
  c2 beaconing  fixed-interval sessions to one port, heartbeat-sized replies
                -> >=5 sessions, inter-arrival CV <=0.12, persistence >=120s  (T1071.001)

Usage: python tools/gen_segment_attacks.py [exfil|beacon|both]
"""
import socket, statistics, sys, time

EXFIL_PEER = '10.99.0.2'   # bulk upload channel
BEACON_PEER = '10.99.0.3' # periodic heartbeat channel, kept SEPARATE so the exfil volume
                          # does not sit in the C2 detector's feature window (it keys on src|dst)
SINK_PORT = 9101     # reads, never replies
BEACON_PORT = 9001   # Tor: deliberately absent from the detector's internal-service allowlist, so a private-destination beacon is judged as lateral C2 (T1021)


def exfil(sessions=8, mb_each=1, gap=1.0):
    print(f'[*] exfiltration: {sessions} sessions x {mb_each}MB -> {EXFIL_PEER}:{SINK_PORT} (sink never replies)')
    blob = b'\x00' * (1 << 20)
    done = 0
    for i in range(sessions):
        try:
            s = socket.socket()
            s.settimeout(10)
            s.connect((EXFIL_PEER, SINK_PORT))
            for _ in range(mb_each):
                s.sendall(blob)
            s.close()
            done += 1
            print(f'    session {i+1}/{sessions}: {mb_each}MB out, 0B back')
        except OSError as e:
            print(f'    session {i+1} failed: {type(e).__name__} {e}')
            break
        time.sleep(gap)
    print(f'[+] exfil done: {done} sessions')
    time.sleep(15)
    return done


def beacon(sessions=15, period=9.0):
    print(f'[*] c2 beaconing: {sessions} sessions every {period}s -> {BEACON_PEER}:{BEACON_PORT} '
          f'({period*(sessions-1):.0f}s persistence)')
    stamps, done = [], 0
    for i in range(sessions):
        t0 = time.time()
        try:
            s = socket.socket()
            s.settimeout(6)
            s.connect((BEACON_PEER, BEACON_PORT))
            s.sendall(bytes([i % 256]) * 256)
            try:
                s.recv(4096)
            except OSError:
                pass
            s.close()
            done += 1
        except OSError as e:
            print(f'    beacon {i+1} failed: {type(e).__name__}')
        stamps.append(t0)
        print(f'    beacon {i+1}/{sessions} at t+{t0-stamps[0]:.0f}s')
        if i < sessions - 1:
            time.sleep(period)
    if len(stamps) > 2:
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        cv = statistics.pstdev(gaps) / max(1e-9, statistics.mean(gaps))
        print(f'[+] {done} beacons, inter-arrival CV={cv:.4f} (detector needs <=0.12), '
              f'persistence={stamps[-1]-stamps[0]:.0f}s (needs >=120s)')
    time.sleep(15)


if __name__ == '__main__':
    which = (sys.argv[1] if len(sys.argv) > 1 else 'both').lower()
    if which in ('exfil', 'both'):
        exfil()
    if which in ('beacon', 'both'):
        beacon()
    print('[+] segment attacks complete')
