"""Sustained outbound upload to a local sink -> the exfiltration shape (large out, tiny in).

The unrouted TEST-NET trick used by the other generators sends bytes into the void, so no
response ever arrives and the flow may never be finalised with byte counts. This one peers with
a sink we start ourselves on this host's subnet address, so the exchange completes and the
out/in byte ratio the detector needs is real.

Usage: python tools/gen_exfil.py [mb] [seconds]
"""
import socket, sys, threading, time

MB = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
SESSIONS = int(sys.argv[3]) if len(sys.argv) > 3 else 6
PORT = 9101

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', PORT))
srv.listen(32)
stop = threading.Event()
conns = []


def serve():
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except (socket.timeout, OSError):
            continue
        conns.append(c)
        threading.Thread(target=_drain, args=(c,), daemon=True).start()


def _drain(c):
    """Accept and discard, never echo -> large out, near-zero in."""
    try:
        c.settimeout(10)
        while c.recv(65536):
            pass
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


threading.Thread(target=serve, daemon=True).start()
time.sleep(0.5)

dst = next((a for a in socket.gethostbyname_ex(socket.gethostname())[2] if a.startswith('172.31.')), '127.0.0.1')
print(f'[*] {SESSIONS} separate sessions x ~{MB / SESSIONS:.1f} MB to {dst}:{PORT} '
      f'over {SECONDS}s (sink discards, never replies with a body)')

# The rule needs >=3 SESSIONS in the window as well as volume and ratio, so open a fresh
# connection per chunk rather than streaming everything down one socket.
per = max(1, int(MB / SESSIONS))
blob = b'\x00' * (1 << 20)
done, end = 0, time.time() + SECONDS
while done < SESSIONS and time.time() < end:
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((dst, PORT))
        for _ in range(per):
            s.sendall(blob)
        s.close()
        done += 1
        print(f'    session {done}/{SESSIONS}: {per} MB out')
    except OSError as e:
        print(f'    session failed: {e}')
        break
    time.sleep(1.0)
stop.set()
try:
    srv.close()
except OSError:
    pass
print(f'[+] completed {done} one-way sessions to {dst}:{PORT}')
time.sleep(20)
