"""The PEER side of the test segment: terminates flows on veth-sink (10.99.0.2).

Three behaviours, selected by port, so a single listener can produce all the shapes the
detectors need — over a real interface the sensor sniffs:

  9101  SINK   accepts a connection, reads it and NEVER replies with a body
               -> large outbound, near-zero inbound = exfiltration (T1041)
  9200  BEACON replies with a fixed heartbeat every connection
               -> periodic low-jitter sessions = c2 beaconing (T1071.001)
  9999  CLOSED nothing listening, so connections RST
               -> failure states, for scan-shaped traffic

Usage: python tools/sink.py
"""
import socket, sys, threading, time

BIND = '0.99.0.2'  # replaced below; kept explicit so the intent is obvious
BIND = '0.0.0.0'


def drain(c, reply=None):
    try:
        c.settimeout(30)
        while True:
            d = c.recv(65536)
            if not d:
                break
            if reply:
                try:
                    c.sendall(reply)
                except OSError:
                    break
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def serve(port, reply=None, name=''):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, port))
    s.listen(128)
    print(f'[sink:{name}] listening on {BIND}:{port}', flush=True)
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            return
        threading.Thread(target=drain, args=(c, reply), daemon=True).start()


if __name__ == '__main__':
    threading.Thread(target=serve, args=(9101, None, 'exfil-sink'), daemon=True).start()
    threading.Thread(target=serve, args=(9200, b'\x00' * 512, 'c2-beacon'), daemon=True).start()
    threading.Thread(target=serve, args=(9001, b'\x00' * 512, 'lateral-c2'), daemon=True).start()
    print('[sink] ready on 9101 (exfil) / 9200 (beacon); 9999 left closed for RST', flush=True)
    while True:
        time.sleep(3600)
