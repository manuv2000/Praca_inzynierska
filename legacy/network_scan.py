# injector/attacks/network_scan.py
import socket, time

def run(host, ports=(502,), timeout=1.0):
    results = {}
    for p in ports:
        t0 = time.perf_counter()
        s = socket.socket(); s.settimeout(timeout)
        try:
            s.connect((host, p))
            results[p] = {"open": True, "rtt_ms": (time.perf_counter()-t0)*1000}
        except Exception:
            results[p] = {"open": False}
        finally:
            try: s.close()
            except: pass
    return results
