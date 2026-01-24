import time
import logging

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.core import modbus

log = logging.getLogger(__name__)

def main() -> None:
    setup_logging("INFO")
    cfg = get_plc_config()
    log.info("Starting PLC health check for %s:%s (unit %s)",
             cfg.host, cfg.port, cfg.unit_id)

    # 1. Odczyt heartbeat_register
    hr_addr = cfg.heartbeat_register
    try:
        value = modbus.read_holding_registers(hr_addr, 1, cfg)[0]
        log.info("Read HR[%s] = %s", hr_addr, value)
    except Exception as e:
        log.error("Failed to read heartbeat register: %s", e)
        return

    # 2. Pomiary czasu odpowiedzi (np. 10 próbek)
    samples = 10
    latencies = []
    for i in range(samples):
        t0 = time.perf_counter()
        try:
            _ = modbus.read_holding_registers(hr_addr, 1, cfg)
        except Exception as e:
            log.error("Error during sample %s: %s", i, e)
            continue
        dt = (time.perf_counter() - t0) * 1000.0  # ms
        latencies.append(dt)
        time.sleep(0.1)

    if not latencies:
        log.error("No successful samples, PLC health check failed")
        return

    avg = sum(latencies) / len(latencies)
    p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1]
    log.info("Latency: mean=%.2f ms, p95=%.2f ms (n=%d)", avg, p95, len(latencies))
    log.info("PLC health check OK")

if __name__ == "__main__":
    main()
