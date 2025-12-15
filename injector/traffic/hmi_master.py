# injector/traffic/hmi_master.py

import logging
import random
import time
from typing import Optional
from threading import Event

from injector.core.config import get_plc_config, PlcConfig
from injector.core.modbus import modbus_client  # <- ważne

log = logging.getLogger(__name__)

def run_hmi_loop(
    cfg: Optional[PlcConfig] = None,
    base_address: int = 0,
    count: int = 10,
    period_s: float = 0.2,
    jitter_s: float = 0.05,
    stop_event: Optional[Event] = None,
) -> None:
    cfg = cfg or get_plc_config()
    log.info(
        "Starting HMI loop: HR[%s..%s], period=%.3fs, jitter=±%.3fs",
        base_address,
        base_address + count - 1,
        period_s,
        jitter_s,
    )

    try:
        with modbus_client(cfg) as client:
            while True:
                if stop_event is not None and stop_event.is_set():
                    log.info("Stop event set, leaving HMI loop")
                    break

                t0 = time.perf_counter()
                try:
                    rr = client.read_holding_registers(
                        base_address, count, unit=cfg.unit_id
                    )
                    if rr.isError():
                        log.warning("HMI read error: %s", rr)
                    else:
                        values = list(rr.registers)
                        log.debug(
                            "HMI read HR[%s..%s] = %s",
                            base_address,
                            base_address + count - 1,
                            values,
                        )
                except Exception as e:
                    log.warning("HMI read exception: %s", e)

                dt = period_s + random.uniform(-jitter_s, jitter_s)
                if dt < 0.0:
                    dt = 0.0
                elapsed = time.perf_counter() - t0
                sleep_time = max(0.0, dt - elapsed)

                if stop_event is None:
                    time.sleep(sleep_time)
                else:
                    stop_event.wait(timeout=sleep_time)


    except KeyboardInterrupt:
        log.info("HMI loop interrupted by user")
