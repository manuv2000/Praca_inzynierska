# injector/traffic/normal_client.py

import logging
import random
import time
from threading import Event
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.core.modbus import modbus_client

log = logging.getLogger(__name__)

def run_normal_client(
    cfg: Optional[PlcConfig] = None,
    read_base: int = 0,
    read_count: int = 10,
    period_s: float = 0.5,
    jitter_s: float = 0.1,
    write_prob: float = 0.1,  # prawdopodobieństwo zapisu w jednym cyklu
    stop_event: Optional[Event] = None,
) -> None:
    """
    Drugi, lekki klient:
      - cyklicznie czyta blok HR[read_base..read_base+read_count-1]
      - z pewnym prawdopodobieństwem wykonuje 'bezpieczny' zapis do safe_write_register
        w zakresie [safe_write_min, safe_write_max], potem robi read-back.
    """

    cfg = cfg or get_plc_config()
    log.info(
        "Starting normal client: read HR[%s..%s], period=%.3fs, jitter=±%.3fs, write_prob=%.2f",
        read_base,
        read_base + read_count - 1,
        period_s,
        jitter_s,
        write_prob,
    )

    try:
        with modbus_client(cfg) as client:
            while True:
                if stop_event is not None and stop_event.is_set():
                    log.info("Stop event set, leaving normal client loop")
                    break

                t0 = time.perf_counter()

                # 1) Odczyt bloku
                try:
                    rr = client.read_holding_registers(
                        read_base, read_count, unit=cfg.unit_id
                    )
                    if rr.isError():
                        log.warning("Normal client read error: %s", rr)
                    else:
                        values = list(rr.registers)
                        log.debug(
                            "Normal client read HR[%s..%s] = %s",
                            read_base,
                            read_base + read_count - 1,
                            values,
                        )
                except Exception as e:
                    log.warning("Normal client read exception: %s", e)

                # 2) Zapis
                if random.random() < write_prob:
                    addr = cfg.safe_write_register
                    val = random.randint(cfg.safe_write_min, cfg.safe_write_max)
                    try:
                        log.info("Normal client writing HR[%s] = %s", addr, val)
                        wq = client.write_register(addr, val, unit=cfg.unit_id)
                        if wq.isError():
                            log.warning("Normal client write error: %s", wq)
                        else:
                            # read-back
                            rb = client.read_holding_registers(
                                addr, 1, unit=cfg.unit_id
                            )
                            if rb.isError():
                                log.warning("Normal client read-back error: %s", rb)
                            else:
                                rb_val = rb.registers[0]
                                log.info(
                                    "Normal client read-back HR[%s] = %s (expected %s)",
                                    addr,
                                    rb_val,
                                    val,
                                )
                    except Exception as e:
                        log.warning("Normal client write exception: %s", e)

                dt = period_s + random.uniform(-jitter_s, jitter_s)
                if dt < 0.0:
                    dt = 0.0
                elapsed = time.perf_counter() - t0
                sleep_time = max(0.0, dt - elapsed)
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        log.info("Normal client loop interrupted by user")
