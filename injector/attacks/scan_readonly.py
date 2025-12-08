# injector/attacks/scan_readonly.py

import logging
import time
from threading import Event
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.core.modbus import modbus_client

log = logging.getLogger(__name__)

def run_scan_readonly(
    cfg: Optional[PlcConfig] = None,
    start_addr: int = 0,
    end_addr: int = 199,
    block_size: int = 10,
    delay_s: float = 0.01,
    stop_event: Optional[Event] = None,
) -> None:
    """
    Read-only scan:
      - przechodzi po zakresie adresów [start_addr, end_addr]
      - czyta bloki po block_size rejestrów
      - NIE wykonuje żadnych zapisów
      - powtarza do czasu Ctrl+C albo ustawienia stop_event
    """

    cfg = cfg or get_plc_config()
    log.info(
        "Starting READ-ONLY scan: HR[%s..%s], block_size=%s, delay=%.3fs",
        start_addr, end_addr, block_size, delay_s,
    )

    try:
        with modbus_client(cfg) as client:
            while True:
                if stop_event is not None and stop_event.is_set():
                    log.info("Stop event set, leaving scan_readonly loop")
                    break

                addr = start_addr
                while addr <= end_addr:
                    if stop_event is not None and stop_event.is_set():
                        break

                    count = min(block_size, end_addr - addr + 1)
                    try:
                        rr = client.read_holding_registers(
                            addr, count, unit=cfg.unit_id
                        )
                        if rr.isError():
                            log.warning("Scan read error at HR[%s] x%s: %s",
                                        addr, count, rr)
                        else:
                            # log na DEBUG, żeby nie zalać outputu
                            log.debug("Scan read HR[%s..%s] = %s",
                                      addr, addr + count - 1, list(rr.registers))
                    except Exception as e:
                        log.warning("Scan read exception at HR[%s]: %s", addr, e)

                    addr += count
                    time.sleep(delay_s)

    except KeyboardInterrupt:
        log.info("scan_readonly interrupted by user")
