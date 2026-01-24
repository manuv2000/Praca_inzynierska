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
    end_addr: int = 200,
    block_size: int = 10,
    delay_s: float = 0.01,
    stop_event: Optional[Event] = None,
) -> None:
    """
    READ-ONLY scan:
      - iteruje po zakresach HR[start_addr..end_addr]
      - czyta block_size rejestrów naraz
      - delay_s między kolejnymi odczytami
    """
    cfg = cfg or get_plc_config()
    log.info(
        "Starting READ-ONLY scan: HR[%s..%s], block_size=%s, delay=%.3fs",
        start_addr, end_addr, block_size, delay_s,
    )

    try:
        with modbus_client(cfg) as client:
            addr = start_addr
            while True:
                if stop_event is not None and stop_event.is_set():
                    log.info("Stop event set, leaving scan_readonly loop")
                    break

                if addr > end_addr:
                    addr = start_addr

                try:
                    rr = client.read_holding_registers(
                        addr, block_size, unit=cfg.unit_id
                    )
                    if rr.isError():
                        log.warning("scan_readonly error at HR[%s]: %s", addr, rr)
                    else:
                        log.debug("scan_readonly read HR[%s..%s]",
                                  addr, addr + block_size - 1)
                except Exception as e:
                    log.warning("scan_readonly exception at HR[%s]: %s", addr, e)

                addr += block_size
                time.sleep(delay_s)

    except KeyboardInterrupt:
        log.info("scan_readonly interrupted by user")
