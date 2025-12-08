# injector/core/markers.py

import logging
from .config import get_plc_config
from . import modbus

log = logging.getLogger(__name__)

def write_marker(value: int) -> None:
    """
    Zapisuje znacznik do marker_register z configu.
    Użyj np. przed/po scenariuszu albo przed atakiem.
    """
    cfg = get_plc_config()
    addr = cfg.marker_register
    log.info("Writing marker %s to HR[%s]", value, addr)
    modbus.write_holding_register(addr, value, cfg)
