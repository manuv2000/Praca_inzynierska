# injector/core/modbus.py

import logging
from contextlib import contextmanager
from typing import Optional, List

from pymodbus.client import ModbusTcpClient

from .config import PlcConfig, get_plc_config

log = logging.getLogger(__name__)


@contextmanager
def modbus_client(cfg: Optional[PlcConfig] = None):
    if cfg is None:
        cfg = get_plc_config()

    client = ModbusTcpClient(cfg.host, port=cfg.port)
    try:
        if not client.connect():
            raise RuntimeError(f"Could not connect to PLC at {cfg.host}:{cfg.port}")
        log.info("Connected to PLC at %s:%s", cfg.host, cfg.port)
        yield client
    finally:
        client.close()
        log.info("Connection closed")


def read_holding_registers(
    address: int,
    count: int = 1,
    cfg: Optional[PlcConfig] = None,
) -> List[int]:
    cfg = cfg or get_plc_config()
    with modbus_client(cfg) as client:
        rr = client.read_holding_registers(address, count, unit=cfg.unit_id)
        if rr.isError():
            raise RuntimeError(f"Modbus error reading HR[{address}] x{count}: {rr}")
        return list(rr.registers)


def write_holding_register(
    address: int,
    value: int,
    cfg: Optional[PlcConfig] = None,
) -> None:
    cfg = cfg or get_plc_config()
    with modbus_client(cfg) as client:
        rq = client.write_register(address, value, unit=cfg.unit_id)
        if rq.isError():
            raise RuntimeError(f"Modbus error writing HR[{address}] = {value}: {rq}")
