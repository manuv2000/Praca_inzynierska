# injector/core/config.py

from dataclasses import dataclass

@dataclass
class PlcConfig:
    host: str = "127.0.0.1"
    port: int = 502
    unit_id: int = 1
    heartbeat_register: int = 0
    marker_register: int = 10

    safe_write_register: int = 2      # np. %MW2
    safe_write_min: int = 0           # minimalna wartość
    safe_write_max: int = 1000        # maksymalna wartość

def get_plc_config() -> PlcConfig:
    return PlcConfig()
