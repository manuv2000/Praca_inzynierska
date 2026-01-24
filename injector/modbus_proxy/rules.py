# injector/modbus_proxy/rules.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from injector.core.config import PlcConfig

class SpoofRule(Protocol):
    def should_spoof(self, cfg: PlcConfig, addr: int) -> bool: ...
    def spoof_value(self, cfg: PlcConfig, addr: int, real_value: int) -> int: ...

@dataclass(frozen=True)
class RangeOffsetRule:
    """
    Default rule:
    - spoof addresses in [start..end]
    - add offset modulo 65536
    """
    start: int = 0
    end: int = 9
    offset: int = 1000

    def should_spoof(self, cfg: PlcConfig, addr: int) -> bool:
        return self.start <= addr <= self.end

    def spoof_value(self, cfg: PlcConfig, addr: int, real_value: int) -> int:
        return (real_value + self.offset) & 0xFFFF
