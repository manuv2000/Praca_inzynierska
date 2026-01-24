import logging
from dataclasses import dataclass
from threading import Event
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.runtime.task_runner import run_task_loop, LoopTiming

log = logging.getLogger(__name__)


@dataclass
class ScanState:
    start_addr: int
    end_addr: int
    block_size: int
    addr: int = 0

    def __post_init__(self):
        if self.addr == 0:
            self.addr = self.start_addr


def _tick_scan(*, client, cfg: PlcConfig, state: ScanState) -> None:
    if state.addr > state.end_addr:
        state.addr = state.start_addr

    count = min(state.block_size, state.end_addr - state.addr + 1)

    rr = client.read_holding_registers(state.addr, count, unit=cfg.unit_id)
    if rr.isError():
        log.warning("Scan read error at HR[%s] x%s: %s", state.addr, count, rr)
    else:
        log.debug("Scan read HR[%s..%s] = %s", state.addr, state.addr + count - 1, list(rr.registers))

    state.addr += count


def run_scan_readonly(
    cfg: Optional[PlcConfig] = None,
    start_addr: int = 0,
    end_addr: int = 199,
    block_size: int = 10,
    delay_s: float = 0.01,
    stop_event: Optional[Event] = None,
) -> None:
    cfg = cfg or get_plc_config()
    run_task_loop(
        name="SCAN_RO",
        cfg=cfg,
        stop_event=stop_event,
        tick=_tick_scan,
        state=ScanState(start_addr=start_addr, end_addr=end_addr, block_size=block_size),
        timing=LoopTiming(period_s=delay_s, jitter_s=0.0),
        connection_mode="persistent",
    )
