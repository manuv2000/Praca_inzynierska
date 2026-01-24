# injector/traffic/hmi_master.py

import logging
from dataclasses import dataclass
from threading import Event
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.runtime.task_runner import run_task_loop, LoopTiming

log = logging.getLogger(__name__)


@dataclass
class HmiState:
    base_address: int
    count: int


def _tick_hmi(*, client, cfg: PlcConfig, state: HmiState) -> None:
    rr = client.read_holding_registers(state.base_address, state.count, unit=cfg.unit_id)
    if rr.isError():
        log.warning("HMI read error: %s", rr)
    else:
        log.debug(
            "HMI read HR[%s..%s] = %s",
            state.base_address,
            state.base_address + state.count - 1,
            list(rr.registers),
        )


def run_hmi_loop(
    cfg: Optional[PlcConfig] = None,
    base_address: int = 0,
    count: int = 10,
    period_s: float = 0.2,
    jitter_s: float = 0.05,
    stop_event: Optional[Event] = None,
) -> None:
    """
    Public entrypoint kept stable for UI/runner compatibility.
    """
    cfg = cfg or get_plc_config()
    run_task_loop(
        name="HMI",
        cfg=cfg,
        stop_event=stop_event,
        tick=_tick_hmi,
        state=HmiState(base_address=base_address, count=count),
        timing=LoopTiming(period_s=period_s, jitter_s=jitter_s),
        connection_mode="persistent",
    )
