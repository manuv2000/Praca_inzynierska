import logging
import random
from dataclasses import dataclass
from threading import Event
from typing import Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.runtime.task_runner import run_task_loop, LoopTiming

log = logging.getLogger(__name__)


@dataclass
class NormalClientState:
    read_base: int
    read_count: int
    write_prob: float


def _tick_normal_client(*, client, cfg: PlcConfig, state: NormalClientState) -> None:
    rr = client.read_holding_registers(state.read_base, state.read_count, unit=cfg.unit_id)
    if rr.isError():
        log.warning("Normal client read error: %s", rr)
    else:
        log.debug(
            "Normal client read HR[%s..%s] = %s",
            state.read_base,
            state.read_base + state.read_count - 1,
            list(rr.registers),
        )

    if random.random() < state.write_prob:
        addr = cfg.safe_write_register
        val = random.randint(cfg.safe_write_min, cfg.safe_write_max)
        log.info("Normal client writing HR[%s] = %s", addr, val)

        wq = client.write_register(addr, val, unit=cfg.unit_id)
        if wq.isError():
            log.warning("Normal client write error: %s", wq)
            return

        rb = client.read_holding_registers(addr, 1, unit=cfg.unit_id)
        if rb.isError():
            log.warning("Normal client read-back error: %s", rb)
        else:
            rb_val = rb.registers[0]
            log.info("Normal client read-back HR[%s] = %s (expected %s)", addr, rb_val, val)


def run_normal_client(
    cfg: Optional[PlcConfig] = None,
    read_base: int = 0,
    read_count: int = 10,
    period_s: float = 0.5,
    jitter_s: float = 0.1,
    write_prob: float = 0.1,
    stop_event: Optional[Event] = None,
) -> None:
    cfg = cfg or get_plc_config()
    run_task_loop(
        name="NORMAL",
        cfg=cfg,
        stop_event=stop_event,
        tick=_tick_normal_client,
        state=NormalClientState(read_base=read_base, read_count=read_count, write_prob=write_prob),
        timing=LoopTiming(period_s=period_s, jitter_s=jitter_s),
        connection_mode="persistent",
    )
