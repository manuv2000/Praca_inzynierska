# injector/runtime/task_runner.py

from __future__ import annotations
import logging
import random
import time
from dataclasses import dataclass
from threading import Event
from typing import Callable, Optional, Protocol, TypeVar, Generic, Any

from injector.core.config import PlcConfig, get_plc_config
from injector.core.modbus import modbus_client

log = logging.getLogger(__name__)

ServiceFn = Callable[..., None]

TState = TypeVar("TState")

class TickFn(Protocol, Generic[TState]):
    def __call__(self, *, client, cfg: PlcConfig, state: TState) -> None: ...

@dataclass(frozen=True)
class LoopTiming:
    period_s: float = 0.0
    jitter_s: float = 0.0
    qps: float = 0.0  # if >0, overrides period

    def next_sleep(self, elapsed_s: float) -> float:
        if self.qps and self.qps > 0:
            target = 1.0 / self.qps
        else:
            target = self.period_s + (random.uniform(-self.jitter_s, self.jitter_s) if self.jitter_s else 0.0)
            if target < 0.0:
                target = 0.0
        return max(0.0, target - elapsed_s)

def run_task_loop(
    *,
    name: str,
    tick: TickFn[TState],
    state: TState,
    cfg: Optional[PlcConfig] = None,
    stop_event: Optional[Event] = None,
    timing: LoopTiming = LoopTiming(period_s=0.5, jitter_s=0.0),
    connection_mode: str = "persistent",  # "persistent" | "per_tick"
) -> None:
    """
    Generic loop runner for traffic sources and attacks.
    Task supplies only 'tick' and optional state.
    """
    cfg = cfg or get_plc_config()
    stop_event = stop_event or Event()

    log.info("%s started (connection_mode=%s)", name, connection_mode)

    def should_stop() -> bool:
        return stop_event.is_set()

    if connection_mode not in ("persistent", "per_tick"):
        raise ValueError("connection_mode must be 'persistent' or 'per_tick'")

    try:
        if connection_mode == "persistent":
            with modbus_client(cfg) as client:
                while not should_stop():
                    t0 = time.perf_counter()
                    try:
                        tick(client=client, cfg=cfg, state=state)
                    except Exception as e:
                        log.warning("%s tick error: %r", name, e)

                    sleep_s = timing.next_sleep(time.perf_counter() - t0)
                    stop_event.wait(timeout=sleep_s)

        else:  # per_tick
            while not should_stop():
                t0 = time.perf_counter()
                try:
                    with modbus_client(cfg) as client:
                        tick(client=client, cfg=cfg, state=state)
                except Exception as e:
                    log.warning("%s tick error: %r", name, e)

                sleep_s = timing.next_sleep(time.perf_counter() - t0)
                stop_event.wait(timeout=sleep_s)

    finally:
        log.info("%s stopped", name)


def run_service_task(
    *,
    name: str,
    service: ServiceFn,
    cfg: Optional[PlcConfig] = None,
    stop_event: Optional[Event] = None,
    ready_event: Optional[Event] = None,
    ready_timeout_s: float = 2.0,
    **kwargs: Any,
) -> None:
    """
    Runner for long-running services (servers/proxies) that don't use modbus_client.
    service must accept: service(*, cfg, stop_event, ready_event=None, **kwargs)
    """
    cfg = cfg or get_plc_config()
    stop_event = stop_event or Event()

    log.info("%s service started", name)
    try:
        service(cfg=cfg, stop_event=stop_event, ready_event=ready_event, **kwargs)
    except Exception as e:
        log.exception("%s service crashed: %r", name, e)
        # ważne: nie blokuj scenariusza jeśli runner czeka na ready
        if ready_event is not None:
            ready_event.set()
    finally:
        log.info("%s service stopped", name)