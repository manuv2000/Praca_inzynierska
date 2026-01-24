import threading
from typing import Sequence

from injector.core.config import PlcConfig
from injector.runtime.modbus_writes import run_parallel_fc16_overwrite


def run_mass_overwrite_fc16(
    *,
    cfg: PlcConfig,
    stop_event: threading.Event,
    target_registers: Sequence[int],
    chunk_size: int = 10,
    workers: int = 3,
    qps_per_worker: float = 5.0,
    min_value: int = 0,
    max_value: int = 1000,
) -> None:
    run_parallel_fc16_overwrite(
        cfg=cfg,
        stop_event=stop_event,
        target_registers=target_registers,
        chunk_size=chunk_size,
        workers=workers,
        qps_per_worker=qps_per_worker,
        min_value=min_value,
        max_value=max_value,
    )
