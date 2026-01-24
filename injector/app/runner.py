# injector/app/runner.py

import logging
import threading
import time
import random
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Dict, Any, List

from capture.core.capture_control import start_capture, stop_capture

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaskSpec:
    """
    Target must accept signature: target(*, cfg, stop_event, **kwargs)
    """
    name: str
    target: Callable[..., None]
    kwargs: Dict[str, Any]
    start_first: bool = False
    ready_event: Optional[threading.Event] = None
    ready_timeout_s: float = 2.0


def _make_thread(
    name: str,
    target: Callable[..., None],
    *,
    cfg,
    stop_event: threading.Event,
    **kwargs,
) -> threading.Thread:
    t = threading.Thread(
        name=name,
        target=target,
        kwargs={"cfg": cfg, "stop_event": stop_event, **kwargs},
        daemon=True,
    )
    t.start()
    return t


def run_scenario(
    *,
    label: str,
    cfg,
    tasks: Iterable[TaskSpec],
    stop_event: Optional[threading.Event] = None,
    capture: bool = True,
    duration_s: Optional[float] = None,  # NEW
    seed: Optional[int] = None
) -> None:

    if seed is not None:
        random.seed(int(seed))
        log.info("[MainThread] Random seed set to %s", seed)
    """
    Owns lifecycle:
    - start capture
    - start start_first tasks + wait for ready
    - start remaining tasks
    - run until Ctrl+C OR duration_s elapsed
    - stop tasks and join
    - stop capture
    """
    stop_event = stop_event or threading.Event()

    pcap_path = None

    capture_enabled = capture and getattr(cfg, "capture", None) and cfg.capture.enabled

    if capture_enabled:
        label_final = f"{cfg.capture.label_prefix}{label}" if cfg.capture.label_prefix else label
        pcap_path = start_capture(
            interface=cfg.capture.interface,
            bpf=cfg.capture.bpf,
            ring_size_mb=cfg.capture.ring_size_mb,
            label=label_final,
        )
        log.info("[MainThread] Capture started: %s", pcap_path)

    tasks = list(tasks)
    first = [t for t in tasks if t.start_first]
    rest = [t for t in tasks if not t.start_first]

    threads: List[threading.Thread] = []
    t_start = time.monotonic()

    if duration_s is None:
        log.info("[MainThread] Scenario label=%s started. Press Ctrl+C to stop.", label)
    else:
        log.info("[MainThread] Scenario label=%s started. Running for %.2fs.", label, duration_s)

    try:
        # start_first tasks (e.g., proxy)
        for spec in first:
            threads.append(_make_thread(spec.name, spec.target, cfg=cfg, stop_event=stop_event, **spec.kwargs))

        # readiness gates
        for spec in first:
            if spec.ready_event is not None:
                ok = spec.ready_event.wait(timeout=spec.ready_timeout_s)
                if not ok:
                    log.warning("[MainThread] Task %s not ready within %.2fs", spec.name, spec.ready_timeout_s)

        # start remaining tasks
        for spec in rest:
            threads.append(_make_thread(spec.name, spec.target, cfg=cfg, stop_event=stop_event, **spec.kwargs))

        # main loop: Ctrl+C or duration expiry
        while not stop_event.is_set():
            time.sleep(0.25)
            if duration_s is not None and (time.monotonic() - t_start) >= duration_s:
                log.info("[MainThread] Duration elapsed (%.2fs). Stopping scenario...", duration_s)
                stop_event.set()

    except KeyboardInterrupt:
        log.info("[MainThread] Ctrl+C received. Stopping scenario...")
        stop_event.set()

    finally:
        # join threads
        for t in threads:
            t.join(timeout=2.0)

        if capture_enabled:
            pid = stop_capture()
            log.info("[MainThread] Scenario finished. Capture PID stopped: %s", pid)

        else:
            log.info("[MainThread] Scenario finished (capture disabled).")
