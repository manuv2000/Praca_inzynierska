# injector/app/runner.py

import hashlib
import json
import logging
import threading
import time
import random
from dataclasses import dataclass
from dataclasses import asdict, is_dataclass
from typing import Callable, Iterable, Optional, Dict, Any, List, Tuple
from pathlib import Path
import platform
import sys

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

    def to_manifest(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "start_first": self.start_first,
            "kwargs": self.kwargs,
        }


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

def _json_safe(obj):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(x) for x in obj]
    return obj

def _json_default(o):
    if is_dataclass(o):
        return asdict(o)
    if isinstance(o, Path):
        return str(o)
    return str(o)  # fallback (bezpiecznie do manifestu)

def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    tmp.replace(path)
def _wait_file_stable(
    p: Path,
    timeout_s: float = 10.0,
    settle_checks: int = 3,
    sleep_s: float = 0.25,
) -> bool:
    """
    Czeka aż plik przestanie rosnąć (size się ustabilizuje).
    Zwraca True jeśli stabilny i istnieje.
    """
    deadline = time.monotonic() + float(timeout_s)
    last_size: Optional[int] = None
    stable_hits = 0

    while time.monotonic() < deadline:
        if not p.exists():
            stable_hits = 0
            last_size = None
            time.sleep(float(sleep_s))
            continue

        try:
            size = p.stat().st_size
        except Exception:
            time.sleep(float(sleep_s))
            continue

        if last_size is not None and size == last_size:
            stable_hits += 1
        else:
            stable_hits = 0

        last_size = size

        if stable_hits >= max(1, int(settle_checks)):
            return True

        time.sleep(float(sleep_s))

    return p.exists()
def _resolve_capture_files(pcap_path_hint: Path) -> Tuple[List[Path], Optional[Path]]:
    """
    Jeśli dumpcap robi wiele plików (np. ..._00002_...), to pcap_path_hint bywa tylko prefiksem.
    Zwraca listę plików + plik główny (największy).
    """
    if pcap_path_hint is None:
        return [], None

    d = pcap_path_hint.parent
    stem = pcap_path_hint.stem  # bez .pcapng/.pcap

    cand = []
    cand += list(d.glob(stem + "*.pcapng"))
    cand += list(d.glob(stem + "*.pcap"))

    # jeśli hint istnieje jako plik – też uwzględnij
    if pcap_path_hint.exists():
        cand.append(pcap_path_hint)

    uniq: List[Path] = []
    seen = set()
    for p in cand:
        if p in seen:
            continue
        seen.add(p)
        if p.exists():
            uniq.append(p)

    if not uniq:
        return [], None

    main = max(uniq, key=lambda p: p.stat().st_size)
    return sorted(uniq, key=lambda p: p.stat().st_mtime), main

def wait_for_pcap(path: Path, timeout_s: float = 5.0) -> bool:
    import time
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(0.2)
    return False

def _sha256_file(p: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def run_scenario(
    *,
    label: str,
    cfg,
    tasks: Iterable[TaskSpec],
    stop_event: Optional[threading.Event] = None,
    capture: bool = True,
    duration_s: Optional[float] = None,  # NEW
    seed: Optional[int] = None,
    warmup_s: float = 0.0,     # NEW
    cooldown_s: float = 0.0,   # NEW
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

    tasks = list(tasks)
    first = [t for t in tasks if t.start_first]
    rest = [t for t in tasks if not t.start_first]

    threads: List[threading.Thread] = []
    t_start = time.monotonic()

    capture_enabled = bool(capture and getattr(cfg, "capture", None) and cfg.capture.enabled)

    pcap_path: Optional[Path] = None
    manifest_path: Optional[Path] = None

    manifest: Dict[str, Any] = {
        "label": label,
        "seed": seed,
        "duration_s": duration_s,
        "warmup_s": warmup_s,
        "cooldown_s": cooldown_s,
        "timestamp_start_epoch": time.time(),
        "platform": {
            "python": sys.version,
            "os": platform.platform(),
        },
        "cfg": {
            # cfg jest dataclass -> najprościej zrobić __dict__ jeśli to płaski dataclass,
            # u Ciebie jest zagnieżdżony (plc/proxy/capture), więc bierzemy "as-is" przez vars()
            # (jeśli coś nie jest serializowalne, później to poprawimy)
            **vars(cfg)
        },
        "tasks": [t.to_manifest() for t in tasks],
        "capture": {
            "enabled": capture_enabled,
            "interface": getattr(getattr(cfg, "capture", None), "interface", None),
            "bpf": getattr(getattr(cfg, "capture", None), "bpf", None),
            "ring_size_mb": getattr(getattr(cfg, "capture", None), "ring_size_mb", None),
            "label_prefix": getattr(getattr(cfg, "capture", None), "label_prefix", None),
        },
        "result": {
            "ok": None,
            "errors": [],
            "warnings": [],
        }
    }

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
        if warmup_s and warmup_s > 0:
            log.info("[MainThread] Warmup %.2fs (capture not started yet)", warmup_s)
            time.sleep(float(warmup_s))

            # 5) Start capture AFTER warmup
        if capture_enabled:
            label_final = f"{cfg.capture.label_prefix}{label}" if cfg.capture.label_prefix else label

            # Twoje start_capture miało różne wywołania w historii (label-only vs. extended).
            # Robimy kompatybilne wywołanie: najpierw extended, fallback na label-only.
            try:
                p = start_capture(
                    interface=cfg.capture.interface,
                    bpf=cfg.capture.bpf,
                    ring_size_mb=cfg.capture.ring_size_mb,
                    label=label_final,
                )
            except TypeError:
                p = start_capture(label=label_final)

            pcap_path = Path(p) if p else None
            if pcap_path is not None:
                manifest["capture"]["pcap_path"] = str(pcap_path)
                manifest_path = pcap_path.with_suffix(pcap_path.suffix + ".manifest.json")
                _write_json(manifest_path, manifest)
                log.info("[MainThread] Capture started: %s", pcap_path)
                log.info("[MainThread] Manifest saved: %s", manifest_path)

            # 6) Main loop: Ctrl+C or duration expiry
        while not stop_event.is_set():
            time.sleep(0.25)
            if duration_s is not None and (time.monotonic() - t_start) >= float(duration_s):
                log.info("[MainThread] Duration elapsed (%.2fs). Stopping scenario...", float(duration_s))
                stop_event.set()

    except KeyboardInterrupt:
        log.info("[MainThread] Ctrl+C received. Stopping scenario...")
        stop_event.set()




    finally:

        # always init locals (avoid UnboundLocalError)

        capture_ok = True

        pcap_ok = True

        pcap_size_kb = None

        pcap_total_kb = 0.0

        stopped_pid = None

        pcap_files = []

        pcap_main = None

        pcap_main_sha256 = None

        stop_event.set()

        for t in threads:

            try:

                t.join(timeout=2.0)

            except Exception:

                pass

        # cooldown while capture still running

        if capture_enabled and cooldown_s and cooldown_s > 0:
            log.info("[MainThread] Cooldown %.2fs (capture still running)", float(cooldown_s))

            time.sleep(float(cooldown_s))

        # stop capture

        if capture_enabled:

            try:

                stopped_pid = stop_capture()

                log.info("[MainThread] Scenario finished. Capture PID stopped: %s", stopped_pid)

            except Exception as e:

                capture_ok = False

                log.exception("[MainThread] stop_capture failed: %r", e)

        # resolve capture files + wait stable + sizes

        if capture_enabled and pcap_path is not None:

            try:

                pcap_files, pcap_main = _resolve_capture_files(Path(pcap_path))

                if pcap_main is None:

                    pcap_ok = False

                    log.warning("[MainThread] No PCAP files resolved for hint: %s", pcap_path)

                else:

                    ok = _wait_file_stable(pcap_main, timeout_s=10.0, settle_checks=3, sleep_s=0.25)

                    if not ok or not pcap_main.exists():

                        pcap_ok = False

                        log.warning("[MainThread] PCAP main not stable or missing: %s", pcap_main)

                    else:

                        pcap_size_kb = pcap_main.stat().st_size / 1024.0

                        pcap_total_kb = sum(
                            p.stat().st_size for p in pcap_files) / 1024.0 if pcap_files else pcap_size_kb

                        log.info("[MainThread] PCAP main stable: %s (%.1f KB)", pcap_main, pcap_size_kb)

                        # optional hash (polecam dopiero gdy pipeline działa, bo kosztuje I/O)

                        try:

                            pcap_main_sha256 = _sha256_file(pcap_main)

                        except Exception as e:

                            log.warning("[MainThread] PCAP hash failed: %r", e)


            except Exception as e:

                pcap_ok = False

                log.exception("[MainThread] PCAP resolve/stability check failed: %r", e)

        min_kb = 20.0

        if pcap_size_kb is None or pcap_size_kb < min_kb:
            pcap_ok = False
            manifest["result"].setdefault("warnings", []).append(f"pcap_main_too_small(<{min_kb}KB)")
        # finalize manifest (never crash)

        if manifest_path is not None:

            try:

                manifest["timestamp_end_epoch"] = time.time()

                manifest.setdefault("result", {})

                manifest.setdefault("capture", {})

                # capture section enrich

                if capture_enabled:
                    manifest["capture"]["capture_pid"] = stopped_pid

                    manifest["capture"]["pcap_files"] = [str(p) for p in pcap_files]

                    manifest["capture"]["pcap_main"] = str(pcap_main) if pcap_main else None

                    manifest["capture"]["pcap_main_sha256"] = pcap_main_sha256

                # result flags

                manifest["result"]["capture_ok"] = bool(capture_ok)

                manifest["result"]["pcap_ok"] = bool(pcap_ok)

                manifest["result"]["pcap_size_kb"] = pcap_size_kb

                manifest["result"]["pcap_total_kb"] = float(pcap_total_kb) if pcap_total_kb is not None else None

                manifest["result"]["capture_pid"] = stopped_pid

                # final ok

                manifest["result"]["ok"] = bool(capture_ok and pcap_ok)

                _write_json(manifest_path, manifest)  # JSON-safe via default=_json_default OR dict already safe

            except Exception as e:

                log.exception("[MainThread] Manifest write failed: %r", e)



