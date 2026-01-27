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
import subprocess

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
def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]

def _manifests_dir() -> Path:
    d = _project_root() / "capture" / "pcap" / "manifests"
    d.mkdir(parents=True, exist_ok=True)
    return d

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

def _json_default(o):
    # minimalnie: dataclass / Path / set / bytes
    try:
        import dataclasses
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
    except Exception:
        pass

    if isinstance(o, Path):
        return str(o)
    if isinstance(o, set):
        return list(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", errors="replace")

    # fallback
    return str(o)

def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(data, indent=2, ensure_ascii=False, default=_json_default)

    tmp.write_text(payload, encoding="utf-8")

    if not tmp.exists():
        raise RuntimeError(f"Temp manifest not created: {tmp}")

    try:
        tmp.replace(path)
    except Exception:
        # fallback: zapis bez replace
        path.write_text(payload, encoding="utf-8")
        tmp.unlink(missing_ok=True)

    if not path.exists():
        raise RuntimeError(f"Manifest not created after replace(): {path}")

def _jsonable(obj: Any) -> Any:
    """Dataclass/Path -> dict/str; reszta -> safe fallback."""
    if obj is None:
        return None
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)

def cfg_to_dict(cfg) -> Dict[str, Any]:
    return _jsonable(cfg)

def _wait_file_stable(p: Path, timeout_s: float = 10.0, settle_checks: int = 3, sleep_s: float = 0.25) -> bool:
    deadline = time.monotonic() + float(timeout_s)
    last_size = None
    stable_hits = 0
    while time.monotonic() < deadline:
        if not p.exists():
            last_size = None
            stable_hits = 0
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

def _run_quick_modbus_export(
    *,
    pcap_main: Path,
    window_s: float,
    features_dir: Path,
) -> Tuple[bool, str]:
    """
    Odpala analysis/quick_modbus_stats.py tak jak Ty robisz ręcznie.
    Zwraca (ok, stdout+stderr).
    """
    features_dir.mkdir(parents=True, exist_ok=True)

    script = _project_root() / "analysis" / "quick_modbus_stats.py"
    if not script.exists():
        return False, f"quick_modbus_stats.py not found at {script}"

    cmd = [
        sys.executable,
        str(script),
        str(pcap_main),
        "--export-windows",
        str(features_dir),
        "--window-s",
        str(float(window_s)),
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return (proc.returncode == 0), out


def _expected_windows_paths(pcap_main: Path, features_dir: Path, window_s: float) -> Tuple[Path, Path]:
    # jeśli window_s = 5.0 -> "win5s"
    wtag = f"win{int(window_s)}s" if float(window_s).is_integer() else f"win{window_s:g}s"
    csv_path = features_dir / f"{pcap_main.stem}.{wtag}.csv"
    report_path = features_dir / f"{pcap_main.stem}.{wtag}.csv.report.json"
    return csv_path, report_path
def run_scenario(
    *,
    label: str,
    cfg,
    tasks: Iterable[TaskSpec],
    stop_event: Optional[threading.Event] = None,
    capture: bool = True,
    duration_s: Optional[float] = None,
    seed: Optional[int] = None,
    warmup_s: float = 0.0,
    cooldown_s: float = 0.0,
    scenario_id: Optional[str] = None,   # NEW
) -> None:

    if seed is not None:
        random.seed(int(seed))
        log.info("[MainThread] Random seed set to %s", seed)

    stop_event = stop_event or threading.Event()

    tasks = list(tasks)
    first = [t for t in tasks if t.start_first]
    rest = [t for t in tasks if not t.start_first]

    features_dir = _project_root() / "capture" / "pcap" / "features"
    window_s = 5.0

    threads: List[threading.Thread] = []

    capture_enabled = bool(capture and getattr(cfg, "capture", None) and cfg.capture.enabled)

    pcap_path: Optional[Path] = None
    manifest_path: Optional[Path] = None

    # --- RUN ID (stable dataset key) ---
    ts_run = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{ts_run}"
    if scenario_id:
        run_id += f"_{scenario_id}"
    if seed is not None:
        run_id += f"_seed{int(seed)}"

    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "scenario_id": scenario_id,
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
        "cfg": cfg_to_dict(cfg),
        "tasks": [t.to_manifest() for t in tasks],
        "capture": {
            "enabled": capture_enabled,
            "interface": getattr(getattr(cfg, "capture", None), "interface", None),
            "bpf": getattr(getattr(cfg, "capture", None), "bpf", None),
            "ring_size_mb": getattr(getattr(cfg, "capture", None), "ring_size_mb", None),
            "label_prefix": getattr(getattr(cfg, "capture", None), "label_prefix", None),
            "pcap_hint": None,
            "pcap_files": [],
            "pcap_main": None,
            "pcap_main_sha256": None,
        },
        "result": {
        "ok": None,
        "errors": [],
        "warnings": [],
        "capture_ok": None,
        "pcap_ok": None,
        "pcap_size_kb": None,
        "pcap_total_kb": None,
        "capture_pid": None,

        "features_ok": None,
        "features_window_s": None,
        "features_stdout_tail": None,
        "windows_csv": None,
        "windows_report": None,
        }

    }

    manifests_dir = _manifests_dir()
    manifest_path = manifests_dir / f"{run_id}.manifest.json"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    _write_json(manifest_path, manifest)
    log.info("[MainThread] Manifest saved (init): %s", manifest_path)
    log.info("[MainThread] manifests_dir=%s (cwd=%s)", manifests_dir, Path.cwd())

    if duration_s is None:
        log.info("[MainThread] Scenario label=%s started. Press Ctrl+C to stop.", label)
    else:
        log.info("[MainThread] Scenario label=%s started. Running for %.2fs.", label, float(duration_s))

    t_start_run = None

    try:
        for spec in first:
            threads.append(_make_thread(spec.name, spec.target, cfg=cfg, stop_event=stop_event, **spec.kwargs))

        for spec in first:
            if spec.ready_event is not None:
                ok = spec.ready_event.wait(timeout=spec.ready_timeout_s)
                if not ok:
                    log.warning("[MainThread] Task %s not ready within %.2fs", spec.name, spec.ready_timeout_s)

        for spec in rest:
            threads.append(_make_thread(spec.name, spec.target, cfg=cfg, stop_event=stop_event, **spec.kwargs))

        # warmup BEFORE capture
        if warmup_s and warmup_s > 0:
            log.info("[MainThread] Warmup %.2fs (capture not started yet)", float(warmup_s))
            time.sleep(float(warmup_s))

        # start capture AFTER warmup
        if capture_enabled:
            # label used for filenames: prefer run_id for uniqueness
            label_final = f"{cfg.capture.label_prefix}{run_id}" if cfg.capture.label_prefix else run_id

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
            manifest["capture"]["pcap_hint"] = str(pcap_path) if pcap_path else None
            _write_json(manifest_path, manifest)
            log.info("[MainThread] Capture started: %s", pcap_path)

        # duration timer starts here
        t_start_run = time.monotonic()

        # main loop
        while not stop_event.is_set():
            time.sleep(0.25)
            if duration_s is not None and t_start_run is not None:
                if (time.monotonic() - t_start_run) >= float(duration_s):
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

        features_ok = True
        windows_csv = None
        windows_report = None
        features_stdout_tail = None

        pcap_files: List[Path] = []
        pcap_main: Optional[Path] = None
        pcap_main_sha256: Optional[str] = None

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
                        pcap_total_kb = (sum(p.stat().st_size for p in pcap_files) / 1024.0) if pcap_files else pcap_size_kb
                        log.info("[MainThread] PCAP main stable: %s (%.1f KB)", pcap_main, pcap_size_kb)

                        try:
                            pcap_main_sha256 = _sha256_file(pcap_main)
                        except Exception as e:
                            log.warning("[MainThread] PCAP hash failed: %r", e)

            except Exception as e:
                pcap_ok = False
                log.exception("[MainThread] PCAP resolve/stability check failed: %r", e)
        if capture_enabled and pcap_main is not None and pcap_main.exists():
            try:
                ok, out = _run_quick_modbus_export(
                    pcap_main=pcap_main,
                    features_dir=features_dir,
                    window_s=window_s,
                )
                features_ok = bool(ok)
                features_stdout_tail = (out or "")[-2000:]  # debug tail

                csv_path, rep_path = _expected_windows_paths(pcap_main, features_dir, window_s)

                if csv_path.exists():
                    windows_csv = str(csv_path)
                else:
                    features_ok = False
                    manifest["result"].setdefault("warnings", []).append("windows_csv_missing")

                if rep_path.exists():
                    windows_report = str(rep_path)
                else:
                    features_ok = False
                    manifest["result"].setdefault("warnings", []).append("windows_report_missing")

            except Exception as e:
                features_ok = False
                manifest["result"].setdefault("warnings", []).append(f"features_export_failed:{type(e).__name__}")
                log.exception("[MainThread] Features export failed: %r", e)
        else:
            features_ok = (not capture_enabled)

        # minimal size check
        min_kb = 20.0
        if pcap_size_kb is None or pcap_size_kb < min_kb:
            pcap_ok = False
            manifest["result"].setdefault("warnings", []).append(f"pcap_main_too_small(<{min_kb}KB)")

        # finalize manifest (never crash)
        try:
            manifest["timestamp_end_epoch"] = time.time()

            manifest["result"]["capture_ok"] = bool(capture_ok)
            manifest["result"]["pcap_ok"] = bool(pcap_ok)
            manifest["result"]["pcap_size_kb"] = pcap_size_kb
            manifest["result"]["pcap_total_kb"] = float(pcap_total_kb) if pcap_total_kb is not None else None
            manifest["result"]["capture_pid"] = stopped_pid
            manifest["result"]["features_ok"] = bool(features_ok)
            manifest["result"]["features_window_s"] = float(window_s)
            manifest["result"]["features_stdout_tail"] = features_stdout_tail
            manifest["result"]["windows_csv"] = windows_csv
            manifest["result"]["windows_report"] = windows_report

            manifest["result"]["ok"] = bool(capture_ok and pcap_ok and features_ok)

            if capture_enabled:
                manifest["capture"]["capture_pid"] = stopped_pid
                manifest["capture"]["pcap_files"] = [str(p) for p in pcap_files]
                manifest["capture"]["pcap_main"] = str(pcap_main) if pcap_main else None
                manifest["capture"]["pcap_main_sha256"] = pcap_main_sha256

            _write_json(manifest_path, manifest)
            log.info("[MainThread] Manifest saved (final): %s", manifest_path)

        except Exception as e:
            log.exception("[MainThread] Manifest write failed: %r", e)



