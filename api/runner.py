import time
import threading
from dataclasses import replace
from typing import Optional, List, Dict, Any

from injector.core.config import get_plc_config
from injector.traffic.hmi_master import run_hmi_loop
from injector.traffic.normal_client import run_normal_client
from injector.attacks.scan_readonly import run_scan_readonly
from injector.attacks.write_injection import run_write_injection
from injector.attacks.mass_overwrite import run_spoofing
from injector.attacks.modbus_proxy_spoof import run_modbus_proxy

from capture.core.capture_control import start_capture, stop_capture


def _make_thread(name: str, target, *, cfg, stop_event: threading.Event, **kwargs) -> threading.Thread:
    t = threading.Thread(
        name=name,
        target=target,
        kwargs={"cfg": cfg, "stop_event": stop_event, **kwargs},
        daemon=True,
    )
    t.start()
    return t


class ScenarioRunner:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event: Optional[threading.Event] = None
        self._threads: List[threading.Thread] = []
        self._scenario: Optional[str] = None
        self._started_at: Optional[float] = None
        self._pcap_path: Optional[str] = None
        self._capture_pid: Optional[int] = None
        self._details: Dict[str, Any] = {}

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._stop_event is not None and not self._stop_event.is_set(),
                "scenario": self._scenario,
                "started_at_epoch": self._started_at,
                "pcap_path": self._pcap_path,
                "capture_pid": self._capture_pid,
                "details": dict(self._details),
            }

    def start(self, name: str) -> Dict[str, Any]:
        with self._lock:
            if self._stop_event is not None and not self._stop_event.is_set():
                raise RuntimeError("Scenario already running. Stop it first.")

            cfg_real = get_plc_config()
            stop_event = threading.Event()
            threads: List[threading.Thread] = []
            details: Dict[str, Any] = {}

            # START CAPTURE (label = name)
            pcap_path = start_capture(label=name)
            details["capture_label"] = name

            # scenariusze
            if name == "baseline":
                threads.append(_make_thread("HMI", run_hmi_loop, cfg=cfg_real, stop_event=stop_event))
                threads.append(_make_thread("NORMAL", run_normal_client, cfg=cfg_real, stop_event=stop_event))

            elif name == "baseline_ro_scan":
                threads.append(_make_thread("HMI", run_hmi_loop, cfg=cfg_real, stop_event=stop_event))
                threads.append(_make_thread("NORMAL", run_normal_client, cfg=cfg_real, stop_event=stop_event))
                threads.append(_make_thread(
                    "SCAN_RO", run_scan_readonly,
                    cfg=cfg_real, stop_event=stop_event,
                    start_addr=0, end_addr=200, block_size=10, delay_s=0.01
                ))

            elif name == "baseline_write_inj":
                threads.append(_make_thread("HMI", run_hmi_loop, cfg=cfg_real, stop_event=stop_event))
                threads.append(_make_thread("NORMAL", run_normal_client, cfg=cfg_real, stop_event=stop_event))
                threads.append(_make_thread(
                    "WRITE_INJ", run_write_injection,
                    cfg=cfg_real, stop_event=stop_event,
                    target_register=2, qps=10.0
                ))

            elif name == "mass_overwrite_only":
                threads.append(_make_thread(
                    "MASS_OVERWRITE", run_spoofing,
                    cfg=cfg_real, stop_event=stop_event,
                    target_registers=list(range(10, 20)), qps=20.0, min_value=0, max_value=1000
                ))

            elif name == "baseline_proxy_spoof":
                proxy_ready = threading.Event()
                proxy_t = threading.Thread(
                    name="PROXY",
                    target=run_modbus_proxy,
                    kwargs={
                        "cfg": cfg_real,
                        "stop_event": stop_event,
                        "listen_host": cfg_real.proxy_host,
                        "listen_port": cfg_real.proxy_port,
                        "ready_event": proxy_ready,
                    },
                    daemon=True,
                )
                proxy_t.start()
                proxy_ready.wait(timeout=2.0)

                cfg_proxy = replace(cfg_real, proxy_enabled=True)
                threads.append(proxy_t)
                threads.append(_make_thread("HMI", run_hmi_loop, cfg=cfg_proxy, stop_event=stop_event))
                threads.append(_make_thread("NORMAL", run_normal_client, cfg=cfg_proxy, stop_event=stop_event))
                details["proxy"] = {"host": cfg_real.proxy_host, "port": cfg_real.proxy_port}

            else:
                # jeśli nie znamy scenariusza -> stop capture i błąd
                stop_capture()
                raise ValueError(f"Unknown scenario name: {name}")

            self._stop_event = stop_event
            self._threads = threads
            self._scenario = name
            self._started_at = time.time()
            self._pcap_path = str(pcap_path)
            self._capture_pid = None  # ustawimy przy stop, bo capture_control zwraca PID przy stop_capture()
            self._details = details

            return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self._stop_event is None or self._stop_event.is_set():
                return self.status()

            self._stop_event.set()
            for t in self._threads:
                t.join(timeout=2.0)

            pid = stop_capture()
            self._capture_pid = pid

            # zostawiamy scenario/pcap_path dla historii, ale running będzie false
            return self.status()
