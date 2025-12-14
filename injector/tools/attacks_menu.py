# injector/tools/attacks_menu.py

import logging
import threading
import time
from dataclasses import replace

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.traffic.hmi_master import run_hmi_loop
from injector.traffic.normal_client import run_normal_client
from injector.attacks.scan_readonly import run_scan_readonly
from injector.attacks.write_injection import run_write_injection
from injector.attacks.mass_overwrite import run_spoofing  # (u Ciebie: mass_overwrite)
from injector.attacks.modbus_proxy_spoof import run_modbus_proxy

from capture.core.capture_control import start_capture, stop_capture

log = logging.getLogger(__name__)


def _make_thread(name: str, target, *, cfg, stop_event, **kwargs) -> threading.Thread:
    t = threading.Thread(
        name=name,
        target=target,
        kwargs={"cfg": cfg, "stop_event": stop_event, **kwargs},
        daemon=True,
    )
    t.start()
    return t


def _main_loop_with_threads(*threads: threading.Thread, stop_event: threading.Event, label: str) -> None:
    pcap_path = start_capture(label=label)
    log.info("[MainThread] Capture started: %s", pcap_path)
    log.info("[MainThread] Press Ctrl+C to stop scenario")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("[MainThread] Stopping all threads...")
        stop_event.set()
        for t in threads:
            t.join(timeout=2.0)
    finally:
        pid = stop_capture()
        log.info("[MainThread] Scenario finished. Capture PID stopped: %s", pid)


def run_baseline_only() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()
    hmi_t = _make_thread("HMI", run_hmi_loop, cfg=cfg, stop_event=stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg=cfg, stop_event=stop_event)
    log.info("[MainThread] Running BASELINE: HMI + normal_client")
    _main_loop_with_threads(hmi_t, normal_t, stop_event=stop_event, label="baseline")


def run_baseline_plus_readonly_scan() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()
    hmi_t = _make_thread("HMI", run_hmi_loop, cfg=cfg, stop_event=stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg=cfg, stop_event=stop_event)
    scan_t = _make_thread(
        "SCAN_RO", run_scan_readonly, cfg=cfg, stop_event=stop_event,
        start_addr=0, end_addr=200, block_size=10, delay_s=0.01,
    )
    log.info("[MainThread] Running BASELINE + READ-ONLY SCAN")
    _main_loop_with_threads(hmi_t, normal_t, scan_t, stop_event=stop_event, label="baseline_ro_scan")


def run_baseline_plus_write_injection() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()
    hmi_t = _make_thread("HMI", run_hmi_loop, cfg=cfg, stop_event=stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg=cfg, stop_event=stop_event)
    write_t = _make_thread(
        "WRITE_INJ", run_write_injection, cfg=cfg, stop_event=stop_event,
        target_register=2, qps=10.0,
    )
    log.info("[MainThread] Running BASELINE + WRITE INJECTION")
    _main_loop_with_threads(hmi_t, normal_t, write_t, stop_event=stop_event, label="baseline_write_inj")


def run_mass_overwrite_only() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()
    t = _make_thread(
        "MASS_OVERWRITE", run_spoofing,
        cfg=cfg, stop_event=stop_event,
        target_registers=list(range(10, 20)),
        qps=20.0, min_value=0, max_value=1000,
    )
    log.info("[MainThread] Running MASS_OVERWRITE ONLY")
    _main_loop_with_threads(t, stop_event=stop_event, label="mass_overwrite_only")


def run_baseline_plus_proxy_spoofing() -> None:
    cfg_real = get_plc_config()
    stop_event = threading.Event()
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

    # klienci łączą się już do proxy
    cfg_proxy = replace(cfg_real, proxy_enabled=True)

    hmi_t = _make_thread("HMI", run_hmi_loop, cfg=cfg_proxy, stop_event=stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg=cfg_proxy, stop_event=stop_event)

    log.info("[MainThread] Running BASELINE + PROXY SPOOFING")
    _main_loop_with_threads(hmi_t, normal_t, proxy_t, stop_event=stop_event, label="baseline_proxy_spoof")


def main() -> None:
    setup_logging("INFO")

    print("=== PLC Security Simulation ===")
    print("1) Baseline only (HMI + normal_client)")
    print("2) Baseline + READ-ONLY scan")
    print("3) Baseline + WRITE injection")
    print("4) MASS_OVERWRITE only")
    print("5) Baseline + PROXY spoofing")

    choice = input("Choose option [1/2/3/4/5]: ").strip()

    if choice == "1":
        run_baseline_only()
    elif choice == "2":
        run_baseline_plus_readonly_scan()
    elif choice == "3":
        run_baseline_plus_write_injection()
    elif choice == "4":
        run_mass_overwrite_only()
    elif choice == "5":
        run_baseline_plus_proxy_spoofing()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
