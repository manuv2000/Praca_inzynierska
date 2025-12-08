# injector/tools/attacks_menu.py

import logging
import threading
import time

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.traffic.hmi_master import run_hmi_loop
from injector.traffic.normal_client import run_normal_client
from injector.attacks.scan_readonly import run_scan_readonly
from injector.attacks.write_injection import run_write_injection
from injector.attacks.spoofing import run_spoofing


from capture.core.capture_control import start_capture, stop_capture

log = logging.getLogger(__name__)


def _make_thread(name: str, target, *, cfg, stop_event, **kwargs) -> threading.Thread:
    """
    Pomocnicza funkcja do uruchamiania wątków:
    - target zawsze dostaje cfg oraz stop_event jako keywordy
    - dodatkowe parametry (np. start_addr, target_register) jako kwargs
    """
    t = threading.Thread(
        name=name,
        target=target,
        kwargs={"cfg": cfg, "stop_event": stop_event, **kwargs},
        daemon=True,
    )
    t.start()
    return t


def _main_loop_with_threads(*threads, stop_event: threading.Event, label: str) -> None:
    """
    Wspólny szkielet:
    - start_capture
    - program czeka aż Ctrl+C
    - stop_event.set()
    - join wątków
    - stop_capture
    """
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
        "SCAN_RO",
        run_scan_readonly,
        cfg=cfg,
        stop_event=stop_event,
        start_addr=0,
        end_addr=200,
        block_size=10,
        delay_s=0.01,
    )

    log.info("[MainThread] Running BASELINE + READ-ONLY SCAN")
    _main_loop_with_threads(
        hmi_t,
        normal_t,
        scan_t,
        stop_event=stop_event,
        label="baseline_ro_scan",
    )


def run_readonly_scan_only() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()

    scan_t = _make_thread(
        "SCAN_RO",
        run_scan_readonly,
        cfg=cfg,
        stop_event=stop_event,
        start_addr=0,
        end_addr=200,
        block_size=10,
        delay_s=0.01,
    )

    log.info("[MainThread] Running READ-ONLY SCAN ONLY")
    _main_loop_with_threads(scan_t, stop_event=stop_event, label="ro_scan_only")


def _make_thread(name: str, target, cfg, stop_event, **kwargs):
    t = threading.Thread(
        name=name,
        target=target,
        kwargs={"cfg": cfg, "stop_event": stop_event, **kwargs},
        daemon=True,
    )
    t.start()
    return t


def run_baseline_plus_write_injection() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()

    hmi_t = _make_thread("HMI", run_hmi_loop, cfg, stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg, stop_event)
    write_t = _make_thread(
        "WRITE_INJ",
        run_write_injection,
        cfg,
        stop_event,
        target_register=2,
        qps=10.0,   # np. 10 zapisów/sek
    )

    log.info("[MainThread] Running BASELINE + WRITE INJECTION")

    pcap_path = start_capture(label="baseline_write_inj")
    log.info("[MainThread] Capture started: %s", pcap_path)

    try:
        log.info("[MainThread] Press Ctrl+C to stop scenario")
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("[MainThread] Stopping all threads...")
        stop_event.set()
        write_t.join(timeout=2.0)
        hmi_t.join(timeout=2.0)
        normal_t.join(timeout=2.0)
    finally:
        pid = stop_capture()
        log.info("[MainThread] Scenario finished. Capture PID stopped: %s", pid)


def run_write_injection_only() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()

    write_t = _make_thread(
        "WRITE_INJ",
        run_write_injection,
        cfg=cfg,
        stop_event=stop_event,
        target_register=2,
        qps=5.0,
    )

    log.info("[MainThread] Running WRITE INJECTION ONLY")
    _main_loop_with_threads(write_t, stop_event=stop_event, label="write_inj_only")

def run_baseline_plus_spoofing() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()

    hmi_t = _make_thread("HMI", run_hmi_loop, cfg=cfg, stop_event=stop_event)
    normal_t = _make_thread("NORMAL", run_normal_client, cfg=cfg, stop_event=stop_event)
    spoof_t = _make_thread(
        "SPOOF",
        run_spoofing,
        cfg=cfg,
        stop_event=stop_event,
        target_registers=list(range(10, 20)),  # np. HR10..HR19
        qps=20.0,
        min_value=0,
        max_value=1000,
    )

    log.info("[MainThread] Running BASELINE + SPOOFING")
    pcap_path = start_capture(label="baseline_spoofing")
    log.info("[MainThread] Capture started: %s", pcap_path)

    try:
        log.info("[MainThread] Press Ctrl+C to stop scenario")
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("[MainThread] Stopping all threads...")
        stop_event.set()
        spoof_t.join(timeout=2.0)
        hmi_t.join(timeout=2.0)
        normal_t.join(timeout=2.0)
    finally:
        pid = stop_capture()
        log.info("[MainThread] Scenario finished. Capture PID stopped: %s", pid)

def run_spoofing_only() -> None:
    cfg = get_plc_config()
    stop_event = threading.Event()

    spoof_t = _make_thread(
        "SPOOF",
        run_spoofing,
        cfg=cfg,
        stop_event=stop_event,
        target_registers=list(range(10, 20)),
        qps=20.0,
        min_value=0,
        max_value=1000,
    )

    log.info("[MainThread] Running SPOOFING ONLY")
    pcap_path = start_capture(label="spoofing_only")
    log.info("[MainThread] Capture started: %s", pcap_path)

    try:
        log.info("[MainThread] Press Ctrl+C to stop scenario")
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("[MainThread] Stopping spoofing thread...")
        stop_event.set()
        spoof_t.join(timeout=2.0)
    finally:
        pid = stop_capture()
        log.info("[MainThread] Scenario finished. Capture PID stopped: %s", pid)


def main() -> None:
    setup_logging("INFO")

    print("=== PLC Security Simulation ===")
    print("1) Baseline only (HMI + normal_client)")
    print("2) Baseline + READ-ONLY scan")
    print("3) READ-ONLY scan only")
    print("4) Baseline + WRITE injection")
    print("5) WRITE injection only")
    print("6) Baseline + SPOOFING")
    print("7) SPOOFING only")
    choice = input("Choose option [1/2/3/4/5/6/7]: ").strip()

    if choice == "1":
        run_baseline_only()
    elif choice == "2":
        run_baseline_plus_readonly_scan()
    elif choice == "3":
        run_readonly_scan_only()
    elif choice == "4":
        run_baseline_plus_write_injection()
    elif choice == "5":
        run_write_injection_only()
    elif choice == "6":
        run_baseline_plus_spoofing()
    elif choice == "7":
        run_spoofing_only()
    else:
        print("Invalid choice")



if __name__ == "__main__":
    main()
