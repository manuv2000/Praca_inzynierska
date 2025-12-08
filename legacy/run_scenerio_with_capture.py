# injector/tools/run_scenario_with_capture.py

import argparse
import logging
import threading
import time
import uuid

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.traffic.hmi_master import run_hmi_loop
from injector.traffic.normal_client import run_normal_client
from injector.attacks.scan_readonly import run_scan_readonly  # za chwilę pokażę interfejs
from capture.core.capture_control import start_capture, stop_capture

log = logging.getLogger(__name__)

def run_baseline(stop_event: threading.Event) -> list[threading.Thread]:
    cfg = get_plc_config()
    threads: list[threading.Thread] = []

    t_hmi = threading.Thread(
        target=run_hmi_loop,
        name="HMI",
        kwargs={"cfg": cfg, "stop_event": stop_event},
        daemon=True,
    )
    t_norm = threading.Thread(
        target=run_normal_client,
        name="NORMAL",
        kwargs={"cfg": cfg, "stop_event": stop_event},
        daemon=True,
    )

    threads.extend([t_hmi, t_norm])
    for t in threads:
        t.start()
    return threads

def run_baseline_with_scan(stop_event: threading.Event) -> list[threading.Thread]:
    cfg = get_plc_config()
    threads = run_baseline(stop_event)

    t_scan = threading.Thread(
        target=run_scan_readonly,
        name="SCAN_RO",
        kwargs={
            "cfg": cfg,
            "start_addr": 0,
            "end_addr": 200,
            "block_size": 10,
            "delay_s": 0.01,
            "stop_event": stop_event,
        },
        daemon=True,
    )
    threads.append(t_scan)
    t_scan.start()
    return threads

def run_scan_only(stop_event: threading.Event) -> list[threading.Thread]:
    cfg = get_plc_config()
    threads: list[threading.Thread] = []
    t_scan = threading.Thread(
        target=run_scan_readonly,
        name="SCAN_RO",
        kwargs={
            "cfg": cfg,
            "start_addr": 0,
            "end_addr": 200,
            "block_size": 10,
            "delay_s": 0.01,
            "stop_event": stop_event,
        },
        daemon=True,
    )
    threads.append(t_scan)
    t_scan.start()
    return threads

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run PLC scenario with automatic capture."
    )
    parser.add_argument(
        "--scenario",
        choices=["baseline", "baseline_scan", "scan_only"],
        default="baseline",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=20.0,
        help="Czas trwania scenariusza w sekundach",
    )
    args = parser.parse_args()

    setup_logging("INFO")
    run_id = uuid.uuid4().hex[:8]
    log.info("=== Run %s, scenario=%s, duration=%.1fs ===",
             run_id, args.scenario, args.duration)

    # 1) start capture z etykietą
    pcap_label = f"{args.scenario}-{run_id}"
    pcap_path = start_capture(label=pcap_label)
    log.info("Capture started: %s", pcap_path)

    # 2) start scenariusza
    stop_event = threading.Event()

    if args.scenario == "baseline":
        threads = run_baseline(stop_event)
    elif args.scenario == "baseline_scan":
        threads = run_baseline_with_scan(stop_event)
    else:
        threads = run_scan_only(stop_event)

    # 3) czekamy z góry określony czas
    log.info("Scenario running... (Ctrl+C zatrzyma wcześniej)")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        log.info("Interrupted by user")

    # 4) zatrzymanie scenariusza
    log.info("Stopping scenario threads...")
    stop_event.set()
    for t in threads:
        t.join(timeout=2.0)

    # 5) zatrzymanie capture
    pid = stop_capture()
    log.info("Capture stopped (PID=%s). PCAP: %s", pid, pcap_path)
    log.info("=== Run %s finished ===", run_id)

if __name__ == "__main__":
    main()
