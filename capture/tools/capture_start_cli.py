# capture/tools/capture_start_cli.py

import logging

from injector.core.logging_setup import setup_logging
from capture.core.capture_control import start_capture, DEFAULT_INTERFACE, BPF_FILTER

log = logging.getLogger(__name__)

def main() -> None:
    setup_logging("INFO")
    log.info("Starting capture on interface '%s' with filter '%s'", DEFAULT_INTERFACE, BPF_FILTER)
    pcap_path = start_capture()
    log.info("Capture started, writing to %s", pcap_path)

if __name__ == "__main__":
    main()
