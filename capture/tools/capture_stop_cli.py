# capture/tools/capture_stop_cli.py

import logging

from injector.core.logging_setup import setup_logging
from capture.core.capture_control import stop_capture

log = logging.getLogger(__name__)

def main() -> None:
    setup_logging("INFO")
    pid = stop_capture()
    if pid is None:
        log.warning("No running capture found (no PID file)")
    else:
        log.info("Stopped capture process PID=%s", pid)

if __name__ == "__main__":
    main()
