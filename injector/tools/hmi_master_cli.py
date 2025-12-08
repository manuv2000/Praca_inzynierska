# injector/tools/hmi_master_cli.py

import logging

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.traffic.hmi_master import run_hmi_loop

log = logging.getLogger(__name__)

def main() -> None:
    setup_logging("INFO")
    cfg = get_plc_config()
    log.info("Starting standalone HMI master against %s:%s (unit %s)",
             cfg.host, cfg.port, cfg.unit_id)

    run_hmi_loop(
        cfg=cfg,
        base_address=0,
        count=10,
        period_s=0.2,
        jitter_s=0.05,
    )

if __name__ == "__main__":
    main()
