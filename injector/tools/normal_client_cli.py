# injector/tools/normal_client_cli.py

import logging

from injector.core.logging_setup import setup_logging
from injector.core.config import get_plc_config
from injector.traffic.normal_client import run_normal_client

log = logging.getLogger(__name__)

def main() -> None:
    setup_logging("INFO")
    cfg = get_plc_config()
    log.info("Starting standalone normal client against %s:%s (unit %s)",
             cfg.host, cfg.port, cfg.unit_id)

    run_normal_client(
        cfg=cfg,
        read_base=0,
        read_count=10,
        period_s=0.5,
        jitter_s=0.1,
        write_prob=0.1,
    )

if __name__ == "__main__":
    main()
