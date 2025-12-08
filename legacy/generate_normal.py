from injector.core.logging_setup import setup
from legacy.modbus_util import modbus_client
import time, random, logging

log = logging.getLogger("plc.normal")

def within(v, lo, hi): return lo <= v <= hi

def run(plc_host, plc_port, unit_id,
        read_period_ms=100, read_addr=0, read_count=8,
        write_prob=0.03, write_addr=2, write_range=(0,100),
        policy=(0,100), dry_run=False):
    """policy is allowed range for writes; if outside -> log warn and skip."""
    setup("INFO")
    period = read_period_ms/1000.0
    with modbus_client(plc_host, plc_port) as c:
        log.info("Normal generator started")
        while True:
            c.read_hr(read_addr, count=read_count, unit=unit_id)

            if random.random() < write_prob:
                value = random.randint(*write_range)
                if not within(value, *policy):
                    log.warning(f"value {value} violates policy {policy}, skipping write")
                elif not dry_run:
                    c.write_hr(write_addr, value, unit=unit_id)
                    # verify via HR1 mirror:
                    rb = c.read_hr(1, count=1, unit=unit_id).registers[0]
                    if rb != value:
                        log.error(f"write-readback mismatch: wrote {value}, got {rb}")
                    else:
                        log.info(f"write OK -> HR2={value}, HR1={rb}")
                else:
                    log.info(f"[dry-run] would write {value} to HR2")

            time.sleep(period)
