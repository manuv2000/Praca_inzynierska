import time, logging
from contextlib import contextmanager
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

log = logging.getLogger("plc.injector")

@contextmanager
def modbus_client(host: str, port: int, timeout=1.5, retries=3):
    c = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not c.connect():
        raise RuntimeError(f"Cannot connect to {host}:{port}")
    try:
        yield RetryingClient(c, retries)
    finally:
        try: c.close()
        except: pass

class RetryingClient:
    def __init__(self, client, retries):
        self.c = client
        self.retries = retries

    def _try(self, fn, *a, **kw):
        last = None
        for i in range(self.retries):
            try:
                res = fn(*a, **kw)
                if hasattr(res, "isError") and res.isError():  # Modbus pdu exception
                    raise ModbusException(res)
                return res
            except Exception as e:
                last = e
                time.sleep(0.05 * (i+1))
        raise last

    # Convenience wrappers
    def read_hr(self, addr, count=1, unit=1):
        return self._try(self.c.read_holding_registers, addr, count=count, unit=unit)

    def write_hr(self, addr, value, unit=1):
        return self._try(self.c.write_register, addr, value=value, unit=unit)

    def write_hrs(self, addr, values, unit=1):
        return self._try(self.c.write_registers, addr, values=values, unit=unit)
