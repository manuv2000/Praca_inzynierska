# injector/modbus_proxy/framing.py
from __future__ import annotations
from typing import Optional, Tuple

def u16(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)

def p16(n: int) -> bytes:
    return int(n).to_bytes(2, byteorder="big", signed=False)

def parse_mbap_frame(buf: bytearray) -> Optional[bytes]:
    """
    Extract exactly one Modbus/TCP frame from a TCP stream buffer.
    Returns the frame bytes or None if incomplete.

    MBAP:
      TID(2) PID(2) LEN(2) UID(1) + PDU(...)
    LEN = bytes of UID + PDU
    Total frame length on wire = 6 + LEN
    """
    if len(buf) < 7:
        return None
    length_field = u16(buf[4:6])
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
    tid = u16(frame[0:2])
    pid = u16(frame[2:4])
    length = u16(frame[4:6])
    unit_id = frame[6]
    pdu = frame[7:]
    return tid, pid, length, unit_id, pdu

def rebuild_mbap(tid: int, pid: int, unit_id: int, pdu: bytes) -> bytes:
    new_length = 1 + len(pdu)  # UID + PDU
    return p16(tid) + p16(pid) + p16(new_length) + bytes([unit_id]) + pdu
