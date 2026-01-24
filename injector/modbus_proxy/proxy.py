# injector/modbus_proxy/proxy.py
from __future__ import annotations
import logging
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from injector.modbus_proxy.framing import parse_mbap_frame
from injector.modbus_proxy.state import ConnState

log = logging.getLogger(__name__)

FrameHook = Callable[[bytes], bytes]
FrameTap = Callable[[bytes], None]

@dataclass(frozen=True)
class StreamHooks:
    """
    Optional hooks for each direction.
    - tap(frame): observe frame (no modification)
    - hook(frame)->frame: modify frame
    """
    tap: Optional[FrameTap] = None
    hook: Optional[FrameHook] = None

def forward_stream(
    *,
    src: socket.socket,
    dst: socket.socket,
    stop_event: threading.Event,
    direction: str,
    hooks: StreamHooks,
) -> None:
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

            if hooks.tap:
                try:
                    hooks.tap(frame)
                except Exception as e:
                    log.debug("[%s] tap error: %r", direction, e)

            if hooks.hook:
                try:
                    frame = hooks.hook(frame)
                except Exception as e:
                    log.debug("[%s] hook error: %r", direction, e)

            try:
                dst.sendall(frame)
            except OSError:
                return

def handle_connection(
    client_sock: socket.socket,
    plc_addr: Tuple[str, int],
    stop_event: threading.Event,
    client_to_plc: StreamHooks,
    plc_to_client: StreamHooks,
) -> None:
    plc_sock: Optional[socket.socket] = None

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
                hooks=client_to_plc,
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
                hooks=plc_to_client,
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

def run_tcp_proxy(
    *,
    listen_host: str,
    listen_port: int,
    plc_host: str,
    plc_port: int,
    stop_event: threading.Event,
    ready_event: Optional[threading.Event] = None,
    client_to_plc: StreamHooks,
    plc_to_client: StreamHooks,
) -> None:
    plc_addr = (plc_host, plc_port)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(50)
    srv.settimeout(1.0)

    log.info("Proxy listening on %s:%s -> PLC %s:%s", listen_host, listen_port, plc_host, plc_port)

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

            log.info("New client for proxy: %s", addr)
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, plc_addr, stop_event, client_to_plc, plc_to_client),
                daemon=True,
            )
            t.start()
    finally:
        try:
            srv.close()
        except Exception:
            pass
        log.info("Proxy stopped.")
