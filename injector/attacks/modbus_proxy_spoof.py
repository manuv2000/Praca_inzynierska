# injector/attacks/modbus_proxy_spoof.py

import socket
import threading
from typing import Optional

from injector.core.config import PlcConfig
from injector.core.logging_setup import logging

log = logging.getLogger(__name__)


def handle_connection(client_sock: socket.socket, plc_addr, stop_event: threading.Event):
    plc_sock: Optional[socket.socket] = None
    try:
        plc_sock = socket.create_connection(plc_addr, timeout=3.0)
        client_sock.settimeout(1.0)
        plc_sock.settimeout(1.0)

        t1 = threading.Thread(
            target=forward_with_optional_spoof,
            args=(client_sock, plc_sock, False, stop_event),
            daemon=True,
        )
        t2 = threading.Thread(
            target=forward_with_optional_spoof,
            args=(plc_sock, client_sock, True, stop_event),
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


def forward_with_optional_spoof(src: socket.socket, dst: socket.socket, is_plc_to_client: bool, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            data = src.recv(4096)
            if not data:
                break
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            if is_plc_to_client:
                spoofed = spoof_modbus_response_if_needed(data)
                dst.sendall(spoofed)
            else:
                dst.sendall(data)
        except OSError:
            break


def spoof_modbus_response_if_needed(data: bytes) -> bytes:
    # TODO: tu dopiero dojdzie prawdziwe spoofing (modyfikacja odpowiedzi)
    return data


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
    srv.listen(20)
    srv.settimeout(1.0)

    log.info("Spoof proxy listening on %s:%s -> PLC %s:%s",
             listen_host, listen_port, cfg.plc_host, cfg.plc_port)

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
                args=(client_sock, plc_addr, stop_event),
                daemon=True,
            )
            t.start()
    finally:
        try:
            srv.close()
        except Exception:
            pass
        log.info("Spoof proxy stopped.")
