# injector/core/config.py
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any, Dict
import yaml

_CONFIG_CACHE: Optional["PlcConfig"] = None

@dataclass(frozen=True)
class PlcConfig:
    # rzeczywiste PLC
    plc_host: str = "127.0.0.1"
    plc_port: int = 502
    unit_id: int = 1

    heartbeat_register: int = 0
    marker_register: int = 10

    safe_write_register: int = 2
    safe_write_min: int = 0
    safe_write_max: int = 1000

    # proxy
    proxy_enabled: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 1502

    @property
    def effective_host(self) -> str:
        return self.proxy_host if self.proxy_enabled else self.plc_host

    @property
    def effective_port(self) -> int:
        return self.proxy_port if self.proxy_enabled else self.plc_port


def _project_root() -> Path:
    # injector/core/config.py -> project_root
    return Path(__file__).resolve().parents[2]

def _load_yaml_dict() -> Dict[str, Any]:
    yaml_path = _project_root() / "config" / "plc_config.yaml"
    if not yaml_path.exists():
        return {}
    with yaml_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}

def _plc_config_from_yaml(data: Dict[str, Any]) -> PlcConfig:
    plc = data.get("plc", {}) or {}
    proxy = data.get("proxy", {}) or {}

    return PlcConfig(
        plc_host=str(plc.get("host", "127.0.0.1")),
        plc_port=int(plc.get("port", 502)),
        unit_id=int(plc.get("unit_id", 1)),

        heartbeat_register=int(plc.get("heartbeat_register", 0)),
        marker_register=int(plc.get("marker_register", 10)),

        safe_write_register=int(plc.get("safe_write_register", 2)),
        safe_write_min=int(plc.get("safe_write_min", 0)),
        safe_write_max=int(plc.get("safe_write_max", 1000)),

        proxy_enabled=bool(proxy.get("enabled", False)),
        proxy_host=str(proxy.get("host", "127.0.0.1")),
        proxy_port=int(proxy.get("port", 1502)),
    )

def get_plc_config() -> PlcConfig:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        data = _load_yaml_dict()
        _CONFIG_CACHE = _plc_config_from_yaml(data) if data else PlcConfig()
    return _CONFIG_CACHE

def reset_plc_config_cache() -> None:
    global _CONFIG_CACHE
    _CONFIG_CACHE = None
