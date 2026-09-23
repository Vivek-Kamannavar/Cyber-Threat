"""
Backend System & Engine Configurations
Loads parameters and detection boundaries from environment variables with sensible fallback defaults.
Supports dynamic environment variable overrides during runtime and testing.
"""

import os
from typing import Any, Dict, List

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConfigMeta(type):
    """Metaclass that provides dynamic property lookups reflecting current os.environ overrides."""
    _overrides: Dict[str, Any] = {}

    def _get_val(cls, key: str, default: Any, caster: type = str):
        if key in cls._overrides:
            return cls._overrides[key]
        val = os.getenv(key)
        if val is not None:
            if caster == bool:
                return val.lower() in ("true", "1", "yes")
            return caster(val)
        return default

    def _set_val(cls, key: str, val: Any):
        cls._overrides[key] = val

    @property
    def HOST(cls) -> str:
        return cls._get_val("HOST", "0.0.0.0", str)

    @HOST.setter
    def HOST(cls, val: str):
        cls._set_val("HOST", val)

    @property
    def PORT(cls) -> int:
        return cls._get_val("PORT", 8000, int)

    @PORT.setter
    def PORT(cls, val: int):
        cls._set_val("PORT", val)

    @property
    def WINDOW_SIZE_SECONDS(cls) -> float:
        return cls._get_val("WINDOW_SIZE_SECONDS", 60.0, float)

    @WINDOW_SIZE_SECONDS.setter
    def WINDOW_SIZE_SECONDS(cls, val: float):
        cls._set_val("WINDOW_SIZE_SECONDS", val)

    @property
    def DATA_DIODE_MODE(cls) -> bool:
        return cls._get_val("DATA_DIODE_MODE", True, bool)

    @DATA_DIODE_MODE.setter
    def DATA_DIODE_MODE(cls, val: bool):
        cls._set_val("DATA_DIODE_MODE", val)

    @property
    def ALLOW_ORIGINS(cls) -> List[str]:
        return cls._get_val("ALLOW_ORIGINS", ["*"], list)

    @ALLOW_ORIGINS.setter
    def ALLOW_ORIGINS(cls, val: List[str]):
        cls._set_val("ALLOW_ORIGINS", val)

    @property
    def DDOS_RATE_THRESHOLD(cls) -> int:
        return cls._get_val("DDOS_RATE_THRESHOLD", 25, int)

    @DDOS_RATE_THRESHOLD.setter
    def DDOS_RATE_THRESHOLD(cls, val: int):
        cls._set_val("DDOS_RATE_THRESHOLD", val)

    @property
    def DDOS_ENTROPY_THRESHOLD(cls) -> float:
        return cls._get_val("DDOS_ENTROPY_THRESHOLD", 1.5, float)

    @DDOS_ENTROPY_THRESHOLD.setter
    def DDOS_ENTROPY_THRESHOLD(cls, val: float):
        cls._set_val("DDOS_ENTROPY_THRESHOLD", val)

    @property
    def C2_CV_THRESHOLD(cls) -> float:
        return cls._get_val("C2_CV_THRESHOLD", 0.22, float)

    @C2_CV_THRESHOLD.setter
    def C2_CV_THRESHOLD(cls, val: float):
        cls._set_val("C2_CV_THRESHOLD", val)

    @property
    def DNS_ENTROPY_THRESHOLD(cls) -> float:
        return cls._get_val("DNS_ENTROPY_THRESHOLD", 3.7, float)

    @DNS_ENTROPY_THRESHOLD.setter
    def DNS_ENTROPY_THRESHOLD(cls, val: float):
        cls._set_val("DNS_ENTROPY_THRESHOLD", val)

    @property
    def RECON_PORT_THRESHOLD(cls) -> int:
        return cls._get_val("RECON_PORT_THRESHOLD", 15, int)

    @RECON_PORT_THRESHOLD.setter
    def RECON_PORT_THRESHOLD(cls, val: int):
        cls._set_val("RECON_PORT_THRESHOLD", val)

    @property
    def RECON_HOST_THRESHOLD(cls) -> int:
        return cls._get_val("RECON_HOST_THRESHOLD", 20, int)

    @RECON_HOST_THRESHOLD.setter
    def RECON_HOST_THRESHOLD(cls, val: int):
        cls._set_val("RECON_HOST_THRESHOLD", val)

    @property
    def EXFIL_ASYMMETRY_RATIO(cls) -> float:
        return cls._get_val("EXFIL_ASYMMETRY_RATIO", 10.0, float)

    @EXFIL_ASYMMETRY_RATIO.setter
    def EXFIL_ASYMMETRY_RATIO(cls, val: float):
        cls._set_val("EXFIL_ASYMMETRY_RATIO", val)

    @property
    def EXFIL_BYTES_THRESHOLD(cls) -> int:
        return cls._get_val("EXFIL_BYTES_THRESHOLD", 5000000, int)

    @EXFIL_BYTES_THRESHOLD.setter
    def EXFIL_BYTES_THRESHOLD(cls, val: int):
        cls._set_val("EXFIL_BYTES_THRESHOLD", val)

    @property
    def ALERT_COOLDOWN_SECONDS(cls) -> float:
        return cls._get_val("ALERT_COOLDOWN_SECONDS", 3.0, float)

    @ALERT_COOLDOWN_SECONDS.setter
    def ALERT_COOLDOWN_SECONDS(cls, val: float):
        cls._set_val("ALERT_COOLDOWN_SECONDS", val)

    @property
    def DB_PATH(cls) -> str:
        default_path = os.path.join(ROOT_DIR, "backend", "data", "cyber_threat.db")
        return cls._get_val("SQLITE_DB_PATH", default_path, str)

    @DB_PATH.setter
    def DB_PATH(cls, val: str):
        cls._set_val("SQLITE_DB_PATH", val)

    @property
    def MODEL_PATH(cls) -> str:
        default_path = os.path.join(ROOT_DIR, "backend", "data", "isolation_forest.joblib")
        return cls._get_val("MODEL_PATH", default_path, str)

    @MODEL_PATH.setter
    def MODEL_PATH(cls, val: str):
        cls._set_val("MODEL_PATH", val)


class Config(metaclass=ConfigMeta):
    """Centralized System & Engine Configuration."""
    ROOT_DIR: str = ROOT_DIR
