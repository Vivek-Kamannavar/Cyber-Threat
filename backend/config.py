"""
Backend System & Engine Configurations
"""

class Config:
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WINDOW_SIZE_SECONDS: float = 60.0
    DATA_DIODE_MODE: bool = True
    ALLOW_ORIGINS: list = ["*"]
