"""
SecureMailScope - Configuration Module
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "sample_pcaps"
MODELS_DIR = DATA_DIR / "models"
CA_STORE_DIR = DATA_DIR / "ca_store"
REPORTS_DIR = DATA_DIR / "reports"
UPLOAD_DIR = DATA_DIR / "uploads"

for d in [DATA_DIR, SAMPLES_DIR, MODELS_DIR, CA_STORE_DIR, REPORTS_DIR, UPLOAD_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class Settings:
    APP_NAME: str = "SecureMailScope"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/securemailscope.db")
    
    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_EXTENSIONS: set = {".pcap", ".pcapng", ".cap"}
    MAX_PACKETS_PER_FILE: int = 250000
    ANALYSIS_TIMEOUT_SECONDS: int = 180
    
    # Paths
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    SAMPLES_DIR: Path = SAMPLES_DIR
    MODELS_DIR: Path = MODELS_DIR
    CA_STORE_DIR: Path = CA_STORE_DIR
    REPORTS_DIR: Path = REPORTS_DIR
    UPLOAD_DIR: Path = UPLOAD_DIR
    
    # Trust store
    CUSTOM_CA_BUNDLE: Path = CA_STORE_DIR / "root_ca.crt"


settings = Settings()
