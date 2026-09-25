import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Path configurations
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

# Camera and video settings
SAMPLE_VIDEO_1 = os.path.join(BASE_DIR, "gettyimages-1215957003-640_adpp.mp4")
SAMPLE_VIDEO_2 = os.path.join(BASE_DIR, "15690486_1920_1080_25fps.mp4")
_default_sample = SAMPLE_VIDEO_1
VIDEO_SOURCE = os.getenv("VIDEO_SOURCE", _default_sample if os.path.exists(_default_sample) else 0)

FRAME_WIDTH = 640
FRAME_HEIGHT = 480
DISPLAY_WIDTH = 640
DISPLAY_HEIGHT = 480
FPS = int(os.getenv("FPS", 20))

# Detection settings
DETECTION_THRESHOLD = float(os.getenv("DETECTION_THRESHOLD", 0.5))
USE_GPU = os.getenv("USE_GPU", "true").lower() in ("true", "1", "yes")

# Classes of interest for detection
CLASSES_OF_INTEREST = [
    'person', 'bicycle', 'car', 'motorcycle', 'bus', 'truck',
    'backpack', 'suitcase', 'cell phone', 'handbag', 'knife', 'drone'
]

# Border crossing detection settings
BORDER_LINES = [
    {
        'id': 'main_border',
        'points': [(0, FRAME_HEIGHT // 2), (FRAME_WIDTH, FRAME_HEIGHT // 2)],
        'direction': 'both'
    },
    {
        'id': 'northeast_border',
        'points': [(0, FRAME_HEIGHT), (FRAME_WIDTH, 0)],
        'direction': 'north_to_south'
    }
]

# Fence tampering detection settings
FENCE_REGIONS = []
TAMPERING_SENSITIVITY = float(os.getenv("TAMPERING_SENSITIVITY", 0.3))

# Behavior analysis settings
SUSPICIOUS_BEHAVIORS = {
    "loitering": {
        "time_threshold": int(os.getenv("LOITERING_TIME", 30)),
        "area_threshold": float(os.getenv("LOITERING_AREA", 0.2))
    },
    "crawling": {
        "height_ratio_threshold": float(os.getenv("CRAWLING_RATIO", 0.5))
    }
}

# Alert settings
ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", 5))
DASHBOARD_ALERTS_ENABLED = os.getenv("DASHBOARD_ALERTS_ENABLED", "true").lower() == "true"

# Performance settings for edge deployment
USE_GPU = os.getenv("USE_GPU", "true").lower() == "true"
MODEL_PRECISION = os.getenv("MODEL_PRECISION", "fp16")
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", 1))

# Logging settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "logs", "surveillance.log")

# ─── Innovation Architecture additions ──────────────────────────────────────

# Database — SQLite by default; set DATABASE_URL env var for PostgreSQL
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'data', 'surveillance.db')}"
)

# Evidence retention
EVIDENCE_RETENTION_DAYS: int = int(os.getenv("EVIDENCE_RETENTION_DAYS", 30))

# Behavioral Baseline Engine
BASELINE_BOOTSTRAP_DAYS: int = int(os.getenv("BASELINE_BOOTSTRAP_DAYS", 3))
BASELINE_UPDATE_INTERVAL_HOURS: int = int(os.getenv("BASELINE_UPDATE_INTERVAL_HOURS", 24))

# Bandwidth-Aware Sync Layer
SYNC_COMMAND_URL: str = os.getenv("SYNC_COMMAND_URL", "http://localhost:8080")
SYNC_CHECK_INTERVAL_SECONDS: int = int(os.getenv("SYNC_CHECK_INTERVAL_SECONDS", 30))

# AI Investigation Assistant
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
AI_MODEL: str = os.getenv("AI_MODEL", "gemini-3.5-flash-lite")

# Risk Scoring Weights
RISK_WEIGHT_BORDER_CROSSING: float = float(os.getenv("RISK_WEIGHT_BORDER_CROSSING", 50.0))
RISK_WEIGHT_FENCE_TAMPERING: float = float(os.getenv("RISK_WEIGHT_FENCE_TAMPERING", 45.0))
RISK_WEIGHT_INTRUSION: float = float(os.getenv("RISK_WEIGHT_INTRUSION", 40.0))
RISK_WEIGHT_CRAWLING: float = float(os.getenv("RISK_WEIGHT_CRAWLING", 35.0))
RISK_WEIGHT_LOITERING: float = float(os.getenv("RISK_WEIGHT_LOITERING", 20.0))
RISK_WEIGHT_ABANDONED: float = float(os.getenv("RISK_WEIGHT_ABANDONED", 15.0))
RISK_WEIGHT_BASELINE_ZSCORE: float = float(os.getenv("RISK_WEIGHT_BASELINE_ZSCORE", 25.0))

