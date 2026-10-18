"""Configuration settings for Smart Log Investigation Agent."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root if present
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

class Config:
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "offline").lower()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    MODEL_NAME = os.getenv("MODEL_NAME", "gemini-1.5-flash")
    
    AGENT_MAX_ITERATIONS = int(os.getenv("AGENT_MAX_ITERATIONS", "10"))
    ANOMALY_Z_THRESHOLD = float(os.getenv("ANOMALY_Z_THRESHOLD", "2.0"))
    TIME_WINDOW_MINUTES = int(os.getenv("TIME_WINDOW_MINUTES", "5"))
    SAMPLE_LOGS_DIR = PROJECT_ROOT / "data" / "sample_logs"
