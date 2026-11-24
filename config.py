import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# LLM Settings
MAX_LLM_ATTEMPTS = 3
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL = "llama-3.3-70b-versatile"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
LLM_MODEL = "deepseek-chat"

# Scanner Settings
REQUEST_TIMEOUT = 10
REQUEST_DELAY = 0.2
MAX_CRAWL_DEPTH = 3
MAX_PAGES = 50

# Risk Levels
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

# CVSS Scores
CVSS_SCORES = {
    "sqli": 9.8,
    "xss_stored": 8.8,
    "xss_reflected": 7.1,
    "xss_dom": 6.1,
    "idor": 7.5,
}

# Report Settings
REPORT_OUTPUT_DIR = "outputs/reports"
REPORT_AUTHOR = "WebProbe v1.0"

# Tool Info
TOOL_NAME = "WebProbe"
TOOL_VERSION = "v1.0"
TOOL_GITHUB = "github.com/yourname/webprobe"

# Scan options menu
SCAN_OPTIONS = {
    "1": ["sqli"],
    "2": ["xss"],
    "3": ["idor"],
    "4": ["sqli", "xss"],
    "5": ["sqli", "idor"],
    "6": ["xss", "idor"],
    "7": ["sqli", "xss", "idor"],
}
