"""
Configuration settings for the Advanced Threat Fusion Engine.
Supports real-time threat intelligence feeds and LLM-powered analysis.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
CACHE_DIR = BASE_DIR / 'cache'

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

# Database settings
DATABASE_PATH = os.getenv('DB_PATH', str(BASE_DIR / 'threat_fusion.db'))
VECTOR_INDEX_PATH = os.getenv('VECTOR_INDEX_PATH', str(BASE_DIR / 'threat_vectors.index'))
KNOWLEDGE_GRAPH_PATH = os.getenv('KNOWLEDGE_GRAPH_PATH', str(BASE_DIR / 'knowledge_graph.json'))

# ============================================================================
# THREAT INTELLIGENCE API KEYS
# ============================================================================
# Get your free API keys from:
# - AlienVault OTX: https://otx.alienvault.com/api
# - VirusTotal: https://www.virustotal.com/gui/my-apikey
# - AbuseIPDB: https://www.abuseipdb.com/account/api
# - URLhaus: No key required (public API)
# - ThreatFox: No key required (public API)

ALIENVAULT_OTX_API_KEY = os.getenv('OTX_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY', '')

# ============================================================================
# LLM SETTINGS
# ============================================================================
# ============================================================================
# LLM SETTINGS
# ============================================================================
# Supports: Ollama (local) only
LLM_PROVIDER = 'ollama'
OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://localhost:11434')
DEFAULT_MODEL = os.getenv('LLM_MODEL', 'llama3.2:3b')

# LLM Model configurations
LLM_MODELS = {
    'ollama': 'llama3.2:3b'  # Best model for threat intelligence analysis
}

# LLM Limits
LLM_MAX_OUTPUT_TOKENS = int(os.getenv('LLM_MAX_OUTPUT_TOKENS', '2048'))
LLM_RATE_LIMIT_RPM = 0  # No rate limit for local LLM

# ============================================================================
# EXTRACTION SETTINGS
# ============================================================================
IOC_CONFIDENCE_THRESHOLD = float(os.getenv('IOC_CONFIDENCE_THRESHOLD', '0.7'))
TTP_CONFIDENCE_THRESHOLD = float(os.getenv('TTP_CONFIDENCE_THRESHOLD', '0.7'))
MAX_IOCS_PER_DOCUMENT = int(os.getenv('MAX_IOCS_PER_DOCUMENT', '100'))
MAX_TTPS_PER_DOCUMENT = int(os.getenv('MAX_TTPS_PER_DOCUMENT', '50'))

# ============================================================================
# FUSION & CORRELATION SETTINGS
# ============================================================================
IOC_OVERLAP_THRESHOLD = int(os.getenv('IOC_OVERLAP_THRESHOLD', '2'))
EMBEDDING_SIMILARITY_THRESHOLD = float(os.getenv('EMBEDDING_SIMILARITY_THRESHOLD', '0.85'))
TTP_OVERLAP_THRESHOLD = int(os.getenv('TTP_OVERLAP_THRESHOLD', '1'))
TEMPORAL_WINDOW_DAYS = int(os.getenv('TEMPORAL_WINDOW_DAYS', '30'))
MIN_CAMPAIGN_CONFIDENCE = float(os.getenv('MIN_CAMPAIGN_CONFIDENCE', '0.6'))

# ============================================================================
# ENRICHMENT SETTINGS
# ============================================================================
AUTO_ENRICHMENT_ENABLED = os.getenv('AUTO_ENRICHMENT', 'true').lower() == 'true'
ENRICHMENT_CACHE_TTL = int(os.getenv('ENRICHMENT_CACHE_TTL', '86400'))  # 24 hours
MAX_ENRICHMENT_RETRIES = int(os.getenv('MAX_ENRICHMENT_RETRIES', '3'))

# ============================================================================
# THREAT SCORING
# ============================================================================
THREAT_SCORE_WEIGHTS = {
    'ioc_count': 0.2,
    'ttp_severity': 0.3,
    'source_reputation': 0.15,
    'temporal_relevance': 0.15,
    'campaign_association': 0.2
}

# ============================================================================
# FEED SETTINGS
# ============================================================================
FEED_UPDATE_INTERVAL = int(os.getenv('FEED_UPDATE_INTERVAL', '3600'))  # 1 hour
MAX_FEED_ITEMS = int(os.getenv('MAX_FEED_ITEMS', '100'))
FEED_TIMEOUT = int(os.getenv('FEED_TIMEOUT', '30'))  # seconds

# ============================================================================
# ADVANCED FEATURES
# ============================================================================
ENABLE_THREAT_PREDICTION = os.getenv('ENABLE_PREDICTION', 'true').lower() == 'true'
ENABLE_AUTO_PLAYBOOKS = os.getenv('ENABLE_PLAYBOOKS', 'true').lower() == 'true'
ENABLE_YARA_GENERATION = os.getenv('ENABLE_YARA', 'true').lower() == 'true'
ENABLE_GEOLOCATION = os.getenv('ENABLE_GEOLOCATION', 'true').lower() == 'true'

# ============================================================================
# LOGGING SETTINGS
# ============================================================================
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', str(BASE_DIR / 'threat_fusion.log'))
ENABLE_AUDIT_LOG = os.getenv('ENABLE_AUDIT_LOG', 'true').lower() == 'true'

# ============================================================================
# API RATE LIMITS
# ============================================================================
RATE_LIMITS = {
    'otx': {'calls': 10, 'period': 60},  # 10 calls per minute
    'virustotal': {'calls': 4, 'period': 60},  # 4 calls per minute (free tier)
    'abuseipdb': {'calls': 1000, 'period': 86400},  # 1000 per day
}

# ============================================================================
# CACHE SETTINGS
# ============================================================================
ENABLE_CACHING = os.getenv('ENABLE_CACHING', 'true').lower() == 'true'
CACHE_BACKEND = os.getenv('CACHE_BACKEND', 'file')  # 'file', 'redis', 'memory'
CACHE_TTL_DEFAULT = int(os.getenv('CACHE_TTL', '3600'))

# ============================================================================
# EXPORT FORMATS
# ============================================================================
SUPPORTED_EXPORT_FORMATS = ['json', 'csv', 'stix', 'misp', 'pdf']
DEFAULT_EXPORT_FORMAT = os.getenv('DEFAULT_EXPORT_FORMAT', 'json')
