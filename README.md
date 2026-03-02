# 🛡️ Advanced Cyber Threat Intelligence using LLM

An advanced, production-ready Cyber Threat Intelligence (CTI) platform powered by Large Language Models. This system automates threat intelligence collection, analysis, correlation, and response generation using real-time threat feeds and AI-powered analytics.

## 🌟 Key Features

### 🔄 Real-Time Threat Intelligence Feeds
- **AlienVault OTX Integration** - Real threat pulses and IOCs from the community
- **VirusTotal API** - File, URL, IP, and domain reputation analysis
- **AbuseIPDB** - IP address abuse and reputation data
- **URLhaus** - Malicious URL database from abuse.ch
- **ThreatFox** - IOC database with malware associations
- **Automated Feed Updates** - Continuous ingestion with configurable intervals

### 🤖 LLM-Powered Advanced Analytics
- **Threat Actor Profiling** - AI-generated profiles with attribution analysis
- **Attack Pattern Prediction** - Predict next attack vectors based on historical data
- **Automated Threat Reports** - Generate executive summaries and technical reports
- **IOC Contextualization** - Explain the significance of each indicator
- **Campaign Attribution** - Link attacks to known threat groups
- **Threat Hunting Recommendations** - AI-suggested hunting queries for multiple platforms

### 🔗 Advanced Correlation Engine
- **Multi-dimensional Correlation** - IOC, TTP, temporal, and semantic analysis
- **Behavioral Analysis** - Identify attack patterns and anomalies
- **Kill Chain Mapping** - Map threats to the cyber kill chain
- **MITRE ATT&CK Mapping** - Automatic technique and tactic mapping
- **Threat Scoring** - AI-powered risk assessment with weighted scoring

### ⚡ Intelligent Automation
- **Auto-enrichment Pipeline** - Automatic IOC enrichment from multiple sources
- **Smart Alerting** - Context-aware threat notifications
- **Playbook Generation** - AI-generated incident response playbooks
- **Threat Prioritization** - ML-based priority ranking
- **YARA Rule Generation** - Automated detection rule creation

### 📊 Advanced Visualization
- **Interactive Dashboards** - Real-time threat intelligence overview
- **Temporal Attack Timeline** - Time-based attack flow visualization
- **Relationship Networks** - Entity relationship graphs
- **Threat Heatmaps** - Risk visualization by geography and sector
- **Campaign Tracking** - Monitor ongoing threat campaigns

### 🎯 Unique Differentiators
- **LLM-Powered Threat Narratives** - Natural language threat stories
- **Predictive Threat Intelligence** - Forecast emerging threats
- **Conversational Threat Analysis** - ChatGPT-style threat analyst
- **Custom IOC Extraction** - Domain-specific indicator extraction
- **Threat Simulation** - What-if scenario analysis
- **Multi-LLM Support** - OpenAI, Google Gemini, or local Ollama

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- (Optional) Ollama for local LLM support
- API keys for threat intelligence feeds (free tiers available)

### Installation

1. **Clone the repository**
```bash
cd threat_fusion_engine
```

2. **Create virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure API keys**
```bash
cp .env.example .env
# Edit .env and add your API keys
```

5. **Run the application**
```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## 🔑 API Keys Setup

### Free API Keys (Recommended)

1. **AlienVault OTX** (Free, Unlimited)
   - Sign up: https://otx.alienvault.com/
   - Get API key: https://otx.alienvault.com/api
   - Add to `.env`: `OTX_API_KEY=your_key_here`

2. **VirusTotal** (Free: 4 requests/min)
   - Sign up: https://www.virustotal.com/
   - Get API key: https://www.virustotal.com/gui/my-apikey
   - Add to `.env`: `VT_API_KEY=your_key_here`

3. **AbuseIPDB** (Free: 1000 requests/day)
   - Sign up: https://www.abuseipdb.com/
   - Get API key: https://www.abuseipdb.com/account/api
   - Add to `.env`: `ABUSEIPDB_API_KEY=your_key_here`

### LLM Provider Setup

**Option 1: Ollama (Free, Local)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull gemma2:2b

# Set in .env
LLM_PROVIDER=ollama
```

**Option 2: OpenAI**
```bash
# Get API key from https://platform.openai.com/api-keys
# Set in .env
LLM_PROVIDER=openai
OPENAI_API_KEY=your_key_here
```

**Option 3: Google Gemini**
```bash
# Get API key from https://makersuite.google.com/app/apikey
# Set in .env
LLM_PROVIDER=google
GOOGLE_API_KEY=your_key_here
```

## 📖 Usage Guide

### 1. Data Ingestion
- **Manual Upload**: Upload threat reports (TXT, JSON, MD)
- **Blog Ingestion**: Ingest security blog posts via URL
- **OSINT Feeds**: Automatically fetch from OTX, URLhaus, ThreatFox
- **Sample Data**: Load demo data for testing

### 2. IOC/TTP Analysis
- Extract Indicators of Compromise (IOCs)
- Identify Tactics, Techniques, and Procedures (TTPs)
- Automatic MITRE ATT&CK mapping
- Real-time enrichment with VirusTotal, AbuseIPDB

### 3. Campaign Analysis
- Correlate related threats
- Identify attack campaigns
- Generate campaign profiles
- Track threat actor activities

### 4. AI Analyst Queries
- **Natural Language Queries**: Ask questions in plain English
- **IOC Deep Analysis**: Detailed analysis of specific indicators
- **Campaign Deep Dive**: Comprehensive campaign investigation
- **Threat Hunting**: Get hunting queries for your SIEM

### 5. Advanced Features
- **Threat Prediction**: Forecast next attack vectors
- **Automated Reports**: Generate executive summaries
- **Response Playbooks**: Get step-by-step incident response guides
- **YARA Rules**: Auto-generate detection rules

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Streamlit Web UI                        │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ Threat Feeds   │  │  LLM Analytics  │  │  Enrichment     │
│ - OTX          │  │  - Profiling    │  │  - VirusTotal   │
│ - URLhaus      │  │  - Prediction   │  │  - AbuseIPDB    │
│ - ThreatFox    │  │  - Reports      │  │  - Caching      │
└────────┬───────┘  └────────┬────────┘  └────────┬────────┘
         │                   │                     │
         └───────────────────┼─────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Fusion Engine  │
                    │  - Correlation  │
                    │  - Scoring      │
                    │  - Campaigns    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │     Storage     │
                    │  - SQLite       │
                    │  - FAISS        │
                    │  - Graph        │
                    └─────────────────┘
```

## 🎓 Advanced Use Cases

### 1. Threat Intelligence Automation
```python
# Automatically ingest, analyze, and correlate threats
from threat_feeds import ThreatFeedAggregator
from enrichment import AutoEnrichmentPipeline

aggregator = ThreatFeedAggregator()
feeds = aggregator.fetch_all_feeds()

# Auto-enrich all IOCs
pipeline = AutoEnrichmentPipeline(storage)
pipeline.process_new_iocs(document_id)
```

### 2. AI-Powered Threat Analysis
```python
from llm_analytics import AdvancedThreatAnalytics

analytics = AdvancedThreatAnalytics()

# Generate threat actor profile
profile = analytics.generate_threat_actor_profile(campaign_data)

# Predict next attack
prediction = analytics.predict_next_attack_vector(historical_data)

# Generate response playbook
playbook = analytics.generate_response_playbook(threat_data)
```

### 3. Custom Threat Hunting
```python
# Generate hunting queries for your environment
queries = analytics.generate_threat_hunting_queries({
    'name': 'APT29 Campaign',
    'iocs': [...],
    'ttps': [...]
})
```

## 📊 Features Comparison

| Feature | Basic CTI | This System |
|---------|-----------|-------------|
| Real-time Feeds | ❌ | ✅ Multiple sources |
| LLM Analysis | ❌ | ✅ Advanced AI |
| Auto-enrichment | ❌ | ✅ Multi-source |
| Threat Prediction | ❌ | ✅ AI-powered |
| Campaign Detection | Basic | ✅ Advanced correlation |
| Report Generation | Manual | ✅ Automated |
| Playbook Creation | Manual | ✅ AI-generated |
| YARA Rules | Manual | ✅ Auto-generated |
| Threat Scoring | Simple | ✅ Multi-factor |
| API Integration | Limited | ✅ Extensive |

## 🔒 Security Considerations

- API keys are stored in `.env` (never commit to git)
- Rate limiting implemented for all external APIs
- Caching reduces API calls and improves performance
- Audit logging tracks all system activities
- Input validation on all user inputs

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional threat feed integrations
- Enhanced visualization capabilities
- Machine learning models for threat classification
- STIX/TAXII support
- Multi-tenancy features

## 📝 License

This project is for educational and research purposes. Ensure compliance with all API terms of service.

## 🙏 Acknowledgments

- AlienVault OTX Community
- abuse.ch for URLhaus and ThreatFox
- VirusTotal and AbuseIPDB
- MITRE ATT&CK Framework
- Open-source threat intelligence community

## 📧 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Built with ❤️ for the cybersecurity community**
