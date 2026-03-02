# Advanced Threat Fusion Engine - Operational Workflow

This document outlines the complete workflow for setting up, configuring, and operating the Advanced Threat Fusion Engine.

## 1. System Setup & Prerequisites

Before running the application, ensure the following components are ready.

### Environment
- **Python 3.9+** is required.
- **Virtual Environment**: Recommended to avoid dependency conflicts.

### API Keys (Critical)
The power of this engine comes from its integrations. You will need API keys for:
- **AlienVault OTX**: For threat feeds.
- **VirusTotal**: For reputation checks.
- **AbuseIPDB**: For IP reputation.
- **Google Gemini / OpenAI**: For the LLM Analyst (unless using local Ollama).

### LLM Provider
Choose one of the following:
1.  **Local (Ollama)**: Free, privacy-focused. Requires pulling a model (e.g., `ollama pull gemma2:2b`).
2.  **Cloud (OpenAI/Google)**: Requires API keys. Better performance for complex reasoning.

## 2. Configuration

1.  **Clone/Open Project**: Ensure you are in the `threat_fusion_engine` directory.
2.  **Setup Environment Variables**:
    ```bash
    cp .env.example .env
    ```
3.  **Edit `.env`**:
    Open `.env` and fill in your keys.
    ```env
    # Threat Feeds
    OTX_API_KEY=your_otx_key
    VT_API_KEY=your_vt_key
    
    # LLM Settings
    LLM_PROVIDER=google  # or openai, ollama
    GOOGLE_API_KEY=your_google_key
    ```

## 3. Installation & Launch

1.  **Create Virtual Environment**:
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\activate
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: This may take a few minutes as it installs heavy libraries like `spacy` and `torch`.*

3.  **Run Streamlit App**:
    ```bash
    streamlit run app.py
    ```
    The application will open at `http://localhost:8501`.

## 4. Operational Workflow

Follow this cycle to process threat intelligence.

### Step 1: Data Ingestion (Collecting Raw Intel)
Navigate to the **Data Ingestion** page.
- **Option A: Manual Upload**: Upload `.txt`, `.md`, or `.json` files containing threat reports.
- **Option B: Blog Ingestion**: Paste a URL to a security blog (e.g., The Hacker News, FireEye blog). The system scrapes the text.
- **Option C: OSINT Feeds**: Select "AlienVault OTX" or "Abuse.ch" into automatically fetch recent indicators.

**What happens:** The system stores the raw text and assigns a Document ID.

### Step 2: Extraction (Parsing IOCs & TTPs)
Navigate to **IOC/TTP Analysis**.
- Select a document you just ingested.
- Click **Analyze Selected Document**.
- **Result**:
    - **IOCs**: IPs, Domains, Hashes extracted via Regex + LLM verification.
    - **TTPs**: Mapped to MITRE ATT&CK techniques (e.g., T1059 PowerShell).
    - **Confidence Scores**: Validated by the LLM.

### Step 3: Fusion (Correlating Intelligence)
Navigate to **Campaign Analysis**.
- This step connects isolated documents.
- Click **Run Fusion Analysis**.
- **Process**:
    - The engine compares IOC overlaps (do two docs mention the same hash?).
    - It compares TTP patterns.
    - It uses semantic similarity (vector embeddings) to find similar narratives.
- **Output**: "Campaigns" are created, grouping related documents (e.g., "Campaign #1 (APT29 related)").

### Step 4: AI Analyst (Deep Dive)
Navigate to **AI Analyst**.
- **Natural Language Query**: Ask questions like:
    - *"What campaigns are targeting the financial sector?"*
    - *"Summarize the attack flow for Campaign #1"*
    - *"Generate a YARA rule for the malware found in the latest report"*
- **Output**: The LLM uses the context of your stored documents to answer extensively.

## 5. Deployment / Production Notes
- **Database**: Uses SQLite (`threat_fusion.db`) by default.
- **Vector Store**: Uses FAISS for semantic search.
- **Logs**: Check `threat_fusion.log` for ingestion errors or API rate limits.
