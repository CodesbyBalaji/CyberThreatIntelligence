# 🚀 Quick Start Guide

## Get Your System Running in 5 Minutes!

### Step 1: Verify Installation ✅

Your system is already set up! The following components are installed:
- Python 3.11
- Virtual environment (.venv)
- All required packages
- Advanced CTI modules

### Step 2: Configure API Keys (Optional but Recommended)

#### Get Free API Keys:

1. **AlienVault OTX** (Recommended - Takes 2 minutes)
   ```bash
   # Visit: https://otx.alienvault.com/
   # Sign up (free)
   # Go to: https://otx.alienvault.com/api
   # Copy your API key
   ```

2. **VirusTotal** (Recommended - Takes 2 minutes)
   ```bash
   # Visit: https://www.virustotal.com/
   # Sign up (free)
   # Go to: https://www.virustotal.com/gui/my-apikey
   # Copy your API key
   ```

3. **AbuseIPDB** (Optional)
   ```bash
   # Visit: https://www.abuseipdb.com/
   # Sign up (free)
   # Go to: https://www.abuseipdb.com/account/api
   # Copy your API key
   ```

#### Add API Keys to .env:

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your keys
# You can use any text editor
nano .env
# or
code .env
```

**Example .env file:**
```bash
# Add your actual API keys here
OTX_API_KEY=your_actual_otx_key_here
VT_API_KEY=your_actual_vt_key_here
ABUSEIPDB_API_KEY=your_actual_abuseipdb_key_here

# LLM Configuration (default uses Ollama)
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
LLM_MODEL=gemma2:2b
```

### Step 3: Choose Your LLM Provider

#### Option A: Ollama (Local, Free, Private) - RECOMMENDED

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull gemma2:2b

# Verify it's running
ollama list
```

#### Option B: OpenAI (Paid, Best Quality)

```bash
# Get API key from: https://platform.openai.com/api-keys
# Add to .env:
LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_key_here
```

#### Option C: Google Gemini (Free Tier Available)

```bash
# Get API key from: https://makersuite.google.com/app/apikey
# Add to .env:
LLM_PROVIDER=google
GOOGLE_API_KEY=your_google_key_here
```

### Step 4: Run the Application

```bash
# Make sure you're in the project directory
cd /Users/balajia/Downloads/threat_fusion_engine

# Activate virtual environment
source .venv/bin/activate

# Run the application
streamlit run app.py
```

The application will open at: **http://localhost:8501**

### Step 5: First Time Usage

#### Test Without API Keys (Demo Mode):

1. **Go to "Data Ingestion" page**
2. **Click "Sample Data" tab**
3. **Click "Load All Sample Data"**
4. **Wait for demo data to load**

#### Test With API Keys:

1. **Go to "Data Ingestion" page**
2. **Click "OSINT Feeds" tab**
3. **Select "alientvault_otx"**
4. **Click "Ingest Feed"**
5. **Watch real threat data flow in!**

### Step 6: Explore Features

#### 📊 Dashboard
- View threat intelligence overview
- See active campaigns
- Monitor data sources

#### 🔍 IOC/TTP Analysis
- Select a document
- Click "Analyze Selected Document"
- View extracted IOCs and TTPs
- See MITRE ATT&CK mappings

#### 🔗 Campaign Analysis
- Click "Run Fusion Analysis"
- See correlated threats
- View detected campaigns
- Explore knowledge graph

#### 🤖 AI Analyst Queries
- **Natural Language**: Ask questions like "What do we know about domain malicious-site.com?"
- **IOC Analysis**: Deep dive into specific indicators
- **Campaign Deep Dive**: Comprehensive campaign investigation

---

## 🎯 Quick Demo Workflow

### Complete Demo in 2 Minutes:

1. **Start the app**
   ```bash
   streamlit run app.py
   ```

2. **Load demo data**
   - Go to "Data Ingestion" → "Sample Data"
   - Click "Load All Sample Data"

3. **View dashboard**
   - Go to "Dashboard"
   - See threat metrics and charts

4. **Analyze a threat**
   - Go to "IOC/TTP Analysis"
   - Select a document
   - Click "Analyze Selected Document"

5. **Ask the AI**
   - Go to "Analyst Queries"
   - Type: "Summarize the most critical threats"
   - Click "Submit Query"

---

## 🔧 Troubleshooting

### Issue: Streamlit won't start

```bash
# Make sure virtual environment is activated
source .venv/bin/activate

# Reinstall streamlit
pip install --upgrade streamlit

# Try again
streamlit run app.py
```

### Issue: Import errors

```bash
# Reinstall all dependencies
pip install -r requirements.txt
```

### Issue: LLM not responding

**For Ollama:**
```bash
# Check if Ollama is running
ollama list

# If not, start it
ollama serve

# Pull the model again
ollama pull gemma2:2b
```

**For OpenAI/Google:**
- Check your API key in .env
- Verify you have credits/quota
- Check internet connection

### Issue: API rate limits

- The system has built-in rate limiting
- Wait a few minutes between large operations
- Use caching (enabled by default)
- Consider upgrading to paid API tiers

---

## 📚 Learning Path

### Beginner (Day 1):
1. ✅ Load demo data
2. ✅ Explore dashboard
3. ✅ Run IOC analysis
4. ✅ Ask simple queries

### Intermediate (Day 2-3):
1. ✅ Add API keys
2. ✅ Ingest real feeds
3. ✅ Run fusion analysis
4. ✅ Explore campaigns

### Advanced (Week 1):
1. ✅ Set up Ollama
2. ✅ Generate threat reports
3. ✅ Create response playbooks
4. ✅ Generate YARA rules

---

## 🎓 For Your Project Demo

### Recommended Demo Flow:

**1. Introduction (1 min)**
- "This is an AI-powered CTI platform"
- "Uses real threat intelligence feeds"
- "Powered by LLMs for intelligent analysis"

**2. Data Ingestion (2 min)**
- Show real-time feed ingestion from OTX
- Demonstrate automatic IOC extraction
- Show enrichment with VirusTotal

**3. AI Analysis (3 min)**
- Generate threat actor profile
- Show attack prediction
- Create response playbook

**4. Unique Features (2 min)**
- YARA rule generation
- Threat narrative
- Hunting queries

**5. Dashboard & Visualization (2 min)**
- Show metrics
- Campaign detection
- Knowledge graph

**Total: 10 minutes, impressive demo!**

---

## 💡 Pro Tips

1. **Start with demo data** - No API keys needed
2. **Add OTX key first** - Best free feed
3. **Use Ollama** - Free, fast, private
4. **Enable caching** - Faster, fewer API calls
5. **Explore AI features** - Most impressive part

---

## 📞 Need Help?

Check these files:
- `README.md` - Complete documentation
- `FEATURES_SUMMARY.md` - All features explained
- `.env.example` - Configuration template

---

**You're all set! Start exploring your advanced CTI platform! 🚀**
