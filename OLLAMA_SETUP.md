# Ollama Setup for Threat Fusion Engine

## ✅ Setup Complete!

Your Threat Fusion Engine is now configured to use **Ollama** with the **llama3.2:3b** model for unlimited local threat intelligence analysis.

## 🎯 Current Configuration

- **LLM Provider**: Ollama (local)
- **Model**: llama3.2:3b
- **Server**: http://localhost:11434
- **Rate Limits**: None! (unlimited queries)

## 🚀 Benefits

✅ **No Rate Limits** - Query as much as you want  
✅ **No API Costs** - Completely free  
✅ **Privacy** - All data stays on your machine  
✅ **Fast Response** - Local processing  
✅ **Offline Capable** - Works without internet  

## 📊 Model Comparison

### llama3.2:3b (Current - Recommended)
- **Size**: 2GB
- **Speed**: Fast
- **Quality**: Excellent for threat intelligence
- **Best for**: Balanced performance and quality

### Alternative Models (if you want to try)

```bash
# Larger, more capable (if you have RAM)
ollama pull qwen2.5:7b        # 4.7GB - Very good reasoning
ollama pull gemma2:9b         # 5.4GB - Excellent technical analysis
ollama pull llama3.1:8b       # 4.7GB - Very capable

# Smaller, faster (if you need speed)
ollama pull gemma2:2b         # 1.6GB - Fast but less capable
ollama pull phi3:mini         # 2.3GB - Good for simple queries
```

## 🔧 How to Switch Models

1. **Pull a new model**:
   ```bash
   ollama pull <model-name>
   ```

2. **Update `.env` file**:
   ```bash
   LLM_MODEL=<model-name>
   ```

3. **Restart Streamlit**:
   ```bash
   streamlit run app.py
   ```

## 🛠️ Troubleshooting

### If Ollama server is not running:
```bash
ollama serve
```

### Check available models:
```bash
ollama list
```

### Test a model:
```bash
ollama run llama3.2:3b "What is ransomware?"
```

### Remove unused models (to save space):
```bash
ollama rm <model-name>
```

## 📱 Access Your App

- **Local**: http://localhost:8501
- **Network**: http://192.168.1.34:8501

## 🎓 Usage Tips

1. **First query might be slow** - Model needs to load into memory
2. **Subsequent queries are fast** - Model stays in memory
3. **Complex queries work better** - llama3.2:3b handles technical content well
4. **No quota worries** - Query as much as you need!

## 🔄 Switch Back to Google (if needed)

Edit `.env`:
```bash
LLM_PROVIDER=google
GOOGLE_API_KEY=your-key-here
```

---

**Enjoy unlimited threat intelligence analysis!** 🛡️
