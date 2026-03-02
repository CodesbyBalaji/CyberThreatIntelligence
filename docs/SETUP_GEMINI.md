# 💎 Setting Up Google Gemini API

You've requested to switch from Ollama (local) to Google Gemini API. Here is how to do it.

## 1. Get Your Google API Key

1.  Go to **[Google AI Studio](https://aistudio.google.com/app/apikey)**.
2.  Click on **"Create API key"**.
3.  Select a project (or create a new one) and click **"Create API key in new project"**.
4.  Copy the generated API key (it starts with `AIza...`).

## 2. Update Your Configuration

You need to add your API key to the `.env` file in the project root.

1.  Open the `.env` file.
2.  Find the `GOOGLE_API_KEY` variable.
3.  Paste your key there.
4.  Change `LLM_PROVIDER` to `google`.

Your `.env` file should look like this:

```ini
# ... other keys ...

# LLM Configuration
LLM_PROVIDER=google
GOOGLE_API_KEY=AIzaSyYourKeyHere...

# ... other settings ...
```

## 3. Restart the Application

After updating the `.env` file, you must restart the application for changes to take effect.

1.  Stop the current server (Ctrl+C in the terminal).
2.  Run the application again:

```bash
OMP_NUM_THREADS=1 streamlit run app.py
```

## ✅ Verification

To verify it's working:
1.  Go to the **"🤖 AI Analyst"** page.
2.  Ask a question like "What is a zero-day exploit?".
3.  If you get a response, Gemini is working!

## 🔧 Troubleshooting

-   **Error: Google API key not configured**: Double-check your `.env` file and make sure you saved it.
-   **ImportError**: If you see an error about `google.generativeai`, run:
    ```bash
    pip install google-generativeai
    ```
