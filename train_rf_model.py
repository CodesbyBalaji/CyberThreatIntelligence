import os
import joblib
import pandas as pd
import numpy as np
import math
from collections import Counter
from sklearn.ensemble import RandomForestClassifier

def _extract_ioc_features(value: str) -> list:
    """Exact feature extraction logic used in ThreatExtractor."""
    import math
    from collections import Counter
    
    value_lower = str(value).lower()
    length = len(value_lower)
    features = []
    
    features.append(float(length))
    
    num_digits = sum(c.isdigit() for c in value_lower)
    num_alpha = sum(c.isalpha() for c in value_lower)
    num_special = length - num_digits - num_alpha
    
    features.append(num_digits / length if length > 0 else 0.0)
    features.append(num_alpha / length if length > 0 else 0.0)
    features.append(num_special / length if length > 0 else 0.0)
    
    features.append(float(value_lower.count('.')))
    features.append(float(value_lower.count('-')))
    
    counts = Counter(value_lower)
    entropy = -sum((count/length) * math.log2(count/length) for count in counts.values()) if length > 0 else 0.0
    features.append(entropy)
    
    features.append(1.0 if 'http://' in value_lower else 0.0)
    features.append(1.0 if 'https://' in value_lower else 0.0)
    
    return features

def train_on_real_datasets(csv_path: str = "data/malicious_urls.csv"):
    """
    Train Random Forest using a Kaggle dataset CSV.
    Expected Columns:
      - 'url' or 'text'
      - 'type' or 'label' or 'status'
    """
    if not os.path.exists(csv_path):
        print(f"[-] Dataset not found at {csv_path}.")
        print("Please download the Kaggle Phishing/Malicious URLs dataset and place it there.")
        print("Expected columns: 'url' (or 'text') and 'type' (or 'label', 'status').")
        return
        
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Identify URL column
    url_col = None
    for col in ['url', 'URL', 'text', 'domain']:
        if col in df.columns:
            url_col = col
            break
            
    # Identify Label column
    label_col = None
    for col in ['type', 'label', 'status', 'result']:
        if col in df.columns:
            label_col = col
            break
            
    if not url_col or not label_col:
        print("[-] Could not automatically determine the 'url' and 'label' columns.")
        print(f"Available columns: {df.columns.tolist()}")
        return
        
    print(f"[*] Using '{url_col}' as input and '{label_col}' as target.")
    
    # Drop NaNs
    df = df.dropna(subset=[url_col, label_col])
    
    # Extract features for all URLs
    print("[*] Extracting 9 static features. This might take a minute...")
    X = np.array([_extract_ioc_features(url) for url in df[url_col]])
    
    # Create target array (1 for malicious, 0 for benign)
    # Often Kaggle malicious URL datasets have 'type' = 'benign', 'phishing', 'malware', 'defacement'
    # Or 'label' = 0 (benign) / 1 (phishing)
    y = []
    for val in df[label_col]:
        val_str = str(val).strip().lower()
        if val_str in ['benign', '0', 'good', 'legitimate']:
            y.append(0)
        else:
            y.append(1) # 'phishing', 'malware', '1', 'bad', etc.
            
    y = np.array(y)
    
    print(f"[*] Done formatting! Dataset structure: {X.shape[0]} samples (Benign: {np.sum(y==0)}, Malicious: {np.sum(y==1)})")
    
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report
    
    print("[*] Splitting dataset into train and test sets (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[*] Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    print("[*] Evaluating Model on Test Set...")
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    print(f"\n--- Model Evaluation Metrics ---")
    print(f"Accuracy:  {accuracy:.4f} ({(accuracy * 100):.2f}%)")
    print(f"Precision: {precision:.4f} ({(precision * 100):.2f}%)")
    print(f"Recall:    {recall:.4f} ({(recall * 100):.2f}%)")
    print("--------------------------------\n")
    
    os.makedirs('models', exist_ok=True)
    rf_path = 'models/ioc_rf_model.pkl'
    joblib.dump(clf, rf_path)
    
    print(f"[+] Model successfully saved to {rf_path}")
    print("[+] The ThreatExtractor will now load and use this model.")

if __name__ == "__main__":
    # Point this to wherever you actually placed the Kaggle Dataset CSV
    train_on_real_datasets("malicious_phish.csv")
