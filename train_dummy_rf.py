import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Dummy data: 9 features
# [length, digit_ratio, alpha_ratio, special_ratio, num_dots, num_hyphens, entropy, has_http, has_https]
# Class 0: Benign, Class 1: Malicious

X = np.random.rand(100, 9)
y = np.random.randint(2, size=100)

clf = RandomForestClassifier(n_estimators=10, random_state=42)
clf.fit(X, y)

os.makedirs('models', exist_ok=True)
joblib.dump(clf, 'models/ioc_classifier.pkl')
print("Dummy model created at models/ioc_classifier.pkl")
