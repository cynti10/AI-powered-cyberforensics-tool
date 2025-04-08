# filepath: c:\Users\ADMIN\OneDrive\Documents\AI-Cyberforensics\AI-Cyberforensics-Tool\train_model.py
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import numpy as np

# Ensure models directory exists
os.makedirs("models", exist_ok=True)

# Load the dataset
data_path = os.path.join("data", "training_data.csv")
data = pd.read_csv(data_path)
X = data[["entropy", "file_size", "num_strings"]]  # Features
y = data["label"]  # Labels (0 for benign, 1 for malware)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate with cross-validation
cv_scores = cross_val_score(model, X, y, cv=5)
print(f"Cross-validation scores: {cv_scores}")
print(f"Average CV score: {cv_scores.mean():.2f}")

# Evaluate on test set
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy on test set: {accuracy * 100:.2f}%")

# Print detailed metrics
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Feature importance
feature_importance = pd.DataFrame({
    'Feature': X.columns,
    'Importance': model.feature_importances_
}).sort_values('Importance', ascending=False)

print("\nFeature Importance:")
print(feature_importance)

# Save the trained model
joblib.dump(model, "models/model.joblib")
print("[+] Model saved to 'models/model.joblib'")