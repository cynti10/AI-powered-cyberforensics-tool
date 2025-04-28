import joblib
import os
import numpy as np

# Path to the trained model
MODEL_PATH = os.path.join("models", "model.joblib")

def predict_malware(features):
    """Predict if a file is malicious based on its features"""
    try:
        # Load the model
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
        else:
            print("[!] Model file not found. Using fallback detection.")
            return _fallback_detection(features)
        
        # Check if we have advanced features
        if 'suspicious_api_count' in features or 'suspicious_term_count' in features:
            return _predict_with_advanced_features(features)
        
        # Extract the features needed for the model in the correct order
        feature_values = [
            features.get("entropy", 0),
            features.get("file_size", 0),
            features.get("num_strings", 0)
        ]
        
        # Make prediction
        prediction = model.predict([feature_values])[0]
        confidence = round(max(model.predict_proba([feature_values])[0]) * 100, 2)
        
        if prediction == 1:
            return f"Malware (confidence: {confidence}%)"
        else:
            return f"Benign (confidence: {confidence}%)"
            
    except Exception as e:
        print(f"[!] Error in prediction: {e}")
        return _fallback_detection(features)

def _predict_with_advanced_features(features):
    """Use advanced features to make a more informed prediction"""
    # Get suspicious counts
    api_count = features.get('suspicious_api_count', 0)
    term_count = features.get('suspicious_term_count', 0)
    
    # Simple rule-based decision for now (can be replaced with a better trained model)
    if api_count >= 2 and term_count >= 2:
        return "Malware (confidence: 95.00%) - Contains multiple suspicious APIs and terms"
    elif api_count >= 2:
        return "Suspicious (confidence: 75.00%) - Contains multiple suspicious APIs"
    elif term_count >= 2:
        return "Suspicious (confidence: 70.00%) - Contains multiple suspicious terms"
    
    # If no advanced signals, fall back to the original model
    feature_values = [
        features.get("entropy", 0),
        features.get("file_size", 0),
        features.get("num_strings", 0)
    ]
    
    model = joblib.load(MODEL_PATH)
    prediction = model.predict([feature_values])[0]
    confidence = round(max(model.predict_proba([feature_values])[0]) * 100, 2)
    
    if prediction == 1:
        return f"Malware (confidence: {confidence}%)"
    else:
        return f"Benign (confidence: {confidence}%)"

def _fallback_detection(features):
    """Fallback detection when model is unavailable"""
    # Simple heuristics
    if features.get("entropy", 0) > 6.8:
        return "Suspicious (high entropy)"
    
    # Check advanced features if available
    if features.get("suspicious_api_count", 0) >= 2:
        return "Suspicious (suspicious APIs detected)"
    if features.get("suspicious_term_count", 0) >= 2:
        return "Suspicious (suspicious terms detected)"
        
    return "Unknown (insufficient data)"