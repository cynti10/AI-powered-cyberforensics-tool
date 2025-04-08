import joblib
import os

MODEL_PATH = os.path.join("models", "model.joblib")

def predict_malware(features):
    try:
        model = joblib.load(MODEL_PATH)
        input_features = [[
            features.get("entropy", 0),
            features.get("file_size", 0),
            features.get("num_strings", 0)
        ]]
        
        prediction = model.predict(input_features)[0]
        confidence = model.predict_proba(input_features)[0].max()
        
        result = "Malware" if prediction == 1 else "Benign"
        return f"{result} (confidence: {confidence:.2%})"
        
    except Exception as e:
        print(f"[!] Error during prediction: {e}")
        return "Unknown"