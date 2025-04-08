import yaml
import os

def generate_report(filepath, features, prediction, hashes, yara_matches):
    report = {
        "File": os.path.basename(filepath),
        "Prediction": prediction,
        "Features": features,
        "Hashes": hashes,
        "YARA Matches": yara_matches
    }

    output_path = os.path.join("reports", f"{os.path.basename(filepath)}_report.yaml")
    try:
        with open(output_path, 'w') as f:
            yaml.dump(report, f)
    except Exception as e:
        print(f"[!] Failed to write report: {e}")

    return yaml.dump(report)