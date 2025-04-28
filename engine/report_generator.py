import os
import yaml
from datetime import datetime

def generate_report(filepath, features, prediction, hashes, yara_matches):
    """Generate a basic YAML report with analysis results"""
    report_data = {
        "file": filepath,
        "features": features,
        "prediction": prediction,
        "hashes": hashes,
        "yara_matches": yara_matches
    }
    
    # Convert to YAML format
    report = yaml.dump(report_data, default_flow_style=False)
    
    # Save report
    os.makedirs("reports", exist_ok=True)
    report_file = os.path.join("reports", f"{os.path.basename(filepath)}_report.yaml")
    with open(report_file, "w") as f:
        f.write(report)
    
    # Return YAML string
    return report

def generate_enhanced_report(filepath, features, prediction, hashes, yara_matches):
    """Generate an enhanced report with additional insights"""
    # Basic report data
    report_data = {
        "file": filepath,
        "analysis_time": datetime.now().isoformat(),
        "features": features,
        "prediction": prediction,
        "hashes": hashes,
        "yara_matches": yara_matches,
    }
    
    # Add interpretation/insights
    insights = []
    
    # Check for suspicious indicators
    if yara_matches:
        insights.append(f"File matches {len(yara_matches)} YARA rules indicating suspicious content")
    
    if "entropy" in features:
        if features["entropy"] > 7.0:
            insights.append("High entropy suggests potential packing or encryption")
        elif features["entropy"] < 1.0:
            insights.append("Unusually low entropy may indicate padding or large null sections")
    
    if "malware" in str(prediction).lower():
        severity = "High"
    elif yara_matches:
        severity = "Medium"
    else:
        severity = "Low"
    
    report_data["severity"] = severity
    report_data["insights"] = insights
    
    # Convert to YAML
    report = yaml.dump(report_data, default_flow_style=False)
    
    # Return report string
    return report