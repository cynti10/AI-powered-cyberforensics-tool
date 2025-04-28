import os
import argparse
import yaml
from engine.feature_extractor import extract_features, extract_advanced_features
from engine.model_predictor import predict_malware
from engine.yara_scanner import run_yara_scan
from utils.hash_utils import compute_hashes

# Import the correct report generator function
from engine.report_generator import generate_report

# Import other modules if available
try:
    from engine.log_parser import parse_log_events, detect_log_anomalies
    from engine.memory_analyzer import analyze_memory_dump
    LOG_SUPPORT = True
except ImportError:
    LOG_SUPPORT = False
    print("[!] Log analysis modules not available - some features disabled")

# Check for case management
try:
    from engine.case_manager import create_case, add_evidence, get_case
    CASE_SUPPORT = True
except ImportError:
    CASE_SUPPORT = False
    print("[!] Case management modules not available - some features disabled")

def analyze_file(filepath, case_id=None):
    """Analyze a single file"""
    print(f"[+] Analyzing file: {filepath}")
    
    # Extract features
    print("[+] Extracting features...")
    features = extract_features(filepath)
    adv_features = extract_advanced_features(filepath)

    # Run ML prediction
    print("[+] Running ML model prediction...")
    prediction = predict_malware(adv_features)

    # Compute hashes
    print("[+] Computing file hashes...")
    hashes = compute_hashes(filepath)

    # Run YARA scan
    print("[+] Scanning with YARA rules...")
    yara_results = run_yara_scan(filepath)
    
    # Generate report
    print("[+] Generating report...")
    report = generate_report(filepath, features, prediction, hashes, yara_results)
    
    # Add to case if provided and case support available
    if case_id and CASE_SUPPORT:
        file_type = "malware" if "Malware" in prediction else "benign"
        evidence_id = add_evidence(case_id, filepath, file_type)
        if evidence_id:
            print(f"[+] Added to case {case_id} as evidence {evidence_id}")
    
    print("--- Report ---")
    for key, value in features.items():
        print(f"  {key}: {value}")
    print(f"File: {filepath}")
    print(f"Hashes:")
    for key, value in hashes.items():
        print(f"  {key}: {value}")
    print(f"Prediction: {prediction}")
    print(f"YARA Matches: {yara_results}")
    
    return {
        "features": features,
        "prediction": prediction,
        "hashes": hashes,
        "yara_results": yara_results
    }

def analyze_log(filepath, log_type="generic", case_id=None):
    """Analyze a log file"""
    if not LOG_SUPPORT:
        print("[!] Log analysis not available")
        return {"error": "Log analysis not supported"}
        
    print(f"[+] Analyzing log file: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        print(f"[+] Parsing {log_type} log events...")
        log_events = parse_log_events(content, log_type)
        
        print("[+] Detecting anomalies...")
        anomalies = detect_log_anomalies(log_events)
        
        if anomalies:
            print("[!] Anomalies detected:")
            for anomaly in anomalies:
                print(f"    - {anomaly}")
        
        # Add to case if provided
        if case_id and CASE_SUPPORT:
            evidence_id = add_evidence(case_id, filepath, "log")
            if evidence_id:
                print(f"[+] Added to case {case_id} as evidence {evidence_id}")
        
        # Generate and save report
        report_data = {
            "file": filepath,
            "log_type": log_type,
            "events": log_events,
            "anomalies": anomalies
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_file = os.path.join("reports", f"{os.path.basename(filepath)}_log_report.yaml")
        with open(report_file, "w") as f:
            yaml.dump(report_data, f, default_flow_style=False)
            
        print(f"[+] Report saved to {report_file}")
        
        return {
            "events": log_events,
            "anomalies": anomalies
        }
        
    except Exception as e:
        print(f"[!] Error analyzing log: {e}")
        return {"error": str(e)}

def analyze_memory(filepath, case_id=None):
    """Analyze a memory dump file"""
    if 'analyze_memory_dump' not in globals():
        print("[!] Memory analysis not available")
        return {"error": "Memory analysis not supported"}
        
    print(f"[+] Analyzing memory dump: {filepath}")
    
    try:
        result = analyze_memory_dump(filepath)
        
        # Add to case if provided
        if case_id and CASE_SUPPORT:
            evidence_id = add_evidence(case_id, filepath, "memory")
            if evidence_id:
                print(f"[+] Added to case {case_id} as evidence {evidence_id}")
        
        # Generate and save report
        report_data = {
            "file": filepath,
            "analysis_type": "memory",
            "results": result
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_file = os.path.join("reports", f"{os.path.basename(filepath)}_memory_report.yaml")
        with open(report_file, "w") as f:
            yaml.dump(report_data, f, default_flow_style=False)
            
        print(f"[+] Report saved to {report_file}")
        
        return result
        
    except Exception as e:
        print(f"[!] Error analyzing memory dump: {e}")
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Cyberforensics Tool")
    parser.add_argument("filepath", help="Path to the file to analyze")
    parser.add_argument("--type", choices=["file", "log", "memory"], default="file", 
                       help="Type of analysis to perform")
    
    if LOG_SUPPORT:
        parser.add_argument("--log-type", choices=["generic", "windows", "apache", "ssh"], default="generic", 
                           help="Type of log file")
    
    if CASE_SUPPORT:                      
        parser.add_argument("--case", help="Case ID to add the evidence to")
        parser.add_argument("--new-case", help="Create a new case with the given name")
    
    args = parser.parse_args()

    # Check if file exists
    if not os.path.isfile(args.filepath):
        print(f"[!] Error: File '{args.filepath}' not found.")
        return

    # Create necessary directories
    os.makedirs("reports", exist_ok=True)
    os.makedirs("yara_rules", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    
    # Handle case creation/selection
    case_id = None
    if CASE_SUPPORT:
        if hasattr(args, 'new_case') and args.new_case:
            case = create_case(args.new_case)
            case_id = case.id
            print(f"[+] Created new case: {case.name} (ID: {case_id})")
        elif hasattr(args, 'case') and args.case:
            case_id = args.case
    
    # Perform analysis based on file type
    if args.type == "file":
        analyze_file(args.filepath, case_id)
    elif args.type == "log" and LOG_SUPPORT:
        analyze_log(args.filepath, args.log_type, case_id)
    elif args.type == "memory":
        analyze_memory(args.filepath, case_id)
    else:
        print(f"[!] Unsupported analysis type: {args.type}")

if __name__ == "__main__":
    main()