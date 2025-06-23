import os
import sys
from engine.feature_extractor import extract_features, extract_advanced_features
from engine.model_predictor import predict_malware
from engine.yara_scanner import run_yara_scan
from utils.hash_utils import compute_hashes

# Try importing new modules
try:
    from engine.log_parser import parse_log_events, detect_log_anomalies
    LOG_SUPPORT = True
except ImportError:
    LOG_SUPPORT = False
    print("[!] Log analysis modules not available")

try:
    from engine.timeline_analyzer import create_event_timeline, detect_timeline_anomalies
    TIMELINE_SUPPORT = True
except ImportError:
    TIMELINE_SUPPORT = False
    print("[!] Timeline analysis modules not available")
    
try:
    from engine.memory_analyzer import analyze_memory_dump
    MEMORY_SUPPORT = True
except ImportError:
    MEMORY_SUPPORT = False
    print("[!] Memory analysis modules not available")

try:
    from engine.report_generator import generate_report
    REPORT_SUPPORT = True
except ImportError:
    REPORT_SUPPORT = False
    print("[!] Report generator not available")

def test_file_analysis(filepath):
    print(f"\n[+] Testing file analysis on: {filepath}")
    
    # Extract features
    print("[+] Extracting basic features...")
    features = extract_features(filepath)
    print(f"    Basic features: {features}")
    
    # Extract advanced features if available
    try:
        print("[+] Extracting advanced features...")
        adv_features = extract_advanced_features(filepath)
        print(f"    Advanced features: {adv_features}")
    except:
        print("    Advanced feature extraction not available")
        adv_features = features
    
    # Predict malware
    print("[+] Running ML prediction...")
    prediction = predict_malware(adv_features)
    print(f"    Prediction: {prediction}")
    
    # Compute hashes
    hashes = compute_hashes(filepath)
    print(f"    File hashes: MD5={hashes.get('md5', 'N/A')}")
    
    # Run YARA scan
    print("[+] Scanning with YARA rules...")
    yara_matches = run_yara_scan(filepath)
    print(f"    YARA matches: {yara_matches}")
    
    # Generate report if available
    if REPORT_SUPPORT:
        print("[+] Generating report...")
        report = generate_report(filepath, adv_features, prediction, hashes, yara_matches)
        print("    Report generated successfully")
    
    return {
        "features": features,
        "advanced_features": adv_features,
        "prediction": prediction,
        "yara_matches": yara_matches
    }

def test_log_analysis(filepath, log_type="generic"):
    if not LOG_SUPPORT:
        print("\n[!] Log analysis not available")
        return {"error": "Log analysis not supported"}
        
    print(f"\n[+] Testing log analysis on: {filepath} (type: {log_type})")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Parse logs
        print("[+] Parsing log events...")
        events = parse_log_events(content, log_type)
        print(f"    Parsed events: {events}")
        
        # Detect anomalies
        print("[+] Detecting log anomalies...")
        anomalies = detect_log_anomalies(events)
        
        if anomalies:
            print("    [!] Anomalies detected:")
            for anomaly in anomalies:
                print(f"        - {anomaly}")
        else:
            print("    No anomalies detected")
            
        return {
            "events": events,
            "anomalies": anomalies
        }
    except Exception as e:
        print(f"    [!] Error in log analysis: {e}")
        return {"error": str(e)}

def test_memory_analysis(filepath):
    if not MEMORY_SUPPORT:
        print("\n[!] Memory analysis not available")
        return {"error": "Memory analysis not supported"}
        
    print(f"\n[+] Testing memory analysis on: {filepath}")
    
    # Analyze memory dump
    result = analyze_memory_dump(filepath)
    
    if "error" in result:
        print(f"    [!] Error: {result['error']}")
        return result
    
    print(f"    [+] Found {result['process_count']} processes")
    print(f"    [+] Found {result['connection_count']} network connections")
    
    if result['suspicious_processes']:
        print("    [!] Suspicious processes detected:")
        for proc in result['suspicious_processes']:
            print(f"        - {proc['process']} (PID: {proc['pid']}): {proc['reason']}")
    
    return result

def test_timeline_analysis():
    if not TIMELINE_SUPPORT:
        print("\n[!] Timeline analysis not available")
        return {"error": "Timeline analysis not supported"}
        
    print("\n[+] Testing timeline analysis")
    
    sources = [
        {"path": "data/samples/windows_security_event.log", "type": "log", "description": "Security Event Log"},
        {"path": "data/samples/suspicious_network.pcap.txt", "type": "log", "description": "Network Traffic"}
    ]
    
    # Create timeline
    timeline_df = create_event_timeline(sources)
    print(f"    [+] Timeline created with {len(timeline_df)} events")
    
    # Detect anomalies
    anomalies = detect_timeline_anomalies(timeline_df)
    print(f"    [+] Detected {len(anomalies)} timeline anomalies")
    
    if anomalies:
        print("    [!] Timeline anomalies detected:")
        for anomaly in anomalies:
            print(f"        - {anomaly['type']} at {anomaly['timestamp']}")
    
    return {
        "timeline_events": len(timeline_df),
        "anomalies": anomalies
    }

def main():
    print("=" * 60)
    print("AI-POWERED CYBERFORENSICS TOOL - FEATURE TEST")
    print("=" * 60)
    
    # Create samples directory if it doesn't exist
    os.makedirs("data/samples", exist_ok=True)
    
    # Test file analysis
    malware_path = "data/samples/suspicious_malware.exe"
    if os.path.exists(malware_path):
        test_file_analysis(malware_path)
    else:
        print(f"[!] File not found: {malware_path}")
    
    # Test log analysis
    if LOG_SUPPORT:
        log_path = "data/samples/windows_security_event.log"
        if os.path.exists(log_path):
            test_log_analysis(log_path, "windows")
        else:
            print(f"[!] File not found: {log_path}")
    
    # Test memory analysis
    if MEMORY_SUPPORT:
        memory_path = "data/samples/memory_dump_sample.bin"
        if os.path.exists(memory_path):
            test_memory_analysis(memory_path)
        else:
            print(f"[!] File not found: {memory_path}")
    
    # Test timeline analysis
    if TIMELINE_SUPPORT:
        test_timeline_analysis()
    
    print("\n" + "=" * 60)
    print("FEATURE TEST COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    main()