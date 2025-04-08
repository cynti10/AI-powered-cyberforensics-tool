import os
import argparse
from engine.feature_extractor import extract_features
from engine.model_predictor import predict_malware
from engine.report_generator import generate_report
from engine.yara_scanner import run_yara_scan
from utils.hash_utils import compute_hashes

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Cyberforensics Tool")
    parser.add_argument("filepath", help="Path to the suspicious file")
    args = parser.parse_args()

    # Check if file exists
    if not os.path.isfile(args.filepath):
        print(f"[!] Error: File '{args.filepath}' not found.")
        return

    # Create necessary directories
    os.makedirs("reports", exist_ok=True)
    os.makedirs("yara_rules", exist_ok=True)
    os.makedirs("models", exist_ok=True)

    print("[+] Extracting features...")
    features = extract_features(args.filepath)

    print("[+] Running ML model prediction...")
    prediction = predict_malware(features)

    print("[+] Computing file hashes...")
    hashes = compute_hashes(args.filepath)

    print("[+] Scanning with YARA rules...")
    yara_results = run_yara_scan(args.filepath)

    print("[+] Generating report...")
    report = generate_report(args.filepath, features, prediction, hashes, yara_results)
    print("--- Report ---")
    print(report)

if __name__ == "__main__":
    main()