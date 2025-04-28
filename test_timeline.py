from engine.timeline_analyzer import create_event_timeline, detect_timeline_anomalies, export_timeline
import os

def run_timeline_test():
    print("[+] Running timeline analysis test...")
    
    sources = [
        {"path": "data/samples/windows_security_event.log", "type": "log", "description": "Security Event Log"},
        {"path": "data/samples/suspicious_network.pcap.txt", "type": "log", "description": "Network Traffic"}
    ]
    
    # Create timeline
    timeline_df = create_event_timeline(sources)
    print(f"[+] Timeline created with {len(timeline_df)} events")
    
    # Detect anomalies
    anomalies = detect_timeline_anomalies(timeline_df)
    print(f"[+] Detected {len(anomalies)} timeline anomalies")
    
    # Export timeline
    os.makedirs("reports", exist_ok=True)
    output_path = os.path.join("reports", "event_timeline.csv")
    export_timeline(timeline_df, output_path)
    print(f"[+] Timeline exported to {output_path}")
    
    # Display sample of timeline
    if not timeline_df.empty:
        print("\nSample timeline events:")
        print(timeline_df.head())
    
    # Display anomalies
    if anomalies:
        print("\nDetected anomalies:")
        for a in anomalies:
            print(f"- {a['type']} at {a['timestamp']}")

if __name__ == "__main__":
    run_timeline_test()