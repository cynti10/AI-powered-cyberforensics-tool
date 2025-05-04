import re
import os
import json
import pandas as pd
from datetime import datetime

def extract_timestamps(content, source_type="file"):
    """Extract timestamps from various data sources"""
    # Common timestamp patterns
    patterns = [
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",  # ISO format
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",  # Common log format
        r"(\w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})",  # Syslog format
        r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"   # Apache log format
    ]
    
    all_timestamps = []
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        all_timestamps.extend(matches)
    
    return all_timestamps

def create_event_timeline(sources):
    """Create a timeline of events from multiple sources"""
    all_events = []
    
    for source in sources:
        source_path = source["path"]
        source_type = source["type"]
        source_description = source.get("description", "Unknown")
        
        try:
            with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract timestamps based on source type
            if source_type == "log":
                log_type = source.get("log_type", "generic")
                events = extract_log_events(content, log_type, source_description)
            elif source_type == "memory":
                events = extract_memory_events(content, source_description)
            else:
                # Generic timestamp extraction
                timestamps = extract_timestamps(content)
                events = [{"timestamp": ts, 
                           "source": source_description, 
                           "event_type": "timestamp", 
                           "details": "Timestamp found in file"} for ts in timestamps]
            
            all_events.extend(events)
        except Exception as e:
            print(f"[!] Error processing {source_path}: {e}")
    
    # Create DataFrame and ensure all required columns exist
    if all_events:
        timeline_df = pd.DataFrame(all_events)
        
        # Make sure all required columns exist
        if 'event_type' not in timeline_df.columns:
            timeline_df['event_type'] = 'unknown'
            
        # Convert timestamp to datetime if it's not already
        if 'timestamp' in timeline_df.columns and not pd.api.types.is_datetime64_dtype(timeline_df['timestamp']):
            timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
        
        return timeline_df
    else:
        # Return empty DataFrame with expected columns
        return pd.DataFrame(columns=['timestamp', 'source', 'event_type', 'details'])

def extract_log_events(content, log_type, source_description):
    """Extract events from log files"""
    events = []
    
    # Extract timestamps based on log type
    if log_type == "windows":
        # Extract Windows event log timestamps
        event_matches = re.finditer(r'Time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\n.*?Event ID: (\d+)\n.*?Type: ([^\n]+)', 
                                   content, re.DOTALL)
        for match in event_matches:
            timestamp, event_id, event_type = match.groups()
            event_text = match.group(0)
            events.append({
                "timestamp": timestamp,
                "source": source_description,
                "event_type": f"Windows-{event_id}",
                "details": event_text[:200] + "..." if len(event_text) > 200 else event_text
            })
    
    elif log_type == "apache":
        # Extract Apache log timestamps
        event_matches = re.finditer(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "([A-Z]+) ([^ ]+)', 
                                   content)
        for match in event_matches:
            timestamp, method, url = match.groups()
            timestamp_obj = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
            timestamp_str = timestamp_obj.strftime('%Y-%m-%d %H:%M:%S')
            events.append({
                "timestamp": timestamp_str,
                "source": source_description,
                "event_type": f"HTTP-{method}",
                "details": f"{method} {url}"
            })
    
    else:
        # Generic log processing - look for timestamps
        timestamps = extract_timestamps(content)
        for ts in timestamps:
            events.append({
                "timestamp": ts,
                "source": source_description,
                "event_type": "Log",
                "details": "Timestamp detected in log file"
            })
    
    return events

def extract_memory_events(content, source_description):
    """Extract events from memory dumps"""
    events = []
    
    # Look for process information with timestamps
    proc_matches = re.finditer(r'PROCESS_NAME: (\S+) PID: (\d+)(?:.*?CREATION_TIME: (\S+ \S+))?', 
                              content, re.DOTALL)
    
    for match in proc_matches:
        proc_name, pid = match.groups()[0:2]
        timestamp = match.groups()[2] if match.groups()[2] else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        events.append({
            "timestamp": timestamp,
            "source": source_description,
            "event_type": "Process",
            "details": f"Process {proc_name} (PID: {pid})"
        })
    
    # Look for network connections
    net_matches = re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) [-><]+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', 
                             content)
    
    for match in net_matches:
        src_ip, src_port, dst_ip, dst_port = match.groups()
        events.append({
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Use current time if no timestamp
            "source": source_description,
            "event_type": "Network",
            "details": f"Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        })
    
    return events

def detect_timeline_anomalies(timeline_df):
    """Detect anomalies in the event timeline"""
    anomalies = []
    
    if len(timeline_df) == 0:
        return anomalies
    
    # Check for timestamp gaps
    timeline_df["timestamp_parsed"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
    timeline_df = timeline_df.dropna(subset=["timestamp_parsed"]).sort_values("timestamp_parsed")
    
    if len(timeline_df) <= 1:
        return anomalies
        
    # Calculate time differences
    timeline_df["time_diff"] = timeline_df["timestamp_parsed"].diff()
    
    # Find gaps (time differences larger than 95th percentile)
    threshold = timeline_df["time_diff"].quantile(0.95)
    gaps = timeline_df[timeline_df["time_diff"] > threshold]
    
    for _, row in gaps.iterrows():
        anomalies.append({
            "type": "time_gap",
            "timestamp": row["timestamp"],
            "gap_duration": str(row["time_diff"]),
            "context": row["context"]
        })
    
    return anomalies

def export_timeline(timeline_df, output_path, format="csv"):
    """Export timeline to various formats"""
    if format == "csv":
        timeline_df.to_csv(output_path, index=False)
    elif format == "json":
        timeline_df.to_json(output_path, orient="records", indent=2)
    else:
        return False
    return True