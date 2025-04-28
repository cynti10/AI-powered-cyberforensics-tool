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
    """Create a timeline of events from multiple sources
    
    Args:
        sources: List of dicts with {path, type, description}
    
    Returns:
        DataFrame with timeline events
    """
    events = []
    
    for source in sources:
        try:
            if source["type"] == "file":
                with open(source["path"], "r") as f:
                    content = f.read()
            elif source["type"] == "log":
                with open(source["path"], "r") as f:
                    content = f.read()
            else:
                continue
                
            timestamps = extract_timestamps(content, source["type"])
            
            for ts in timestamps:
                # Extract context (20 chars before and after timestamp)
                pos = content.find(ts)
                start = max(0, pos - 20)
                end = min(len(content), pos + len(ts) + 20)
                context = content[start:end]
                
                events.append({
                    "timestamp": ts,
                    "source": source["path"],
                    "source_type": source["type"],
                    "description": source.get("description", ""),
                    "context": context
                })
                
        except Exception as e:
            print(f"[!] Error processing {source['path']}: {e}")
    
    # Convert to DataFrame and sort by timestamp
    if events:
        df = pd.DataFrame(events)
        df.sort_values("timestamp", inplace=True)
        return df
    else:
        return pd.DataFrame(columns=["timestamp", "source", "source_type", "description", "context"])

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