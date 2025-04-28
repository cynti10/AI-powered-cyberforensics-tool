import re
import json
from datetime import datetime

def parse_log_events(log_content, log_type="generic"):
    """Parse different types of log files and extract events"""
    if log_type == "generic":
        return _parse_generic_log(log_content)
    elif log_type == "windows":
        return _parse_windows_log(log_content)
    elif log_type == "apache":
        return _parse_apache_log(log_content)
    elif log_type == "ssh":
        return _parse_ssh_log(log_content)
    else:
        return {"error": f"Unsupported log type: {log_type}"}

def _parse_generic_log(log_content):
    timestamps = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", log_content)
    commands = re.findall(r"(GET|POST|PUT|DELETE|cmd|powershell)", log_content, re.IGNORECASE)
    ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log_content)
    
    return {
        "num_timestamps": len(timestamps),
        "commands_found": list(set(commands)),
        "ips_found": list(set(ips)),
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None
    }

def _parse_windows_log(log_content):
    """Parse Windows Event Logs"""
    logon_events = re.findall(r"(?:logon|login|user session|authentication)", log_content, re.IGNORECASE)
    failed_logins = re.findall(r"(?:failed|failure|unsuccessful).*(?:logon|login|authentication)", log_content, re.IGNORECASE)
    admin_actions = re.findall(r"(?:administrator|admin|elevated|sudo)", log_content, re.IGNORECASE)
    
    return {
        "total_logon_events": len(logon_events),
        "failed_logins": len(failed_logins),
        "admin_actions": len(admin_actions)
    }

def _parse_apache_log(log_content):
    """Parse Apache/web server logs"""
    http_methods = re.findall(r" (GET|POST|PUT|DELETE|HEAD) ", log_content)
    status_codes = re.findall(r" (\d{3}) ", log_content)
    user_agents = re.findall(r"\"(Mozilla[^\"]+)\"", log_content)
    
    # Count status codes by category
    status_summary = {
        "2xx": len([s for s in status_codes if s.startswith("2")]),
        "3xx": len([s for s in status_codes if s.startswith("3")]),
        "4xx": len([s for s in status_codes if s.startswith("4")]),
        "5xx": len([s for s in status_codes if s.startswith("5")])
    }
    
    return {
        "http_methods": {m: http_methods.count(m) for m in set(http_methods)},
        "status_summary": status_summary,
        "unique_user_agents": len(set(user_agents))
    }

def _parse_ssh_log(log_content):
    """Parse SSH logs"""
    failed_attempts = re.findall(r"(?:Failed password|authentication failure)", log_content, re.IGNORECASE)
    accepted_logins = re.findall(r"Accepted password", log_content, re.IGNORECASE)
    
    return {
        "failed_attempts": len(failed_attempts),
        "successful_logins": len(accepted_logins),
        "failure_ratio": len(failed_attempts) / (len(accepted_logins) + 1)  # Add 1 to avoid division by zero
    }

def detect_log_anomalies(log_events, threshold=0.8):
    """Detect potential anomalies in log events"""
    anomalies = []
    
    # Simple anomaly rules - can be expanded
    if "failed_attempts" in log_events and "successful_logins" in log_events:
        if log_events["failure_ratio"] > threshold:
            anomalies.append("High rate of SSH login failures")
    
    if "status_summary" in log_events:
        if log_events["status_summary"].get("4xx", 0) > 100:
            anomalies.append("High number of HTTP 4xx errors")
        if log_events["status_summary"].get("5xx", 0) > 20:
            anomalies.append("High number of HTTP 5xx errors")
            
    if "failed_logins" in log_events and log_events["failed_logins"] > 5:
        anomalies.append("Multiple failed Windows logon attempts")
        
    return anomalies