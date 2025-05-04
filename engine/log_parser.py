import re
import base64
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_log_events(content, log_type):
    """Parse log files based on their type"""
    if log_type == "windows":
        return parse_windows_event_log(content)
    elif log_type == "apache":
        return parse_apache_log(content)
    elif log_type == "ssh":
        return parse_ssh_log(content)
    else:
        return parse_generic_log(content)

def parse_windows_event_log(content):
    """Parse Windows event logs"""
    if content.strip().startswith('<'):
        return parse_windows_xml_event_log(content)
    
    events = {
        "total_events": 0,
        "logon_events": 0,
        "failed_logins": 0,
        "admin_actions": 0,
        "suspicious_commands": 0
    }
    
    events["total_events"] = len(re.findall(r"EventID", content))
    events["logon_events"] = len(re.findall(r"LogonType", content))
    events["failed_logins"] = len(re.findall(r"Failure Audit", content))
    events["admin_actions"] = len(re.findall(r"Administrator", content))
    
    return events

def parse_windows_xml_event_log(content):
    """Parse Windows event logs in XML format"""
    events = {
        "total_events": 0,
        "logon_events": 0,
        "failed_logins": 0,
        "admin_actions": 0,
        "suspicious_commands": 0
    }
    
    try:
        event_parts = re.findall(r'<Event.*?</Event>', content, re.DOTALL)
        
        if not event_parts:
            return {"total_events": 0, "error": "No valid Event elements found"}
        
        events["total_events"] = len(event_parts)
        
        for event_xml in event_parts:
            try:
                event = ET.fromstring(event_xml)
                ns = ''
                match = re.search(r'xmlns="(.*?)"', event_xml)
                if match:
                    ns = '{' + match.group(1) + '}'
                event_id_elem = event.find(f'.//{ns}EventID') or event.find('.//EventID')
                
                if event_id_elem is not None:
                    event_id = event_id_elem.text
                    if event_id == "4624":
                        events["logon_events"] += 1
                        
                        for data_elem in event.findall(f'.//{ns}Data') or event.findall('.//Data'):
                            if data_elem.get('Name') == 'TargetUserName' and data_elem.text == 'Administrator':
                                events["admin_actions"] += 1
                    
                    if event_id == "4688":
                        process_name = None
                        command_line = None
                        
                        for data_elem in event.findall(f'.//{ns}Data') or event.findall('.//Data'):
                            if data_elem.get('Name') == 'NewProcessName':
                                process_name = data_elem.text
                            elif data_elem.get('Name') == 'CommandLine':
                                command_line = data_elem.text
                        
                        if process_name and "powershell" in process_name.lower():
                            if command_line and "-enc" in command_line.lower():
                                events["suspicious_commands"] += 1
                                
                                # Try to decode Base64
                                try:
                                    # Split by -enc and take the part after it
                                    parts = command_line.lower().split("-enc")
                                    if len(parts) > 1:
                                        encoded_part = parts[1].strip()
                                        words = encoded_part.split()
                                        base64_str = max(words, key=len) if words else encoded_part
                                        if len(base64_str) >= 8: 
                                            decoded = base64.b64decode(base64_str).decode('utf-16-le', errors='ignore')
                                            
                                            suspicious_terms = ['netcat', 'nc.exe', '192.168', '4444', '-e', 'cmd.exe', 'powershell']
                                            for term in suspicious_terms:
                                                if term in decoded.lower():
                                                    events["suspicious_commands"] += 5 
                                except Exception as e:
                                    print(f"Error decoding Base64: {e}")
            
            except Exception as e:
                print(f"Error parsing individual event: {e}")
                continue
        
        return events
    except Exception as e:
        print(f"Error in parse_windows_xml_event_log: {e}")
        return {
            "total_events": 0,
            "error": str(e)
        }

def parse_apache_log(content):
    """Parse Apache logs"""
    events = {
        "total_requests": 0,
        "get_requests": 0,
        "post_requests": 0,
        "error_responses": 0,
        "suspicious_urls": 0
    }
    
    events["total_requests"] = len(content.split('\n'))
    events["get_requests"] = len(re.findall(r' GET ', content))
    events["post_requests"] = len(re.findall(r' POST ', content))
    events["error_responses"] = len(re.findall(r' 4\d\d ', content)) + len(re.findall(r' 5\d\d ', content))
    
    suspicious_patterns = [
        r'(\.php\?id=)', r'(/admin/)', r'(/config)', r'(/wp-admin)',
        r'(select.*from)', r'(union.*select)', r'(exec\()', r'(eval\()',
        r'(../../)', r'(/etc/passwd)', r'(/etc/shadow)', r'(/bin/sh)'
    ]
    
    for pattern in suspicious_patterns:
        events["suspicious_urls"] += len(re.findall(pattern, content, re.IGNORECASE))
    
    return events

def parse_ssh_log(content):
    """Parse SSH logs"""
    events = {
        "total_events": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "root_login_attempts": 0
    }
    
    events["total_events"] = len(content.split('\n'))
    events["failed_logins"] = len(re.findall(r'Failed password', content))
    events["successful_logins"] = len(re.findall(r'Accepted password', content))
    events["root_login_attempts"] = len(re.findall(r'for root from', content))
    
    return events

def parse_generic_log(content):
    """Parse generic log format"""
    
    lines = content.split('\n')
    
    events = {
        "total_lines": len(lines),
        "error_lines": 0,
        "warning_lines": 0,
        "info_lines": 0
    }
    for line in lines:
        line_lower = line.lower()
        if "error" in line_lower:
            events["error_lines"] += 1
        elif "warning" in line_lower or "warn" in line_lower:
            events["warning_lines"] += 1
        elif "info" in line_lower:
            events["info_lines"] += 1
    
    return events

def detect_log_anomalies(events):
    """Detect anomalies in parsed log events"""
    anomalies = []
    
    if events.get("suspicious_commands", 0) > 0:
        anomalies.append("CRITICAL: Suspicious PowerShell encoded commands detected - possible reverse shell activity")
    
    if events.get("failed_logins", 0) > 3:
        anomalies.append(f"Multiple failed login attempts ({events['failed_logins']}) - possible brute force attack")
    
    if events.get("admin_actions", 0) >= 1:
        anomalies.append(f"Administrative logon detected ({events['admin_actions']} events) - sensitive activity")
    
    return anomalies