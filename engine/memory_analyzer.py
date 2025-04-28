import re
import os

def extract_processes(memory_dump):
    """Extract running processes from memory dump"""
    processes = []
    
    # Look for process information in the dump
    proc_matches = re.findall(r"PROCESS_NAME:\s+(\S+)\s+PID:\s+(\d+)", memory_dump)
    
    for proc_name, pid in proc_matches:
        processes.append({
            "name": proc_name,
            "pid": int(pid)
        })
    
    return processes

def extract_network_connections(memory_dump):
    """Extract network connections from memory dump"""
    connections = []
    
    # Look for network information
    net_matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+(?:->|<-)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", memory_dump)
    
    for src_ip, src_port, dst_ip, dst_port in net_matches:
        connections.append({
            "source_ip": src_ip,
            "source_port": int(src_port),
            "destination_ip": dst_ip,
            "destination_port": int(dst_port)
        })
    
    return connections

def detect_suspicious_processes(processes):
    """Identify potentially suspicious processes"""
    suspicious = []
    known_suspicious = [
        "mimikatz", "psexec", "powershell", "cmd", "netcat", "nc", 
        "rar", "winrar", "7z", "svchost", "regsvr32"
    ]
    
    for proc in processes:
        proc_name = proc["name"].lower()
        
        # Check against known suspicious processes
        if any(susp in proc_name for susp in known_suspicious):
            suspicious.append({
                "process": proc["name"],
                "pid": proc["pid"],
                "reason": "Known suspicious process name"
            })
    
    return suspicious

def analyze_memory_dump(filepath):
    """Analyze a memory dump file"""
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
        
        # Extract information
        processes = extract_processes(content)
        connections = extract_network_connections(content)
        suspicious_procs = detect_suspicious_processes(processes)
        
        return {
            "processes": processes,
            "network_connections": connections,
            "suspicious_processes": suspicious_procs,
            "process_count": len(processes),
            "connection_count": len(connections)
        }
    except Exception as e:
        print(f"[!] Error analyzing memory dump: {e}")
        return {
            "error": str(e)
        }