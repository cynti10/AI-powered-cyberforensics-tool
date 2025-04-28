import os
import math
import re
import csv


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy


def extract_strings(data: bytes, min_length: int = 4):
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    return re.findall(pattern, data)


def extract_features(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        entropy = calculate_entropy(data)
        file_size = os.path.getsize(filepath)
        strings = extract_strings(data)

        features = {
            "entropy": round(entropy, 2),
            "file_size": file_size,
            "num_strings": len(strings)
        }
        return features

    except Exception as e:
        print(f"[!] Error extracting features: {e}")
        return {}


def extract_advanced_features(filepath):
    """Extract advanced features including suspicious API and term detection"""
    features = extract_features(filepath)
    
    try:
        # Add string-based features
        with open(filepath, 'rb') as f:
            data = f.read()
        
        strings = extract_strings(data)
        suspicious_apis = ['virtualalloc', 'writeprocessmemory', 'createprocess', 'loadlibrary']
        suspicious_terms = ['rootkit', 'payload', 'exfiltration', 'c2:', 'backdoor']
        
        # Count suspicious strings
        api_matches = sum(1 for s in strings if any(api.lower() in str(s).lower() for api in suspicious_apis))
        term_matches = sum(1 for s in strings if any(term.lower() in str(s).lower() for term in suspicious_terms))
        
        # Add to features
        features['suspicious_api_count'] = api_matches
        features['suspicious_term_count'] = term_matches
        
        return features
    except Exception as e:
        print(f"[!] Error extracting advanced features: {e}")
        return features