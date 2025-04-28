import os
import json
import uuid
import shutil
from datetime import datetime

CASES_DIR = "cases"

class Case:
    def __init__(self, name, description="", investigator=""):
        self.id = str(uuid.uuid4())[:8]
        self.name = name
        self.description = description
        self.investigator = investigator
        self.created_at = datetime.now().isoformat()
        self.evidence = []
        self.notes = []
        
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "investigator": self.investigator,
            "created_at": self.created_at,
            "evidence": self.evidence,
            "notes": self.notes
        }
        
    @classmethod
    def from_dict(cls, data):
        case = cls(data["name"], data["description"], data["investigator"])
        case.id = data["id"]
        case.created_at = data["created_at"]
        case.evidence = data["evidence"]
        case.notes = data["notes"]
        return case

def create_case(name, description="", investigator=""):
    """Create a new investigation case"""
    # Ensure cases directory exists
    os.makedirs(CASES_DIR, exist_ok=True)
    
    case = Case(name, description, investigator)
    
    # Create case directory
    case_dir = os.path.join(CASES_DIR, case.id)
    os.makedirs(case_dir, exist_ok=True)
    os.makedirs(os.path.join(case_dir, "evidence"), exist_ok=True)
    os.makedirs(os.path.join(case_dir, "reports"), exist_ok=True)
    
    # Save case metadata
    _save_case(case)
    
    return case

def get_case(case_id):
    """Get a case by ID"""
    try:
        with open(os.path.join(CASES_DIR, case_id, "case.json"), "r") as f:
            return Case.from_dict(json.load(f))
    except Exception as e:
        print(f"[!] Error retrieving case {case_id}: {e}")
        return None

def list_cases():
    """List all cases"""
    if not os.path.exists(CASES_DIR):
        return []
        
    cases = []
    for case_id in os.listdir(CASES_DIR):
        case_file = os.path.join(CASES_DIR, case_id, "case.json")
        if os.path.exists(case_file):
            try:
                with open(case_file, "r") as f:
                    cases.append(json.load(f))
            except:
                continue
    return cases

def add_evidence(case_id, filepath, evidence_type, tags=None):
    """Add evidence to a case"""
    case = get_case(case_id)
    if not case:
        return False
        
    evidence_id = str(uuid.uuid4())[:8]
    evidence_dir = os.path.join(CASES_DIR, case_id, "evidence")
    
    # Copy evidence file to case directory
    _, filename = os.path.split(filepath)
    evidence_path = os.path.join(evidence_dir, f"{evidence_id}_{filename}")
    
    try:
        shutil.copy2(filepath, evidence_path)
    except Exception as e:
        print(f"[!] Error copying evidence: {e}")
        return False
    
    # Add evidence metadata
    evidence_meta = {
        "id": evidence_id,
        "filename": filename,
        "original_path": filepath,
        "type": evidence_type,
        "added_at": datetime.now().isoformat(),
        "tags": tags or [],
        "analysis_results": {}
    }
    
    case.evidence.append(evidence_meta)
    _save_case(case)
    
    return evidence_id

def _save_case(case):
    """Save case data to disk"""
    case_file = os.path.join(CASES_DIR, case.id, "case.json")
    with open(case_file, "w") as f:
        json.dump(case.to_dict(), f, indent=2)