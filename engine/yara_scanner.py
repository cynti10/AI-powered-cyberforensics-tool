import yara
import os

RULES_DIR = "yara_rules"

def run_yara_scan(filepath):
    matches = []
    try:
        rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yar") or f.endswith(".yara")]
        for rule_file in rule_files:
            rules = yara.compile(filepath=os.path.join(RULES_DIR, rule_file))
            match = rules.match(filepath)
            for m in match:
                matches.append(m.rule)
    except Exception as e:
        print(f"[!] YARA scanning error: {e}")
    return matches