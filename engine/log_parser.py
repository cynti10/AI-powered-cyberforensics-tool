import re

def parse_log_events(log_content):
    timestamps = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", log_content)
    commands = re.findall(r"(GET|POST|PUT|DELETE|cmd|powershell)", log_content, re.IGNORECASE)
    return {
        "num_timestamps": len(timestamps),
        "commands_found": list(set(commands))
    }