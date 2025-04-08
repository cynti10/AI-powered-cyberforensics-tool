import hashlib
import magic

def compute_hashes(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "magic": magic.from_buffer(data)
        }
    except Exception as e:
        print(f"[!] Error computing hashes: {e}")
        return {}

