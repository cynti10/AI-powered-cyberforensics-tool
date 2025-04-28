import hashlib
import magic

def compute_hashes(filepath):
    """Compute various hashes for a file"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Calculate common hashes
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        
        # Get file type using magic
        file_type = magic.from_file(filepath)
        
        return {
            "magic": file_type,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        }
    except Exception as e:
        print(f"[!] Error computing hashes: {e}")
        return {
            "magic": "unknown",
            "md5": "error",
            "sha256": "error"
        }

