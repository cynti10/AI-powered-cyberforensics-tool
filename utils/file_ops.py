def read_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"[!] Could not read file: {e}")
        return b""
