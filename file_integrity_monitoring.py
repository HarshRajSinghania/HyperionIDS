import hashlib
import os
import json

# Define paths to monitor
paths_to_monitor = ["/etc", "/var/www/html"]

# Compute file hash
def compute_hash(filepath):
    hash_func = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Generate a baseline of hashes
def generate_baseline(paths):
    baseline = {}
    for path in paths:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    baseline[full_path] = compute_hash(full_path)
                except Exception as e:
                    print(f"Error hashing {full_path}: {e}")
    with open("baseline.json", "w") as f:
        json.dump(baseline, f, indent=4)

# Check integrity
def check_integrity():
    with open("baseline.json", "r") as f:
        baseline = json.load(f)
    for file, baseline_hash in baseline.items():
        try:
            current_hash = compute_hash(file)
            if current_hash != baseline_hash:
                print(f"[ALERT] File modified: {file}")
        except FileNotFoundError:
            print(f"[ALERT] File deleted: {file}")

# Run once to create baseline
# generate_baseline(paths_to_monitor)
# Run periodically to check integrity
check_integrity()
