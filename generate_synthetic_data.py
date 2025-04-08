import os
import numpy as np
import pandas as pd
from sklearn.utils import shuffle

# Define typical characteristics of benign vs malicious files
benign_features = {
    'entropy': (2.5, 4.5),       # Lower entropy for benign files
    'file_size': (10000, 5000000),
    'num_strings': (100, 5000),
}

malware_features = {
    'entropy': (5.5, 8.0),      # Malware often has higher entropy due to packing/encryption
    'file_size': (100000, 10000000),
    'num_strings': (20, 200),
}

def generate_synthetic_dataset(n_benign=500, n_malware=500):
    # Generate benign samples
    benign_data = []
    for _ in range(n_benign):
        sample = {
            'entropy': round(np.random.uniform(benign_features['entropy'][0], benign_features['entropy'][1]), 2),
            'file_size': int(np.random.randint(benign_features['file_size'][0], benign_features['file_size'][1])),
            'num_strings': int(np.random.randint(benign_features['num_strings'][0], benign_features['num_strings'][1])),
            'label': 0  # Benign
        }
        benign_data.append(sample)
    
    # Generate malware samples
    malware_data = []
    for _ in range(n_malware):
        sample = {
            'entropy': round(np.random.uniform(malware_features['entropy'][0], malware_features['entropy'][1]), 2),
            'file_size': int(np.random.randint(malware_features['file_size'][0], malware_features['file_size'][1])),
            'num_strings': int(np.random.randint(malware_features['num_strings'][0], malware_features['num_strings'][1])),
            'label': 1  # Malware
        }
        malware_data.append(sample)
    
    # Combine and shuffle
    all_data = benign_data + malware_data
    df = pd.DataFrame(all_data)
    return shuffle(df)

if __name__ == "__main__":
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    # Generate and save dataset
    synthetic_data = generate_synthetic_dataset(n_benign=5000, n_malware=5000)
    synthetic_data.to_csv('data/training_data.csv', index=False)
    print(f"[+] Generated synthetic dataset with {len(synthetic_data)} samples")
    print(f"[+] Data saved to data/training_data.csv")