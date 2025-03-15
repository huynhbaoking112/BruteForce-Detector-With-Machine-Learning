import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import ipaddress

def generate_datasets(num_normal=1000, num_attacks=200):
    """
    Generate training and testing datasets for brute force detection.
    
    Args:
        num_normal: Number of normal access attempts
        num_attacks: Number of attack access attempts
        
    Returns:
        training_df: DataFrame for training
        testing_df: DataFrame for testing
    """
    # Generate legitimate IPs
    legitimate_ips = [
        str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
        for _ in range(50)
    ]
    
    # Generate attacker IPs
    attacker_ips = [
        str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
        for _ in range(20)
    ]
    
    # Key types and sizes
    key_types = ['RSA', 'ECC', 'DSA']
    key_sizes = {
        'RSA': [2048, 3072, 4096],
        'ECC': [256, 384, 521],
        'DSA': [1024, 2048, 3072]
    }
    
    # Starting time
    start_time = datetime.now() - timedelta(days=7)
    
    # Generate normal access patterns
    normal_data = []
    for i in range(num_normal):
        # Random user from legitimate pool
        ip = random.choice(legitimate_ips)
        
        # Random time within a week, biased towards business hours
        hour = random.choices(
            range(24),
            weights=[2 if 8 <= h <= 18 else 1 for h in range(24)]
        )[0]
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        days_offset = random.randint(0, 6)
        timestamp = start_time + timedelta(
            days=days_offset, 
            hours=hour, 
            minutes=minute,
            seconds=second
        )
        
        # Random key information
        key_type = random.choice(key_types)
        key_size = random.choice(key_sizes[key_type])
        
        # Success is more likely for legitimate users
        success = random.random() < 0.95
        
        # User agent (legitimate users typically have consistent, modern agents)
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        user_agent = random.choice(user_agents)
        
        # Add to dataset
        normal_data.append({
            'timestamp': timestamp,
            'source_ip': ip,
            'key_type': key_type,
            'key_size': key_size,
            'success': success,
            'time_of_day': f"{hour:02d}:{minute:02d}",
            'user_agent': user_agent,
            'is_attack': 0  # Not an attack
        })
    
    # Generate attack patterns
    attack_data = []
    for i in range(num_attacks):
        # Choose an attacker IP
        ip = random.choice(attacker_ips)
        
        # For each attack, we'll generate a burst of attempts
        burst_size = random.randint(5, 20)
        
        # Starting time for this attack burst
        hour = random.randint(0, 23)  # Attacks can happen anytime
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        days_offset = random.randint(0, 6)
        burst_start = start_time + timedelta(
            days=days_offset, 
            hours=hour, 
            minutes=minute,
            seconds=second
        )
        
        # Target key information (attacks often target specific key types)
        key_type = random.choice(key_types)
        key_size = random.choice(key_sizes[key_type])
        
        # Malicious user agent strings (often simplified or spoofed)
        malicious_agents = [
            "python-requests/2.25.1",
            "curl/7.68.0",
            "Mozilla/5.0",
            "Go-http-client/1.1"
        ]
        user_agent = random.choice(malicious_agents)
        
        # Generate burst of attempts
        for j in range(burst_size):
            # Time increments slightly between attempts (very fast attempts)
            attempt_time = burst_start + timedelta(seconds=j * random.uniform(0.5, 3))
            
            # Almost always fails
            success = random.random() < 0.01
            
            attack_data.append({
                'timestamp': attempt_time,
                'source_ip': ip,
                'key_type': key_type,
                'key_size': key_size,
                'success': success,
                'time_of_day': f"{attempt_time.hour:02d}:{attempt_time.minute:02d}",
                'user_agent': user_agent,
                'is_attack': 1  # This is an attack
            })
    
    # Combine data and shuffle
    all_data = normal_data + attack_data
    random.shuffle(all_data)
    
    # Convert to DataFrame
    df = pd.DataFrame(all_data)
    
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    # Split into training (70%) and testing (30%)
    split_idx = int(0.7 * len(df))
    training_df = df[:split_idx]
    testing_df = df[split_idx:]
    
    # Save datasets
    training_df.to_csv('data/training_dataset.csv', index=False)
    testing_df.to_csv('data/testing_dataset.csv', index=False)
    
    return training_df, testing_df

if __name__ == "__main__":
    # Create datasets with 1000 normal entries and 200 attack sequences
    train_df, test_df = generate_datasets()
    print(f"Training dataset created with {len(train_df)} entries")
    print(f"Testing dataset created with {len(test_df)} entries")
    
    # Display class distribution
    print("\nTraining class distribution:")
    print(train_df['is_attack'].value_counts())
    
    print("\nTesting class distribution:")
    print(test_df['is_attack'].value_counts()) 