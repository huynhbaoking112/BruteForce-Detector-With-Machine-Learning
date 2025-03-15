import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import ipaddress

def preprocess_data(df):
    """
    Preprocess the raw access data for model training.
    
    Args:
        df: DataFrame containing the raw access data
        
    Returns:
        X: Feature matrix
        y: Target labels
    """
    # Feature engineering
    features = []
    
    # Group by IP to calculate IP-based features
    ip_groups = df.groupby('source_ip')
    
    # Convert IPs to numerical form for distance calculation
    df['ip_numeric'] = df['source_ip'].apply(
        lambda ip: int(ipaddress.IPv4Address(ip))
    )
    
    # Process each record
    for idx, row in df.iterrows():
        ip = row['source_ip']
        ip_data = ip_groups.get_group(ip)
        
        # IP history up to this point (avoid data leakage)
        timestamp = row['timestamp']
        history = ip_data[ip_data['timestamp'] <= timestamp]
        
        # Features based on historical behavior
        recent_history = history[history['timestamp'] >= (timestamp - pd.Timedelta(minutes=10))]
        
        # Calculate features
        features_dict = {
            # Request frequency features
            'attempts_10min': len(recent_history),
            'total_attempts': len(history),
            
            # Success/failure patterns
            'failure_rate': 1 - history['success'].mean() if len(history) > 0 else 0,
            'recent_failure_rate': 1 - recent_history['success'].mean() if len(recent_history) > 0 else 0,
            
            # Timing features
            'hour_of_day': int(row['time_of_day'].split(':')[0]),
            'is_business_hours': 1 if 8 <= int(row['time_of_day'].split(':')[0]) <= 18 else 0,
            
            # Key-related features
            'key_type_rsa': 1 if row['key_type'] == 'RSA' else 0,
            'key_type_ecc': 1 if row['key_type'] == 'ECC' else 0,
            'key_type_dsa': 1 if row['key_type'] == 'DSA' else 0,
            'key_size': row['key_size'],
            
            # User agent features
            'is_script_ua': 1 if any(ua in row['user_agent'].lower() 
                                   for ua in ['python', 'curl', 'wget', 'go-http']) else 0,
            
            # Current attempt succeeded
            'current_success': 1 if row['success'] else 0
        }
        
        # If we have enough history, calculate time patterns
        if len(history) > 1:
            # Calculate mean and std of time between attempts
            timestamps = history['timestamp'].sort_values()
            time_diffs = [(timestamps.iloc[i] - timestamps.iloc[i-1]).total_seconds() 
                          for i in range(1, len(timestamps))]
            
            features_dict['mean_time_between'] = np.mean(time_diffs)
            features_dict['std_time_between'] = np.std(time_diffs) if len(time_diffs) > 1 else 0
            features_dict['min_time_between'] = min(time_diffs) if time_diffs else 0
        else:
            features_dict['mean_time_between'] = 0
            features_dict['std_time_between'] = 0
            features_dict['min_time_between'] = 0
        
        features.append(features_dict)
    
    # Convert to DataFrame
    features_df = pd.DataFrame(features)
    
    # Handle NaN values
    features_df = features_df.fillna(0)
    
    # Extract features and labels
    X = features_df.values
    y = df['is_attack'].values
    
    return X, y

def split_sequence_data(df, window_size=5):
    """
    Create sequential data for recurrent models.
    
    Args:
        df: DataFrame with the access data
        window_size: Number of access attempts to include in each sequence
        
    Returns:
        X_seq: Sequence features
        y_seq: Sequence labels
    """
    # Group by IP
    ip_groups = df.groupby('source_ip')
    
    X_seq = []
    y_seq = []
    
    # Process each IP
    for ip, group in ip_groups:
        # Sort by timestamp
        group = group.sort_values('timestamp')
        
        # Preprocess the group data
        X_group, y_group = preprocess_data(group)
        
        # Create sequences
        for i in range(len(X_group) - window_size + 1):
            X_seq.append(X_group[i:i+window_size])
            y_seq.append(y_group[i+window_size-1])
    
    return np.array(X_seq), np.array(y_seq) 