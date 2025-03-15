import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import ipaddress

def preprocess_data(df):
    """
    Preprocess the raw password access data for model training.
    
    Args:
        df: DataFrame containing the raw access data
        
    Returns:
        X: Feature matrix
        y: Target labels
    """
    # Feature engineering
    features = []
    
    # Group by IP and username to calculate features
    ip_groups = df.groupby('source_ip')
    user_groups = df.groupby('username')
    
    # Convert IPs to numerical form for distance calculation
    df['ip_numeric'] = df['source_ip'].apply(
        lambda ip: int(ipaddress.IPv4Address(ip))
    )
    
    # Process each record
    for idx, row in df.iterrows():
        ip = row['source_ip']
        username = row['username']
        
        # Get data for this IP and username
        ip_data = ip_groups.get_group(ip)
        user_data = user_groups.get_group(username)
        
        # History up to this point (avoid data leakage)
        timestamp = row['timestamp']
        ip_history = ip_data[ip_data['timestamp'] <= timestamp]
        user_history = user_data[user_data['timestamp'] <= timestamp]
        
        # Features based on historical behavior (last 10 minutes)
        recent_ip_history = ip_history[ip_history['timestamp'] >= (timestamp - pd.Timedelta(minutes=10))]
        recent_user_history = user_history[user_history['timestamp'] >= (timestamp - pd.Timedelta(minutes=10))]
        
        # Calculate features
        features_dict = {
            # Request frequency features
            'ip_attempts_10min': len(recent_ip_history),
            'user_attempts_10min': len(recent_user_history),
            'ip_total_attempts': len(ip_history),
            'user_total_attempts': len(user_history),
            
            # Success/failure patterns
            'ip_failure_rate': 1 - ip_history['success'].mean() if len(ip_history) > 0 else 0,
            'user_failure_rate': 1 - user_history['success'].mean() if len(user_history) > 0 else 0,
            'ip_recent_failure_rate': 1 - recent_ip_history['success'].mean() if len(recent_ip_history) > 0 else 0,
            'user_recent_failure_rate': 1 - recent_user_history['success'].mean() if len(recent_user_history) > 0 else 0,
            
            # Timing features
            'hour_of_day': int(row['time_of_day'].split(':')[0]),
            'is_business_hours': 1 if 8 <= int(row['time_of_day'].split(':')[0]) <= 18 else 0,
            
            # Unique usernames tried from this IP
            'unique_usernames': len(ip_history['username'].unique()),
            
            # Unique IPs used for this username
            'unique_ips': len(user_history['source_ip'].unique()),
            
            # Password complexity (if available)
            'password_complexity': row['password_complexity'] if 'password_complexity' in row else 0,
            
            # User agent features
            'is_script_ua': 1 if 'user_agent' in row and any(ua in row['user_agent'].lower() 
                                   for ua in ['python', 'curl', 'wget', 'go-http']) else 0,
            
            # Current attempt succeeded
            'current_success': 1 if row['success'] else 0
        }
        
        # If we have enough history, calculate time patterns
        if len(ip_history) > 1:
            # Calculate mean and std of time between attempts for IP
            ip_timestamps = ip_history['timestamp'].sort_values()
            ip_time_diffs = [(ip_timestamps.iloc[i] - ip_timestamps.iloc[i-1]).total_seconds() 
                          for i in range(1, len(ip_timestamps))]
            
            features_dict['ip_mean_time_between'] = np.mean(ip_time_diffs)
            features_dict['ip_std_time_between'] = np.std(ip_time_diffs) if len(ip_time_diffs) > 1 else 0
            features_dict['ip_min_time_between'] = min(ip_time_diffs) if ip_time_diffs else 0
        else:
            features_dict['ip_mean_time_between'] = 0
            features_dict['ip_std_time_between'] = 0
            features_dict['ip_min_time_between'] = 0
            
        if len(user_history) > 1:
            # Calculate mean and std of time between attempts for username
            user_timestamps = user_history['timestamp'].sort_values()
            user_time_diffs = [(user_timestamps.iloc[i] - user_timestamps.iloc[i-1]).total_seconds() 
                          for i in range(1, len(user_timestamps))]
            
            features_dict['user_mean_time_between'] = np.mean(user_time_diffs)
            features_dict['user_std_time_between'] = np.std(user_time_diffs) if len(user_time_diffs) > 1 else 0
            features_dict['user_min_time_between'] = min(user_time_diffs) if user_time_diffs else 0
        else:
            features_dict['user_mean_time_between'] = 0
            features_dict['user_std_time_between'] = 0
            features_dict['user_min_time_between'] = 0
        
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
    # Group by IP and username
    ip_groups = df.groupby('source_ip')
    user_groups = df.groupby('username')
    
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
    
    # Process each username
    for username, group in user_groups:
        # Sort by timestamp
        group = group.sort_values('timestamp')
        
        # Preprocess the group data
        X_group, y_group = preprocess_data(group)
        
        # Create sequences
        for i in range(len(X_group) - window_size + 1):
            X_seq.append(X_group[i:i+window_size])
            y_seq.append(y_group[i+window_size-1])
    
    return np.array(X_seq), np.array(y_seq) 