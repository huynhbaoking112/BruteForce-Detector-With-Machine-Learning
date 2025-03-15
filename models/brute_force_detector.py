import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import time
from datetime import datetime, timedelta

class BruteForceDetector:
    def __init__(self, threshold=0.8, lockout_period=300, max_attempts=5):
        """
        Initialize the password brute force detector model.
        
        Args:
            threshold: Probability threshold for classifying an attempt as malicious
            lockout_period: Seconds to lock out an IP after detection (default: 5 min)
            max_attempts: Maximum failed attempts before additional scrutiny
        """
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.threshold = threshold
        self.lockout_period = lockout_period
        self.max_attempts = max_attempts
        
        # Track IPs and their access attempts
        self.ip_tracking = {}
        # Track user accounts and their access attempts
        self.user_tracking = {}
        # Track locked out IPs
        self.locked_ips = {}
        # Track locked out users
        self.locked_users = {}
        
    def extract_features(self, access_data):
        """
        Extract features from password access data.
        
        Args:
            access_data: Dictionary containing access information
            
        Returns:
            Feature vector
        """
        # Current time for reference
        current_time = time.time()
        
        # Get IP history or create if new
        ip = access_data['source_ip']
        username = access_data['username']
        
        if ip not in self.ip_tracking:
            self.ip_tracking[ip] = {
                'attempts': [],
                'failures': 0,
                'successes': 0,
                'first_seen': current_time,
                'usernames_tried': set()
            }
        
        if username not in self.user_tracking:
            self.user_tracking[username] = {
                'attempts': [],
                'failures': 0,
                'successes': 0,
                'first_seen': current_time,
                'ips_used': set()
            }
        
        ip_history = self.ip_tracking[ip]
        user_history = self.user_tracking[username]
        
        # Track usernames tried from this IP
        ip_history['usernames_tried'].add(username)
        # Track IPs used for this username
        user_history['ips_used'].add(ip)
        
        # Update histories
        ip_history['attempts'].append(current_time)
        user_history['attempts'].append(current_time)
        
        # Keep only the most recent 100 attempts to limit memory
        if len(ip_history['attempts']) > 100:
            ip_history['attempts'] = ip_history['attempts'][-100:]
        if len(user_history['attempts']) > 100:
            user_history['attempts'] = user_history['attempts'][-100:]
        
        # Update success/failure counts
        if access_data['success']:
            ip_history['successes'] += 1
            user_history['successes'] += 1
        else:
            ip_history['failures'] += 1
            user_history['failures'] += 1
        
        # Calculate features
        ip_attempts = ip_history['attempts']
        user_attempts = user_history['attempts']
        
        # Calculate attempt frequency (attempts per minute)
        one_minute_ago = current_time - 60
        ip_recent_attempts = sum(1 for t in ip_attempts if t >= one_minute_ago)
        user_recent_attempts = sum(1 for t in user_attempts if t >= one_minute_ago)
        
        # Calculate attempt frequency (attempts per 10 minutes)
        ten_minutes_ago = current_time - 600
        ip_attempts_10min = sum(1 for t in ip_attempts if t >= ten_minutes_ago)
        user_attempts_10min = sum(1 for t in user_attempts if t >= ten_minutes_ago)
        
        # Time since first seen (in hours)
        ip_time_since_first = (current_time - ip_history['first_seen']) / 3600
        user_time_since_first = (current_time - user_history['first_seen']) / 3600
        
        # Calculate mean time between attempts (if multiple attempts exist)
        if len(ip_attempts) > 1:
            ip_time_diffs = [ip_attempts[i] - ip_attempts[i-1] for i in range(1, len(ip_attempts))]
            ip_mean_time_between = np.mean(ip_time_diffs)
            ip_std_time_between = np.std(ip_time_diffs) if len(ip_time_diffs) > 1 else 0
            ip_min_time_between = min(ip_time_diffs) if ip_time_diffs else 0
        else:
            ip_mean_time_between = 0
            ip_std_time_between = 0
            ip_min_time_between = 0
        
        if len(user_attempts) > 1:
            user_time_diffs = [user_attempts[i] - user_attempts[i-1] for i in range(1, len(user_attempts))]
            user_mean_time_between = np.mean(user_time_diffs)
            user_std_time_between = np.std(user_time_diffs) if len(user_time_diffs) > 1 else 0
            user_min_time_between = min(user_time_diffs) if user_time_diffs else 0
        else:
            user_mean_time_between = 0
            user_std_time_between = 0
            user_min_time_between = 0
        
        # Success to failure ratio
        ip_total_attempts = ip_history['successes'] + ip_history['failures']
        ip_success_ratio = ip_history['successes'] / ip_total_attempts if ip_total_attempts > 0 else 0
        ip_failure_rate = 1 - ip_success_ratio
        
        user_total_attempts = user_history['successes'] + user_history['failures']
        user_success_ratio = user_history['successes'] / user_total_attempts if user_total_attempts > 0 else 0
        user_failure_rate = 1 - user_success_ratio
        
        # Calculate recent failure rates (last 10 minutes)
        # For IP
        recent_ip_successes = sum(1 for t, s in 
                                 zip(ip_attempts, [access_data['success']]) 
                                 if t >= ten_minutes_ago and s)
        recent_ip_total = sum(1 for t in ip_attempts if t >= ten_minutes_ago)
        ip_recent_failure_rate = 1 - (recent_ip_successes / recent_ip_total if recent_ip_total > 0 else 0)
        
        # For user
        recent_user_successes = sum(1 for t, s in 
                                   zip(user_attempts, [access_data['success']]) 
                                   if t >= ten_minutes_ago and s)
        recent_user_total = sum(1 for t in user_attempts if t >= ten_minutes_ago)
        user_recent_failure_rate = 1 - (recent_user_successes / recent_user_total if recent_user_total > 0 else 0)
        
        # Number of distinct usernames tried from this IP
        unique_usernames_count = len(ip_history['usernames_tried'])
        
        # Number of distinct IPs used for this username
        unique_ips_count = len(user_history['ips_used'])
        
        # Password complexity (if available)
        password_complexity = 0
        if 'password_complexity' in access_data:
            password_complexity = access_data['password_complexity']
        
        # Hour of day
        hour_of_day = int(access_data['time_of_day'].split(':')[0])
        
        # Is business hours
        is_business_hours = 1 if 8 <= hour_of_day <= 18 else 0
        
        # Check for script-like user agent
        is_script_ua = 0
        if 'user_agent' in access_data:
            ua = access_data['user_agent'].lower()
            is_script_ua = 1 if any(agent in ua for agent in ['python', 'curl', 'wget', 'go-http']) else 0
        
        # Features vector (MUST match features from preprocess_data in utils/preprocessing.py)
        features = [
            ip_attempts_10min,                # IP-based attempts in last 10min
            user_attempts_10min,              # User-based attempts in last 10min
            len(ip_history['attempts']),      # Total IP attempts
            len(user_history['attempts']),    # Total user attempts
            ip_failure_rate,                  # IP failure rate
            user_failure_rate,                # User failure rate
            ip_recent_failure_rate,           # IP recent failure rate
            user_recent_failure_rate,         # User recent failure rate
            hour_of_day,                      # Hour of day
            is_business_hours,                # Is business hours
            unique_usernames_count,           # Number of usernames tried from this IP
            unique_ips_count,                 # Number of IPs used for this username
            password_complexity,              # Password complexity
            is_script_ua,                     # Is script user agent
            1 if access_data['success'] else 0,  # Current success
            ip_mean_time_between,             # IP mean time between attempts
            ip_std_time_between,              # IP std time between attempts
            ip_min_time_between,              # IP min time between attempts
            user_mean_time_between,           # User mean time between attempts
            user_std_time_between,            # User std time between attempts
            user_min_time_between,            # User min time between attempts
        ]
        
        return np.array(features).reshape(1, -1)
    
    def train(self, X, y):
        """
        Train the model on the provided dataset.
        
        Args:
            X: Features matrix
            y: Target labels (0 for normal, 1 for attack)
        """
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        
    def predict(self, access_data):
        """
        Predict if the given password access attempt is a brute force attack.
        
        Args:
            access_data: Dictionary with access information
            
        Returns:
            Dictionary with prediction results and action
        """
        ip = access_data['source_ip']
        username = access_data['username']
        
        # Check if IP is locked out
        if ip in self.locked_ips:
            lockout_time = self.locked_ips[ip]
            if time.time() < lockout_time:
                return {
                    'is_attack': True,
                    'probability': 1.0,
                    'action': 'block',
                    'reason': 'IP is currently locked out'
                }
            else:
                # Lockout period expired
                del self.locked_ips[ip]
        
        # Check if username is locked out
        if username in self.locked_users:
            lockout_time = self.locked_users[username]
            if time.time() < lockout_time:
                return {
                    'is_attack': True,
                    'probability': 1.0,
                    'action': 'block',
                    'reason': 'User account is currently locked out'
                }
            else:
                # Lockout period expired
                del self.locked_users[username]
        
        # Extract features
        features = self.extract_features(access_data)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Get prediction
        prob = self.model.predict_proba(features_scaled)[0, 1]
        is_attack = prob >= self.threshold
        
        # Determine action
        action = 'allow'
        reason = 'Normal activity detected'
        
        if is_attack:
            action = 'block'
            reason = 'Detected as potential brute force attack'
            # Lock out the IP and username
            self.locked_ips[ip] = time.time() + self.lockout_period
            self.locked_users[username] = time.time() + self.lockout_period
        elif (ip in self.ip_tracking and self.ip_tracking[ip]['failures'] >= self.max_attempts) or \
             (username in self.user_tracking and self.user_tracking[username]['failures'] >= self.max_attempts):
            action = 'challenge'
            reason = 'Too many failed attempts'
        
        return {
            'is_attack': is_attack,
            'probability': prob,
            'action': action,
            'reason': reason
        }
    
    def save_model(self, filepath):
        """Save the trained model to disk"""
        joblib.dump({'model': self.model, 'scaler': self.scaler}, filepath)
    
    def load_model(self, filepath):
        """Load a trained model from disk"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
    
    def online_update(self, access_data, is_attack):
        """
        Update the model with new labeled data.
        
        Args:
            access_data: Access information
            is_attack: Boolean indicating if this was a real attack
        """
        features = self.extract_features(access_data)
        X_scaled = self.scaler.transform(features)
        # Update with a single sample
        self.model.fit(X_scaled, [1 if is_attack else 0]) 