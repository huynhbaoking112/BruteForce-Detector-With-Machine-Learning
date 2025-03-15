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
        Initialize the brute force detector model.
        
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
        # Track locked out IPs
        self.locked_ips = {}
        
    def extract_features(self, access_data):
        """
        Extract features from access data.
        
        Args:
            access_data: Dictionary containing access information
            
        Returns:
            Feature vector
        """
        # Current time for reference
        current_time = time.time()
        
        # Get IP history or create if new
        ip = access_data['source_ip']
        if ip not in self.ip_tracking:
            self.ip_tracking[ip] = {
                'attempts': [],
                'failures': 0,
                'successes': 0,
                'first_seen': current_time
            }
        
        ip_history = self.ip_tracking[ip]
        ip_history['attempts'].append(current_time)
        
        # Keep only the most recent 100 attempts to limit memory
        if len(ip_history['attempts']) > 100:
            ip_history['attempts'] = ip_history['attempts'][-100:]
        
        # Update success/failure counts
        if access_data['success']:
            ip_history['successes'] += 1
        else:
            ip_history['failures'] += 1
        
        # Calculate features
        attempts = ip_history['attempts']
        
        # Calculate attempt frequency (attempts per minute)
        one_minute_ago = current_time - 60
        recent_attempts = sum(1 for t in attempts if t >= one_minute_ago)
        
        # Calculate attempt frequency (attempts per 10 minutes)
        ten_minutes_ago = current_time - 600
        attempts_10min = sum(1 for t in attempts if t >= ten_minutes_ago)
        
        # Time since first seen (in hours)
        time_since_first = (current_time - ip_history['first_seen']) / 3600
        
        # Calculate mean time between attempts (if multiple attempts exist)
        if len(attempts) > 1:
            time_diffs = [attempts[i] - attempts[i-1] for i in range(1, len(attempts))]
            mean_time_between = np.mean(time_diffs)
            std_time_between = np.std(time_diffs) if len(time_diffs) > 1 else 0
            min_time_between = min(time_diffs) if time_diffs else 0
        else:
            mean_time_between = 0
            std_time_between = 0
            min_time_between = 0
        
        # Success to failure ratio
        total_attempts = ip_history['successes'] + ip_history['failures']
        success_ratio = ip_history['successes'] / total_attempts if total_attempts > 0 else 0
        failure_rate = 1 - success_ratio
        
        # Recent failure rate (using the last 10 min as "recent")
        recent_success = sum(1 for t, s in zip(attempts, [access_data['success']]) if t >= ten_minutes_ago and s)
        recent_total = sum(1 for t in attempts if t >= ten_minutes_ago)
        recent_failure_rate = 1 - (recent_success / recent_total if recent_total > 0 else 0)
        
        # Hour of day
        hour_of_day = int(access_data['time_of_day'].split(':')[0])
        
        # Is business hours
        is_business_hours = 1 if 8 <= hour_of_day <= 18 else 0
        
        # Check for script-like user agent
        is_script_ua = 0
        if 'user_agent' in access_data:
            ua = access_data['user_agent'].lower()
            is_script_ua = 1 if any(agent in ua for agent in ['python', 'curl', 'wget', 'go-http']) else 0
        
        # Features vector (matching the 15 features from preprocess_data)
        features = [
            attempts_10min,                   # attempts_10min
            len(ip_history['attempts']),      # total_attempts
            failure_rate,                     # failure_rate
            recent_failure_rate,              # recent_failure_rate
            hour_of_day,                      # hour_of_day
            is_business_hours,                # is_business_hours
            1 if access_data['key_type'] == 'RSA' else 0,  # key_type_rsa
            1 if access_data['key_type'] == 'ECC' else 0,  # key_type_ecc
            1 if access_data['key_type'] == 'DSA' else 0,  # key_type_dsa
            int(access_data['key_size']),     # key_size
            is_script_ua,                     # is_script_ua
            1 if access_data['success'] else 0,  # current_success
            mean_time_between,                # mean_time_between
            std_time_between,                 # std_time_between
            min_time_between                  # min_time_between
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
        Predict if the given access attempt is a brute force attack.
        
        Args:
            access_data: Dictionary with access information
            
        Returns:
            Dictionary with prediction results and action
        """
        ip = access_data['source_ip']
        
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
            # Lock out the IP
            self.locked_ips[ip] = time.time() + self.lockout_period
        elif ip in self.ip_tracking and self.ip_tracking[ip]['failures'] >= self.max_attempts:
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