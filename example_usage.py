from models.brute_force_detector import BruteForceDetector
import numpy as np
import time
from datetime import datetime

def simulate_key_access():
    """Simulate key access attempts, including normal usage and attacks."""
    # Load the trained model
    detector = BruteForceDetector()
    detector.load_model('models/brute_force_detector.joblib')
    
    # Simulate normal usage
    print("Simulating normal usage patterns...")
    normal_ips = ['192.168.1.100', '10.0.0.5', '172.16.254.1']
    
    for _ in range(10):
        for ip in normal_ips:
            # Normal access pattern
            access_data = {
                'source_ip': ip,
                'key_type': np.random.choice(['RSA', 'ECC', 'DSA']),
                'key_size': np.random.choice([2048, 3072, 4096]),
                'success': np.random.random() < 0.95,  # 95% success rate
                'time_of_day': datetime.now().strftime('%H:%M')
            }
            
            result = detector.predict(access_data)
            
            print(f"IP: {ip}, Action: {result['action']}, Probability: {result['probability']:.4f}")
            
            # Simulate time passing
            time.sleep(0.5)
    
    # Simulate brute force attack
    print("\nSimulating brute force attack...")
    attack_ip = '45.33.22.156'
    
    for _ in range(20):
        access_data = {
            'source_ip': attack_ip,
            'key_type': 'RSA',  # Attackers often target a specific key type
            'key_size': 2048,
            'success': False,  # Most attempts fail
            'time_of_day': datetime.now().strftime('%H:%M')
        }
        
        result = detector.predict(access_data)
        
        print(f"IP: {attack_ip}, Action: {result['action']}, Probability: {result['probability']:.4f}")
        
        # If blocked, show message
        if result['action'] == 'block':
            print(f"Attack detected! {result['reason']}")
        
        # Simulate faster attempts (typical of brute force)
        time.sleep(0.1)
    
    print("\nSimulation complete.")

if __name__ == "__main__":
    simulate_key_access() 