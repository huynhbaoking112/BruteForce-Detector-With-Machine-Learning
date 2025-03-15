from models.brute_force_detector import BruteForceDetector
import numpy as np
import time
from datetime import datetime

def simulate_password_access():
    """Simulate password access attempts, including normal usage and attacks."""
    # Load the trained model
    detector = BruteForceDetector()
    detector.load_model('models/brute_force_detector.joblib')
    
    # Simulate normal usage
    print("Simulating normal usage patterns...")
    normal_ips = ['192.168.1.100', '10.0.0.5', '172.16.254.1']
    normal_users = ['john', 'alice', 'bob']
    
    for _ in range(10):
        for i, ip in enumerate(normal_ips):
            # Normal access pattern
            access_data = {
                'source_ip': ip,
                'username': normal_users[i],
                'password_complexity': np.random.randint(70, 100),
                'success': np.random.random() < 0.95,  # 95% success rate
                'time_of_day': datetime.now().strftime('%H:%M'),
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            result = detector.predict(access_data)
            
            print(f"IP: {ip}, User: {access_data['username']}, Action: {result['action']}, Probability: {result['probability']:.4f}")
            
            # Simulate time passing
            time.sleep(0.5)
    
    # Simulate brute force attack
    print("\nSimulating brute force password attack...")
    attack_ip = '135.792.2137'
    target_user = 'kingh'
    
    for _ in range(20):
        access_data = {
            'source_ip': attack_ip,
            'username': target_user,
            'password_complexity': np.random.randint(30, 60),  # Simpler passwords in attacks
            'success': False,  # Most attempts fail
            'time_of_day': datetime.now().strftime('%H:%M'),
            'user_agent': 'python-requests/2.25.1'
        }
        
        result = detector.predict(access_data)
        
        print(f"IP: {attack_ip}, User: {target_user}, Action: {result['action']}, Probability: {result['probability']:.4f}")
        
        # If blocked, show message
        if result['action'] == 'block':
            print(f"Attack detected! {result['reason']}")
        
        # Simulate faster attempts (typical of brute force)
        time.sleep(0.1)
    
    print("\nSimulation complete.")

if __name__ == "__main__":
    simulate_password_access() 



# from models.brute_force_detector import BruteForceDetector
# import numpy as np
# import time
# from datetime import datetime

# def simulate_password_access():
#     """Simulate password access attempts, including normal usage and attacks."""
#     # Load the trained model
#     detector = BruteForceDetector()
#     detector.load_model('models/brute_force_detector.joblib')
    
#     # Simulate normal usage
#     print("Simulating normal usage patterns...")
#     normal_ips = ['192.168.1.100', '10.0.0.5', '172.16.254.1']
#     normal_users = ['john', 'alice', 'bob']
    
#     for _ in range(10):
#         for i, ip in enumerate(normal_ips):
#             # Normal access pattern
#             access_data = {
#                 'source_ip': ip,
#                 'username': normal_users[i],
#                 'password_complexity': np.random.randint(70, 100),
#                 'success': np.random.random() < 0.95,  # 95% success rate
#                 'time_of_day': datetime.now().strftime('%H:%M'),
#                 'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
#             }
            
#             result = detector.predict(access_data)
            
#             print(f"IP: {ip}, User: {access_data['username']}, Action: {result['action']}, Probability: {result['probability']:.4f}")
            
#             # Simulate time passing
#             time.sleep(0.5)
    
#     # Simulate brute force attack
#     print("\nSimulating brute force password attack...")
#     attack_ip = '192.168.1.100'
#     target_user = 'john'
    
#     for _ in range(30):
#         access_data = {
#             'source_ip': attack_ip,
#             'username': target_user,
#             'password_complexity': np.random.randint(30, 60),  # Simpler passwords in attacks
#             'success': False,  # Most attempts fail
#             'time_of_day': datetime.now().strftime('%H:%M'),
#             'user_agent': 'python-requests/2.25.1'
#         }
        
#         result = detector.predict(access_data)
        
#         print(f"IP: {attack_ip}, User: {target_user}, Action: {result['action']}, Probability: {result['probability']:.4f}")
        
#         # If blocked, show message
#         if result['action'] == 'block':
#             print(f"Attack detected! {result['reason']}")
        
#         # Simulate faster attempts (typical of brute force)
#         time.sleep(0.1)
    
#     print("\nSimulation complete.")

# if __name__ == "__main__":
#     simulate_password_access() 


# from models.brute_force_detector import BruteForceDetector
# import numpy as np
# import time
# from datetime import datetime

# def simulate_password_access():
#     """Simulate password access attempts, including normal usage and attacks."""
#     # Load the trained model
#     detector = BruteForceDetector()
#     detector.load_model('models/brute_force_detector.joblib')
    
#     # Simulate normal usage
#     print("Simulating normal usage patterns...")
#     normal_ips = ['192.168.1.100', '10.0.0.5', '172.16.254.1','123.123.123']
#     normal_users = ['john', 'alice', 'bob','ben']
    
#     for _ in range(20):
#         for i, ip in enumerate(normal_ips):
#             test = False if ip == '123.123.123' else np.random.random() < 0.95
#             # Normal access pattern
#             access_data = {
#                 'source_ip': ip,
#                 'username': normal_users[i],
#                 'password_complexity': np.random.randint(70, 100),
#                 'success': test,  # 95% success rate
#                 'time_of_day': datetime.now().strftime('%H:%M'),
#                 'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
#             }
            
#             result = detector.predict(access_data)
            
#             print(f"IP: {ip}, MK:{test} ,User: {access_data['username']}, Action: {result['action']}, Probability: {result['probability']:.4f}")
            
#             # Simulate time passing
#             time.sleep(0.5)
    
#     # Simulate brute force attack
#     print("\nSimulating brute force password attack...")
#     attack_ip = '19.1213'
#     target_user = 'joasdhn'
    
#     for _ in range(30):
#         access_data = {
#             'source_ip': attack_ip,
#             'username': target_user,
#             'password_complexity': np.random.randint(30, 60),  # Simpler passwords in attacks
#             'success': False,  # Most attempts fail
#             'time_of_day': datetime.now().strftime('%H:%M'),
#             'user_agent': 'python-requests/2.25.1'
#         }
        
#         result = detector.predict(access_data)
        
#         print(f"IP: {attack_ip}, User: {target_user}, Action: {result['action']}, Probability: {result['probability']:.4f}")
        
#         # If blocked, show message
#         if result['action'] == 'block':
#             print(f"Attack detected! {result['reason']}")
        
#         # Simulate faster attempts (typical of brute force)
#         time.sleep(0.1)
    
#     print("\nSimulation complete.")

# if __name__ == "__main__":
#     simulate_password_access() 