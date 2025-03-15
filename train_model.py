from data.generate_datasets import generate_datasets
from utils.preprocessing import preprocess_data
from models.brute_force_detector import BruteForceDetector
import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve, classification_report

def train_brute_force_model():
    """Train the brute force detection model on generated data."""
    # Ensure directories exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('visualizations', exist_ok=True)  # Create folder for visualizations
    
    print("Generating datasets...")
    train_df, test_df = generate_datasets(num_normal=1000, num_attacks=200)
    
    print("Preprocessing data...")
    X_train, y_train = preprocess_data(train_df)
    X_test, y_test = preprocess_data(test_df)
    
    print("Training model...")
    detector = BruteForceDetector(threshold=0.7, lockout_period=300, max_attempts=5)
    detector.train(X_train, y_train)
    
    print("Saving model...")
    detector.save_model('models/brute_force_detector.joblib')
    
    print("Evaluating model...")
    # Load the model to make sure it works
    detector_test = BruteForceDetector()
    detector_test.load_model('models/brute_force_detector.joblib')
    
    # Test on all test examples
    print("Running full evaluation...")
    predictions = []
    probabilities = []
    
    for i in range(len(X_test)):
        # Create a test example
        test_data = {
            'source_ip': test_df.iloc[i]['source_ip'],
            'username': test_df.iloc[i]['username'],
            'password_complexity': test_df.iloc[i]['password_complexity'],
            'success': test_df.iloc[i]['success'],
            'time_of_day': test_df.iloc[i]['time_of_day'],
            'user_agent': test_df.iloc[i]['user_agent']
        }
        
        result = detector_test.predict(test_data)
        predictions.append(1 if result['is_attack'] else 0)
        probabilities.append(result['probability'])
    
    # Calculate metrics for visualization
    correct = sum(1 for p, y in zip(predictions, y_test) if p == y)
    accuracy = correct / len(y_test)
    
    # Display some sample predictions
    for i in range(min(10, len(y_test))):
        print(f"Example {i+1}:")
        print(f"  Actual: {'Attack' if y_test[i] == 1 else 'Normal'}")
        print(f"  Predicted: {'Attack' if predictions[i] == 1 else 'Normal'}")
        print(f"  Probability: {probabilities[i]:.4f}")
        print()
        
    print(f"Overall accuracy: {accuracy:.2%}")
    
    # Generate visualizations
    print("Generating visualizations...")
    
    # 1. Confusion Matrix
    cm = confusion_matrix(y_test, predictions)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Attack'], 
                yticklabels=['Normal', 'Attack'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig('visualizations/confusion_matrix.png')
    plt.close()
    
    # 2. ROC Curve
    fpr, tpr, _ = roc_curve(y_test, probabilities)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC)')
    plt.legend(loc="lower right")
    plt.savefig('visualizations/roc_curve.png')
    plt.close()
    
    # 3. Precision-Recall Curve
    precision, recall, _ = precision_recall_curve(y_test, probabilities)
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='blue', lw=2)
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.savefig('visualizations/precision_recall_curve.png')
    plt.close()
    
    # 4. Feature Importance
    feature_names = [
        'IP attempts (10min)', 'User attempts (10min)', 'IP total attempts', 
        'User total attempts', 'IP failure rate', 'User failure rate',
        'IP recent failure rate', 'User recent failure rate', 'Hour of day',
        'Is business hours', 'Unique usernames', 'Unique IPs',
        'Password complexity', 'Is script UA', 'Current success',
        'IP mean time between', 'IP std time between', 'IP min time between',
        'User mean time between', 'User std time between', 'User min time between'
    ]
    
    importances = detector_test.model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    plt.figure(figsize=(12, 8))
    plt.bar(range(len(importances)), importances[indices], align='center')
    plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=90)
    plt.xlim([-1, len(importances)])
    plt.tight_layout()
    plt.title('Feature Importance')
    plt.savefig('visualizations/feature_importance.png')
    plt.close()
    
    # 5. Classification Report as Image
    report = classification_report(y_test, predictions, target_names=['Normal', 'Attack'])
    plt.figure(figsize=(10, 6))
    plt.text(0.01, 0.99, report, {'fontsize': 12}, verticalalignment='top')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig('visualizations/classification_report.png')
    plt.close()
    
    print("Model ready for use! Overall accuracy: {:.2%}".format(accuracy))
    print("Visualizations saved to 'visualizations' directory")

if __name__ == "__main__":
    train_brute_force_model()