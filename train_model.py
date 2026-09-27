"""
Stand-alone Model Training & Benchmark Script for AI Scam Detector.
Trains 4 machine learning models (Naive Bayes, Logistic Regression, Linear SVM, Random Forest),
computes evaluation metrics (Accuracy, Precision, Recall, F1), and saves model artifacts.
"""

import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir))

from backend.classifier import train_and_evaluate_models

def main():
    print("=" * 60)
    print("  AI Scam Detector — ML Model Training & Benchmarking")
    print("=" * 60)
    print("[*] Loading labeled dataset and extracting features (TF-IDF)...")
    
    metrics = train_and_evaluate_models()
    
    print("\n[+] Model Training Complete! Benchmark Results:")
    print("-" * 60)
    print(f"{'Model Name':<26} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<7} | {'F1-Score':<8}")
    print("-" * 60)
    for b in metrics["benchmark"]:
        print(f"{b['model_name']:<26} | {b['accuracy']:>7}% | {b['precision']:>8}% | {b['recall']:>6}% | {b['f1_score']:>7}%")
    print("-" * 60)

    cm = metrics["confusion_matrix"]
    print(f"\n[+] Confusion Matrix (Logistic Regression on Test Set):")
    print(f"    True Negative (Safe identified as Safe):     {cm['true_negative']}")
    print(f"    False Positive (Safe flagged as Scam):      {cm['false_positive']}")
    print(f"    False Negative (Scam missed as Safe):       {cm['false_negative']}")
    print(f"    True Positive (Scam identified as Scam):    {cm['true_positive']}")
    print("\n[+] Artifacts successfully serialized to models/scam_model.joblib and models/model_metrics.json\n")

if __name__ == "__main__":
    main()
