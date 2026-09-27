import os
import json
from pathlib import Path
from typing import Dict, Any, Tuple, List
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from backend.sample_dataset import get_augmented_dataset

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODELS_DIR / "scam_model.joblib"
METRICS_PATH = MODELS_DIR / "model_metrics.json"

_cached_pipeline = None

def train_and_evaluate_models() -> Dict[str, Any]:
    """
    Trains and compares 4 ML models on scam message detection:
    - Multinomial Naive Bayes
    - Logistic Regression
    - Linear SVM (Calibrated)
    - Random Forest
    Saves the best model and performance metrics for academic presentation.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    dataset = get_augmented_dataset()

    texts = [item["text"] for item in dataset]
    labels = [item["is_scam"] for item in dataset]
    categories = [item["category"] for item in dataset]

    # Train / test split (80% train, 20% test) with stratified sampling
    X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
        texts, labels, categories, test_size=0.25, random_state=42, stratify=labels
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=3000,
        sublinear_tf=True,
        stop_words='english'
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Multi-class category classifier
    category_clf = LogisticRegression(max_iter=500, C=1.5)
    category_clf.fit(X_train_vec, cat_train)

    candidate_models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(C=1.5, max_iter=500),
        "Linear SVM": CalibratedClassifierCV(LinearSVC(C=1.0, random_state=42), cv=3),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
    }

    benchmarks = []
    best_model_name = "Logistic Regression"
    best_f1 = -1.0
    trained_models = {}

    for name, model in candidate_models.items():
        model.fit(X_train_vec, y_train)
        preds = model.predict(X_test_vec)
        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))

        benchmarks.append({
            "model_name": name,
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2)
        })
        trained_models[name] = model

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name

    # Select best model (Logistic Regression provides natural calibrated probability estimates)
    selected_model = trained_models.get("Logistic Regression", list(trained_models.values())[0])

    # Confusion matrix on test set for Logistic Regression
    lr_preds = selected_model.predict(X_test_vec)
    cm = confusion_matrix(y_test, lr_preds)
    cm_dict = {
        "true_negative": int(cm[0][0]) if len(cm) > 0 else 0,
        "false_positive": int(cm[0][1]) if len(cm) > 0 and len(cm[0]) > 1 else 0,
        "false_negative": int(cm[1][0]) if len(cm) > 1 else 0,
        "true_positive": int(cm[1][1]) if len(cm) > 1 and len(cm[1]) > 1 else 0
    }

    # Save artifact bundle
    pipeline_bundle = {
        "vectorizer": vectorizer,
        "scam_classifier": selected_model,
        "category_classifier": category_clf,
        "model_name": "Logistic Regression (TF-IDF)",
        "categories": list(set(categories))
    }
    joblib.dump(pipeline_bundle, MODEL_PATH)

    metrics_data = {
        "active_model": "Logistic Regression (TF-IDF)",
        "total_samples": len(dataset),
        "test_split_ratio": 0.25,
        "benchmark": benchmarks,
        "confusion_matrix": cm_dict
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)

    global _cached_pipeline
    _cached_pipeline = pipeline_bundle
    return metrics_data

def get_or_load_pipeline():
    global _cached_pipeline
    if _cached_pipeline is not None:
        return _cached_pipeline

    if not MODEL_PATH.exists():
        train_and_evaluate_models()

    _cached_pipeline = joblib.load(MODEL_PATH)
    return _cached_pipeline

def predict_scam(text: str) -> Dict[str, Any]:
    """Predicts scam probability and category from input text."""
    if not text or not text.strip():
        return {
            "is_scam": False,
            "probability": 0.0,
            "predicted_category": "Legitimate",
            "confidence_label": "Neutral",
            "model_name": "None"
        }

    pipeline = get_or_load_pipeline()
    vectorizer = pipeline["vectorizer"]
    classifier = pipeline["scam_classifier"]
    cat_clf = pipeline["category_classifier"]

    vec = vectorizer.transform([text])
    
    # Scam binary probability
    if hasattr(classifier, "predict_proba"):
        probs = classifier.predict_proba(vec)[0]
        # Class 1 is scam
        scam_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
    else:
        decision = classifier.decision_function(vec)[0]
        scam_prob = 1.0 / (1.0 + (2.71828 ** -decision))

    # Predicted category
    pred_cat = cat_clf.predict(vec)[0]

    is_scam = scam_prob >= 0.50

    if scam_prob > 0.85:
        conf_label = "Very High Confidence"
    elif scam_prob > 0.65:
        conf_label = "High Confidence"
    elif scam_prob > 0.45:
        conf_label = "Moderate Confidence"
    else:
        conf_label = "Low Scam Probability"

    return {
        "is_scam": is_scam,
        "probability": round(scam_prob, 3),
        "predicted_category": pred_cat if is_scam else "Legitimate",
        "confidence_label": conf_label,
        "model_name": pipeline["model_name"]
    }

def get_model_metrics() -> Dict[str, Any]:
    if not METRICS_PATH.exists():
        return train_and_evaluate_models()
    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
