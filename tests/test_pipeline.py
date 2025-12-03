import pytest
import pandas as pd
import os
import joblib
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_loader import load_data, generate_synthetic_data
from src.preprocessing import clean_code, preprocess_data, extract_features
from src.train_model import train_models
from src.predict import predict_file

def test_clean_code():
    raw_code = "int main() { // comment \n return 0; }"
    cleaned = clean_code(raw_code)
    assert "//" not in cleaned
    assert "return 0;" in cleaned

def test_data_loader():
    df = generate_synthetic_data(num_samples=10)
    # It might be more than 10 because of external CVEs
    assert len(df) >= 10
    assert "code" in df.columns
    assert "is_vulnerable" in df.columns

def test_model_training_and_prediction(tmp_path):
    # Setup temp dirs
    os.chdir(tmp_path)
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    
    # Generate data
    df = generate_synthetic_data(num_samples=20)
    df.to_csv("data/dataset.csv", index=False)
    
    # Train
    # We need to import train_models but it relies on hardcoded paths in the module.
    # For this test, we'll replicate the logic briefly or mock.
    # Actually, let's just run the functions directly.
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=10)
    rf.fit(X_train_vec, y_train)
    
    joblib.dump(rf, "models/rf_model.pkl")
    joblib.dump(joblib.load("models/tfidf_vectorizer.pkl"), "models/tfidf_vectorizer.pkl") # Re-save to ensure it exists
    
    # Predict
    test_file = tmp_path / "test.c"
    test_file.write_text("int main() { return 0; }", encoding="utf-8")
    
    model = joblib.load("models/rf_model.pkl")
    vectorizer = joblib.load("models/tfidf_vectorizer.pkl")
    
    pred, prob, details = predict_file(str(test_file), model, vectorizer)
    assert pred in [0, 1]
    assert 0.0 <= prob <= 1.0
    assert isinstance(details, dict)
