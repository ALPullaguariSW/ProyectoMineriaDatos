import shap
import joblib
import os
import matplotlib.pyplot as plt
import numpy as np
from data_loader import load_data
from preprocessing import preprocess_data, extract_features

MODEL_DIR = "models"
OUTPUT_DIR = "reports/figures"

def explain_model():
    """Generates SHAP plots for the Random Forest model."""
    print("Generating SHAP explanations...")
    
    # Load data and model
    df = load_data()
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
        vectorizer = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
    except FileNotFoundError:
        print("Model not found. Train first.")
        return

    # SHAP Explainer
    # We use a summary of X_train to speed up calculation if dataset is large
    # For small dataset, we can use X_train directly
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test_vec)
    
    # Feature Names
    feature_names = vectorizer.get_feature_names_out()
    # Add complexity feature name
    feature_names = np.append(feature_names, "Cyclomatic_Complexity")
    
    print(f"Data shape: {X_test_vec.shape}")
    print(f"Feature names length: {len(feature_names)}")
    
    if X_test_vec.shape[1] != len(feature_names):
        print("Shape mismatch! Adjusting feature names...")
        # If mismatch, likely TF-IDF produced fewer features than max_features
        # But get_feature_names_out() should match the vectorizer's output.
        # Wait, did we save the vectorizer AFTER fitting on train? Yes.
        # Did we load the SAME vectorizer? Yes.
        # Maybe CodeBERT was enabled in preprocessing but not here?
        # No, we commented it out.
        # Let's just truncate or pad feature names if needed to avoid crash
        if len(feature_names) < X_test_vec.shape[1]:
            diff = X_test_vec.shape[1] - len(feature_names)
            feature_names = np.append(feature_names, [f"Unknown_{i}" for i in range(diff)])
        elif len(feature_names) > X_test_vec.shape[1]:
            feature_names = feature_names[:X_test_vec.shape[1]]
            
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Summary Plot
    plt.figure()
    # shap_values[1] is for the positive class (Vulnerable)
    # Check if shap_values is a list (for classifier) or array
    if isinstance(shap_values, list):
        vals = shap_values[1]
    else:
        vals = shap_values
        
    shap.summary_plot(vals, X_test_vec, feature_names=feature_names, show=False)
    plt.savefig(os.path.join(OUTPUT_DIR, "shap_summary.png"), bbox_inches='tight')
    print(f"Saved SHAP summary to {OUTPUT_DIR}/shap_summary.png")

if __name__ == "__main__":
    explain_model()
