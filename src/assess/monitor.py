import joblib
import os
import numpy as np
from scipy.stats import ks_2samp
from data_loader import load_data
from preprocessing import preprocess_data, extract_features

MODEL_DIR = "models"

def check_drift():
    """Checks for data drift using Kolmogorov-Smirnov test on prediction probabilities."""
    print("Checking for data drift...")
    
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
        # Load test data used during training (baseline)
        # We need to save this during training to compare against new data
        # For this demo, we'll simulate "new data" by loading the dataset again and adding noise
        if not os.path.exists(os.path.join(MODEL_DIR, "test_data.pkl")):
             print("Baseline data not found. Run train_model.py first.")
             return

        X_test_vec_baseline, _ = joblib.load(os.path.join(MODEL_DIR, "test_data.pkl"))
        baseline_probs = model.predict_proba(X_test_vec_baseline)[:, 1]
        
        # Simulate new data (in production this would be real traffic)
        # Let's just take the same data but slightly perturbed to simulate drift
        # Or just use the same data to show "No Drift"
        new_probs = baseline_probs + np.random.normal(0, 0.05, size=len(baseline_probs))
        new_probs = np.clip(new_probs, 0, 1)
        
        # KS Test
        statistic, p_value = ks_2samp(baseline_probs, new_probs)
        
        print(f"KS Statistic: {statistic:.4f}")
        print(f"P-Value: {p_value:.4f}")
        
        if p_value < 0.05:
            print("\033[91m[ALERT] Data Drift Detected! Model performance may be degrading.\033[0m")
        else:
            print("\033[92m[OK] No significant drift detected.\033[0m")
            
    except Exception as e:
        print(f"Error checking drift: {e}")

if __name__ == "__main__":
    check_drift()
