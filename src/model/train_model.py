import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sample.data_loader import load_data
from modify.preprocessing import preprocess_data, extract_features

def train_models():
    """Trains Random Forest and SVM models with advanced tuning and metrics."""
    print("Starting training pipeline...")
    
    # 1. Load Data
    df = load_data()
    
    # 2. Smart Polishing (Balancing)
    # If we have too many safe samples (0), downsample them to match vulnerable (1)
    vuln_count = df['is_vulnerable'].sum()
    safe_count = len(df) - vuln_count
    print(f"Original Distribution: Safe={safe_count}, Vulnerable={vuln_count}")
    
    if safe_count > vuln_count * 1.5: # Allow some imbalance, but not extreme
        print("Balancing dataset (Downsampling Safe class)...")
        df_vuln = df[df['is_vulnerable'] == 1]
        df_safe = df[df['is_vulnerable'] == 0].sample(n=int(vuln_count * 1.2), random_state=42) # 1.2 ratio
        df = pd.concat([df_vuln, df_safe]).sample(frac=1).reset_index(drop=True)
        print(f"Balanced Distribution: Safe={len(df_safe)}, Vulnerable={len(df_vuln)}")

    # 3. Preprocessing (80/20 Split is handled in preprocess_data, let's verify)
    # We need to ensure preprocess_data uses test_size=0.2
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    print(f"Training Set: {X_train_vec.shape[0]} samples")
    print(f"Testing Set: {X_test_vec.shape[0]} samples")
    
    # 4. Random Forest with Grid Search (5-Fold CV)
    print("\n--- Training Random Forest (Grid Search) ---")
    rf_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [None, 20, 30],
        'min_samples_split': [2, 5],
        'class_weight': ['balanced', None]
    }
    rf_grid = GridSearchCV(RandomForestClassifier(random_state=42), rf_params, cv=5, n_jobs=-1, verbose=1)
    rf_grid.fit(X_train_vec, y_train)
    
    best_rf = rf_grid.best_estimator_
    print(f"Best RF Params: {rf_grid.best_params_}")
    print(f"Best CV Score: {rf_grid.best_score_:.4f}")
    
    # 5. SVM (Linear)
    print("\n--- Training SVM ---")
    svm_model = SVC(kernel='linear', probability=True, random_state=42, class_weight='balanced')
    svm_model.fit(X_train_vec, y_train)
    
    # 6. Evaluation
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import learning_curve
    import matplotlib.pyplot as plt
    import numpy as np
    
    print("\n--- Random Forest Evaluation (Test Set) ---")
    y_pred_rf = best_rf.predict(X_test_vec)
    print(classification_report(y_test, y_pred_rf))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_rf))
    
    print("\n--- SVM Evaluation (Test Set) ---")
    y_pred_svm = svm_model.predict(X_test_vec)
    print(classification_report(y_test, y_pred_svm))

    # 7. Learning Curve Analysis
    print("\n--- Generating Learning Curve ---")
    try:
        os.makedirs("reports", exist_ok=True)
        train_sizes, train_scores, test_scores = learning_curve(
            best_rf, X_train_vec, y_train, cv=5, n_jobs=-1, 
            train_sizes=np.linspace(0.1, 1.0, 5), scoring='accuracy'
        )
        
        train_scores_mean = np.mean(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        
        plt.figure()
        plt.title("Learning Curve (Random Forest)")
        plt.xlabel("Training examples")
        plt.ylabel("Accuracy Score")
        plt.grid()
        
        plt.plot(train_sizes, train_scores_mean, 'o-', color="r", label="Training score")
        plt.plot(train_sizes, test_scores_mean, 'o-', color="g", label="Cross-validation score")
        
        plt.legend(loc="best")
        plt.savefig("reports/learning_curve.png")
        print("✅ Learning curve saved to 'reports/learning_curve.png'")
        
        # Textual Analysis for User
        gap = train_scores_mean[-1] - test_scores_mean[-1]
        print(f"Final Training Score: {train_scores_mean[-1]:.4f}")
        print(f"Final CV Score: {test_scores_mean[-1]:.4f}")
        print(f"Gap: {gap:.4f}")
        
        if gap > 0.1:
            print("⚠️  High Variance detected (Overfitting). More data needed.")
        elif test_scores_mean[-1] < 0.7:
            print("⚠️  High Bias detected (Underfitting). Model too simple or features poor.")
        else:
            print("✅  Good Fit. Model generalizes well.")
            
    except Exception as e:
        print(f"Error generating learning curve: {e}")
    
    # 8. Save Models
    os.makedirs("models", exist_ok=True)
    joblib.dump(best_rf, "models/rf_model.pkl")
    joblib.dump(svm_model, "models/svm_model.pkl")
    
    print("\n✅ Models saved successfully.")

if __name__ == "__main__":
    train_models()
