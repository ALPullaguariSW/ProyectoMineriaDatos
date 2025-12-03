import os
import sys
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sample.data_loader import load_data
from modify.preprocessing import preprocess_data, extract_features

def train_models():
    """Trains Random Forest and SVM models."""
    print("Starting training...")
    df = load_data()
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    # Random Forest with Grid Search
    print("Training Random Forest with Grid Search...")
    rf_params = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5, 10]
    }
    rf_grid = GridSearchCV(RandomForestClassifier(random_state=42), rf_params, cv=3, n_jobs=-1)
    rf_grid.fit(X_train_vec, y_train)
    
    best_rf = rf_grid.best_estimator_
    print(f"Best RF Params: {rf_grid.best_params_}")
    
    # SVM
    print("Training SVM...")
    svm_model = SVC(kernel='linear', probability=True, random_state=42)
    svm_model.fit(X_train_vec, y_train)
    
    # Save Models
    os.makedirs("models", exist_ok=True)
    joblib.dump(best_rf, "models/rf_model.pkl")
    joblib.dump(svm_model, "models/svm_model.pkl")
    joblib.dump(best_rf, "models/rf_model_latest.pkl") # Save as latest for consistency if needed
    
    print("Models saved to 'models/' directory.")

if __name__ == "__main__":
    train_models()
