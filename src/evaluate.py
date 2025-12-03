import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve

MODEL_DIR = "models"
OUTPUT_DIR = "reports/figures"

def evaluate_models():
    """Evaluates trained models."""
    if not os.path.exists(os.path.join(MODEL_DIR, "test_data.pkl")):
        print("Test data not found. Run train_model.py first.")
        return

    X_test_vec, y_test = joblib.load(os.path.join(MODEL_DIR, "test_data.pkl"))
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
    svm_model = joblib.load(os.path.join(MODEL_DIR, "svm_model.pkl"))
    
    models = {"Random Forest": rf_model, "SVM": svm_model}
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    for name, model in models.items():
        print(f"--- Evaluating {name} ---")
        y_pred = model.predict(X_test_vec)
        y_prob = model.predict_proba(X_test_vec)[:, 1]
        
        print(classification_report(y_test, y_pred))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(5, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f"Confusion Matrix - {name}")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.savefig(os.path.join(OUTPUT_DIR, f"confusion_matrix_{name.replace(' ', '_')}.png"))
        
        # ROC Curve
        auc = roc_auc_score(y_test, y_prob)
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        plt.figure(figsize=(6, 4))
        plt.plot(fpr, tpr, label=f"AUC = {auc:.2f}")
        plt.plot([0, 1], [0, 1], 'k--')
        plt.title(f"ROC Curve - {name}")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.legend()
        plt.savefig(os.path.join(OUTPUT_DIR, f"roc_curve_{name.replace(' ', '_')}.png"))
        print(f"Saved plots for {name}")

if __name__ == "__main__":
    evaluate_models()
