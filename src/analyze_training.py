import matplotlib.pyplot as plt
import numpy as np
import os
from sklearn.model_selection import learning_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from data_loader import load_data
from preprocessing import preprocess_data, extract_features

OUTPUT_DIR = "reports/figures"

def plot_learning_curve(estimator, title, X, y, ylim=None, cv=None,
                        n_jobs=None, train_sizes=np.linspace(.1, 1.0, 5)):
    """
    Generate a simple plot of the test and training learning curve.
    """
    plt.figure()
    plt.title(title)
    if ylim is not None:
        plt.ylim(*ylim)
    plt.xlabel("Training examples")
    plt.ylabel("Score")
    
    train_sizes, train_scores, test_scores = learning_curve(
        estimator, X, y, cv=cv, n_jobs=n_jobs, train_sizes=train_sizes)
    
    train_scores_mean = np.mean(train_scores, axis=1)
    train_scores_std = np.std(train_scores, axis=1)
    test_scores_mean = np.mean(test_scores, axis=1)
    test_scores_std = np.std(test_scores, axis=1)
    
    plt.grid()

    plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                     train_scores_mean + train_scores_std, alpha=0.1,
                     color="r")
    plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                     test_scores_mean + test_scores_std, alpha=0.1,
                     color="g")
    plt.plot(train_sizes, train_scores_mean, 'o-', color="r",
             label="Training score")
    plt.plot(train_sizes, test_scores_mean, 'o-', color="g",
             label="Cross-validation score")

    plt.legend(loc="best")
    
    save_path = os.path.join(OUTPUT_DIR, f"learning_curve_{title.replace(' ', '_')}.png")
    plt.savefig(save_path)
    print(f"Saved learning curve to {save_path}")
    return plt

def analyze_training():
    print("Generating learning curves...")
    df = load_data()
    # We use the full dataset for cross-validated learning curve
    # But we still need to vectorise it.
    # For simplicity, let's just split and vectorize like before to get X and y compatible
    # Ideally we'd put vectorizer in a pipeline, but let's stick to our manual steps for consistency
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    # Combine for CV
    from scipy.sparse import vstack
    X_full = vstack((X_train_vec, X_test_vec))
    y_full = np.concatenate([y_train, y_test])
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    plot_learning_curve(rf, "Random Forest", X_full, y_full, cv=5, n_jobs=-1)
    
    # SVM
    svm = SVC(probability=True, random_state=42)
    plot_learning_curve(svm, "SVM", X_full, y_full, cv=5, n_jobs=-1)

if __name__ == "__main__":
    analyze_training()
