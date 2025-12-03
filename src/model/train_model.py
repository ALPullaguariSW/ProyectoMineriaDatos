    """Trains Random Forest and SVM models."""
    df = load_data()
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    
    # Random Forest with Grid Search
    print("Training Random Forest with Grid Search...")
    rf_params = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5]
    }
    rf = RandomForestClassifier(random_state=42)
    rf_grid = GridSearchCV(rf, rf_params, cv=3, n_jobs=-1, scoring='accuracy')
    rf_grid.fit(X_train_vec, y_train)
    print(f"Best RF Params: {rf_grid.best_params_}")
    rf_model = rf_grid.best_estimator_
    
    # SVM with Grid Search
    print("Training SVM with Grid Search...")
    svm_params = {
        'C': [0.1, 1, 10],
        'kernel': ['linear', 'rbf'],
        'gamma': ['scale', 'auto']
    }
    svm = SVC(probability=True, random_state=42)
    svm_grid = GridSearchCV(svm, svm_params, cv=3, n_jobs=-1, scoring='accuracy')
    svm_grid.fit(X_train_vec, y_train)
    print(f"Best SVM Params: {svm_grid.best_params_}")
    svm_model = svm_grid.best_estimator_
    
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(rf_model, os.path.join(MODEL_DIR, "rf_model.pkl"))
    joblib.dump(svm_model, os.path.join(MODEL_DIR, "svm_model.pkl"))
    
    # Save test data for evaluation
    joblib.dump((X_test_vec, y_test), os.path.join(MODEL_DIR, "test_data.pkl"))
    
    print("Models trained and saved.")

if __name__ == "__main__":
    train_models()
