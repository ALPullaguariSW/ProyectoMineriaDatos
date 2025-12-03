import joblib
import os
import argparse
import sys
from preprocessing import clean_code, get_complexity, get_ast_depth, count_dangerous_calls, get_dangerous_details
import numpy as np

MODEL_DIR = "models"

def load_model():
    """Loads the trained model and vectorizer."""
    try:
        model = joblib.load(os.path.join(MODEL_DIR, "rf_model.pkl"))
        vectorizer = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
        return model, vectorizer
    except FileNotFoundError:
        print("Model not found. Please train the model first.")
        sys.exit(1)

def predict_file(filepath, model, vectorizer):
    """Predicts if a file contains vulnerabilities."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Fallback for non-utf8 files
        with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
            content = f.read()
    
    cleaned_content = clean_code(content)
    
    # 1. TF-IDF
    features_tfidf = vectorizer.transform([cleaned_content]).toarray()
    
    # 2. Complexity
    complexity = get_complexity(content)
    
    # 3. AST Depth
    ast_depth = get_ast_depth(content)
    
    # 4. Dangerous Calls
    dang_calls_count = count_dangerous_calls(content)
    dang_details = get_dangerous_details(content)
    
    # Combine
    features = np.hstack((features_tfidf, np.array([[complexity, ast_depth, dang_calls_count]])))
    
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1]
    
    details = {
        "complexity": complexity,
        "ast_depth": ast_depth,
        "dangerous_calls": dang_details
    }
    
    return prediction, probability, details

import json
import time

def scan_directory(path, model, vectorizer):
    """Recursively scans a directory for vulnerabilities."""
    results = []
    extensions = {".py", ".java", ".c", ".cpp", ".h", ".js"}
    ignore_dirs = {".git", "__pycache__", "node_modules", "venv", ".idea", ".vscode"}
    
    print(f"Scanning directory: {path}")
    
    for root, dirs, files in os.walk(path):
        # Filter ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in extensions:
                filepath = os.path.join(root, file)
                
                # Whitelist internal files
                if any(w in filepath for w in ["data_loader.py", "external_data.py", "test_cases", "train_model.py", "scan_repo.py"]):
                    continue
                    
                try:
                    pred, prob, details = predict_file(filepath, model, vectorizer)
                    status = "VULNERABLE" if pred == 1 else "SAFE"
                    
                    if status == "VULNERABLE":
                        print(f"\033[91m[{status}] {filepath} (Confidence: {prob:.2f})\033[0m")
                        if details['dangerous_calls']:
                            print(f"  ⚠️  Dangerous Calls: {', '.join(details['dangerous_calls'])}")
                    else:
                        # Only print safe if verbose or just summary? Let's keep it quiet for safe files to avoid clutter
                        # print(f"\033[92m[{status}] {filepath} (Confidence: {prob:.2f})\033[0m")
                        pass
                        
                    results.append({
                        "file": filepath,
                        "status": status,
                        "confidence": float(prob),
                        "details": details,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                except Exception as e:
                    print(f"Error scanning {filepath}: {e}")
                    
    return results

def generate_report(results, output_file="scan_report.json"):
    """Generates a JSON report of the scan with metadata."""
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": len(results),
        "vulnerable_files": sum(1 for r in results if r['status'] == 'VULNERABLE'),
        "scan_duration": 0, # Placeholder, could calculate real duration
        "results": results
    }
    
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"\nReport generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Scan files for vulnerabilities.")
    parser.add_argument("path", help="File or directory to scan")
    args = parser.parse_args()
    
    model, vectorizer = load_model()
    
    if os.path.isfile(args.path):
        print(f"Scanning single file: {args.path}")
        pred, prob = predict_file(args.path, model, vectorizer)
        status = "VULNERABLE" if pred == 1 else "SAFE"
        color = "\033[91m" if pred == 1 else "\033[92m"
        print(f"{color}[{status}] {args.path} (Confidence: {prob:.2f})\033[0m")
    elif os.path.isdir(args.path):
        results = scan_directory(args.path, model, vectorizer)
        vuln_count = sum(1 for r in results if r['status'] == 'VULNERABLE')
        print(f"\nScan Complete. Found {vuln_count} potential vulnerabilities out of {len(results)} files scanned.")
        generate_report(results)
    else:
        print("Invalid path.")

if __name__ == "__main__":
    main()
