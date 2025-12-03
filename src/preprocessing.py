import pandas as pd
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from radon.complexity import cc_visit
import joblib
import os

MODEL_DIR = "models"

# Load CodeBERT (lazy loading to save time on import if not used)
tokenizer = None
model = None

def get_codebert_embedding(code):
    """Generates CodeBERT embedding for a code snippet."""
    global tokenizer, model
    try:
        import torch
        from transformers import AutoTokenizer, AutoModel
    except ImportError:
        print("PyTorch or Transformers not installed. Skipping CodeBERT.")
        return np.zeros(768) # Return dummy embedding

    if tokenizer is None:
        print("Loading CodeBERT model...")
        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        model = AutoModel.from_pretrained("microsoft/codebert-base")
    
    # Truncate to 512 tokens
    inputs = tokenizer(code, return_tensors="pt", max_length=512, truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
    
    # Use the [CLS] token embedding (first token)
    return outputs.last_hidden_state[:, 0, :].numpy().flatten()

def get_complexity(code):
    """Calculates Cyclomatic Complexity."""
    try:
        # Radon works best on Python, for C/C++ we might need a different tool or heuristic.
        # Since our synthetic data is Python-like, we use radon.
        # For C/C++, we would use 'lizard' or similar.
        # Here we wrap in try-except to be robust.
        blocks = cc_visit(code)
        if not blocks:
            return 1
        return sum([block.complexity for block in blocks]) / len(blocks) # Average complexity
    except Exception:
        return 1 # Default fallback

def clean_code(code):
    """Basic code cleaning."""
    if code is None:
        return ""
    # Remove comments (simple regex for C/Python style)
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'#.*', '', code)
    # Remove extra whitespace
    code = re.sub(r'\s+', ' ', code).strip()
    return code

def preprocess_data(df):
    """Cleans data and splits into train/test."""
    print("Preprocessing data...")
    df['clean_code'] = df['code'].apply(clean_code)
    
    # Add Complexity Feature
    print("Calculating complexity...")
    df['complexity'] = df['code'].apply(get_complexity)
    
    X = df[['code', 'clean_code', 'complexity']]
    y = df['is_vulnerable']
    
    return train_test_split(X, y, test_size=0.2, random_state=42)

import ast
import re

def get_ast_depth(code):
    """Calculates AST depth for Python, or estimates brace depth for C/Java."""
    try:
        # Try parsing as Python first
        tree = ast.parse(code)
        return _compute_ast_depth(tree)
    except SyntaxError:
        # Fallback for C/C++/Java: Brace counting
        max_depth = 0
        current_depth = 0
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        return max_depth

def _compute_ast_depth(node):
    """Recursive helper for AST depth."""
    if not isinstance(node, ast.AST):
        return 0
    
    max_child_depth = 0
    for child in ast.iter_child_nodes(node):
        max_child_depth = max(max_child_depth, _compute_ast_depth(child))
    
    return 1 + max_child_depth

def count_dangerous_calls(code):
    """Counts occurrences of known dangerous functions (C, Python, Java)."""
    patterns = [
        r'strcpy\(', r'strcat\(', r'sprintf\(', r'gets\(', r'system\(', # C/C++
        r'os\.system\(', r'subprocess\.call\(', r'eval\(', r'exec\(', r'pickle\.load\(', r'input\(', # Python
        r'Runtime\.getRuntime\(\)\.exec\(', r'Statement\.execute\(', r'executeQuery\(' # Java
    ]
    count = 0
    for p in patterns:
        count += len(re.findall(p, code))
    return count

def extract_features(X_train, X_test):
    """Extracts TF-IDF + Complexity + AST Depth + Dangerous Calls features."""
    print("Extracting features...")
    
    # 1. TF-IDF
    vectorizer = TfidfVectorizer(max_features=1000, token_pattern=r'\b\w+\b')
    X_train_tfidf = vectorizer.fit_transform(X_train['clean_code']).toarray()
    X_test_tfidf = vectorizer.transform(X_test['clean_code']).toarray()
    
    # 2. Complexity (reshape for concatenation)
    X_train_cc = X_train['complexity'].values.reshape(-1, 1)
    X_test_cc = X_test['complexity'].values.reshape(-1, 1)
    
    # 3. AST Depth
    X_train_ast = np.array([get_ast_depth(c) for c in X_train['code']]).reshape(-1, 1)
    X_test_ast = np.array([get_ast_depth(c) for c in X_test['code']]).reshape(-1, 1)
    
    # 4. Dangerous Calls
    X_train_dang = np.array([count_dangerous_calls(c) for c in X_train['code']]).reshape(-1, 1)
    X_test_dang = np.array([count_dangerous_calls(c) for c in X_test['code']]).reshape(-1, 1)
    
    # Combine all features
    X_train_final = np.hstack((X_train_tfidf, X_train_cc, X_train_ast, X_train_dang))
    X_test_final = np.hstack((X_test_tfidf, X_test_cc, X_test_ast, X_test_dang))
    
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
    
    return X_train_final, X_test_final

if __name__ == "__main__":
    from data_loader import load_data
    df = load_data()
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    print(f"Training features shape: {X_train_vec.shape}")
    print(f"Testing features shape: {X_test_vec.shape}")
