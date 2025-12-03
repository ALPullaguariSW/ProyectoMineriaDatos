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

def get_dangerous_details(code):
    """
    Scans code line-by-line for specific dangerous functions, patterns, and secrets.
    Returns a list of dictionaries with detailed findings.
    """
    findings = []
    lines = code.split('\n')
    
    # Define Knowledge Base of Vulnerabilities
    # Format: Regex Pattern -> {Type, Severity, Description, Remediation}
    knowledge_base = {
        # --- C/C++ ---
        r'strcpy\(': {
            "type": "Buffer Overflow", "severity": "High",
            "cwe": "CWE-120", "owasp": "A03:2021-Injection",
            "desc": "La función 'strcpy' no verifica la longitud del buffer destino.",
            "fix": "Use 'strncpy' o funciones seguras como 'strcpy_s'."
        },
        r'gets\(': {
            "type": "Buffer Overflow", "severity": "Critical",
            "cwe": "CWE-242", "owasp": "A03:2021-Injection",
            "desc": "La función 'gets' es inherentemente insegura y obsoleta.",
            "fix": "Reemplácela con 'fgets'."
        },
        r'system\(': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Ejecutar comandos del sistema operativo puede permitir inyección de comandos.",
            "fix": "Evite 'system'. Use APIs específicas del lenguaje o valide estrictamente la entrada."
        },
        r'sprintf\(': {
            "type": "Buffer Overflow", "severity": "Medium",
            "cwe": "CWE-134", "owasp": "A03:2021-Injection",
            "desc": "Uso de sprintf sin control de longitud.",
            "fix": "Use 'snprintf' para limitar el tamaño del buffer."
        },

        # --- Python ---
        r'eval\(': {
            "type": "Code Injection", "severity": "Critical",
            "cwe": "CWE-95", "owasp": "A03:2021-Injection",
            "desc": "'eval' ejecuta código arbitrario. Si la entrada es controlada por el usuario, es fatal.",
            "fix": "Use 'ast.literal_eval' para evaluar estructuras de datos seguras."
        },
        r'exec\(': {
            "type": "Code Injection", "severity": "Critical",
            "cwe": "CWE-95", "owasp": "A03:2021-Injection",
            "desc": "'exec' ejecuta código Python dinámicamente.",
            "fix": "Evite la ejecución dinámica de código. Reestructure la lógica."
        },
        r'pickle\.load': {
            "type": "Insecure Deserialization", "severity": "High",
            "cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures",
            "desc": "Pickle es inseguro contra datos maliciosos.",
            "fix": "Use formatos seguros como JSON ('json.load') para serializar datos."
        },
        r'subprocess\.call\(.*shell=True': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Usar 'shell=True' en subprocess abre brechas de seguridad.",
            "fix": "Establezca 'shell=False' y pase los argumentos como una lista."
        },
        r'yaml\.load\(': {
            "type": "Insecure Deserialization", "severity": "High",
            "cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures",
            "desc": "yaml.load es inseguro por defecto en versiones antiguas de PyYAML.",
            "fix": "Use 'yaml.safe_load'."
        },

        # --- JavaScript / Node.js / TypeScript ---
        r'innerHTML': {
            "type": "XSS (Cross-Site Scripting)", "severity": "Medium",
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Asignar directamente a 'innerHTML' puede permitir inyección de scripts.",
            "fix": "Use 'textContent' o bibliotecas de sanitización como DOMPurify."
        },
        r'document\.write': {
            "type": "XSS / Performance", "severity": "Medium",
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "'document.write' es inseguro y bloquea el renderizado.",
            "fix": "Use manipulación segura del DOM (e.g., 'appendChild')."
        },
        r'dangerouslySetInnerHTML': {
            "type": "XSS (React)", "severity": "High",
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Uso explícito de inyección HTML en React.",
            "fix": "Evite su uso o sanitice la entrada con DOMPurify."
        },
        r'eval\(': {
            "type": "Code Injection", "severity": "Critical",
            "cwe": "CWE-95", "owasp": "A03:2021-Injection",
            "desc": "Eval ejecuta código arbitrario en JS.",
            "fix": "Evite eval. Use JSON.parse o alternativas seguras."
        },

        # --- Java ---
        r'Runtime\.getRuntime\(\)\.exec': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Ejecución directa de comandos del sistema.",
            "fix": "Use 'ProcessBuilder' y evite pasar argumentos sin validar."
        },
        r'(?i)Statement\s*=\s*.*createStatement': {
            "type": "SQL Injection Risk", "severity": "Medium",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "El uso de 'Statement' puede llevar a inyecciones SQL si se concatenan parámetros.",
            "fix": "Use 'PreparedStatement' con parámetros '?'."
        },
        r'(?i)\.executeQuery\s*\(.*[\+]': {
            "type": "SQL Injection", "severity": "Critical",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "Concatenación detectada en consulta SQL.",
            "fix": "Use 'PreparedStatement' para evitar inyecciones SQL."
        },
        r'MessageDigest\.getInstance\(\"MD5\"\)': {
            "type": "Weak Cryptography", "severity": "Medium",
            "cwe": "CWE-327", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "MD5 es un algoritmo de hash obsoleto.",
            "fix": "Use SHA-256 o superior."
        },
        r'new\s+Random\(\)': {
            "type": "Insecure Randomness", "severity": "Low",
            "cwe": "CWE-330", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "'java.util.Random' no es criptográficamente seguro.",
            "fix": "Use 'java.security.SecureRandom' para tokens o claves."
        },

        # --- C# (.NET) ---
        r'SqlCommand\s*\(.*[\+]': {
            "type": "SQL Injection", "severity": "Critical",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "Concatenación de cadenas en comandos SQL.",
            "fix": "Use 'SqlParameter' para parametrizar consultas."
        },
        r'Unsafe\.': {
            "type": "Unsafe Code", "severity": "Medium",
            "cwe": "CWE-111", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Uso de código no gestionado/inseguro en C#.",
            "fix": "Evite bloques 'unsafe' a menos que sea estrictamente necesario."
        },
        r'ValidateInput\s*=\s*false': {
            "type": "XSS Protection Disabled", "severity": "High",
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Deshabilitar la validación de entrada en ASP.NET permite XSS.",
            "fix": "Habilite la validación de entrada."
        },

        # --- Go (Golang) ---
        r'fmt\.Sprintf\(.*SELECT': {
            "type": "SQL Injection", "severity": "High",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "Construcción de consultas SQL con Sprintf.",
            "fix": "Use argumentos posicionales ($1, $2) en 'db.Query'."
        },
        r'os\.Exec': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Ejecución de comandos del sistema.",
            "fix": "Valide estrictamente la entrada antes de pasarla a os.Exec."
        },
        r'unsafe\.Pointer': {
            "type": "Memory Safety", "severity": "Medium",
            "cwe": "CWE-119", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Uso de punteros inseguros en Go.",
            "fix": "Evite el paquete 'unsafe' para garantizar la seguridad de memoria."
        },

        # --- Ruby ---
        r'eval\(': {
            "type": "Code Injection", "severity": "Critical",
            "cwe": "CWE-95", "owasp": "A03:2021-Injection",
            "desc": "Ejecución dinámica de código en Ruby.",
            "fix": "Evite 'eval'. Use alternativas seguras."
        },
        r'system\(': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Ejecución de comandos del sistema.",
            "fix": "Use 'exec' con lista de argumentos, no string."
        },
        r'params\[:.*\]\.html_safe': {
            "type": "XSS Risk", "severity": "High",
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Marcar entrada de usuario como 'html_safe' permite XSS.",
            "fix": "Nunca use 'html_safe' en entrada de usuario sin sanitizar."
        },

        # --- PHP ---
        r'shell_exec\(': {
            "type": "Command Injection", "severity": "High",
            "cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "desc": "Ejecuta comandos en el servidor.",
            "fix": "Deshabilite esta función en php.ini si no es necesaria."
        },
        r'eval\(': {
            "type": "Code Injection", "severity": "Critical",
            "cwe": "CWE-95", "owasp": "A03:2021-Injection",
            "desc": "Ejecución de código PHP arbitrario.",
            "fix": "Evite 'eval' a toda costa."
        },
        r'mysql_query\(': {
            "type": "SQL Injection / Deprecated", "severity": "High",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "Funciones 'mysql_*' están obsoletas e inseguras.",
            "fix": "Use PDO o MySQLi con Prepared Statements."
        },

        # --- Cryptography (General) ---
        r'MD5\(': {
            "type": "Weak Cryptography", "severity": "Medium",
            "cwe": "CWE-327", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "MD5 está roto y es vulnerable a colisiones.",
            "fix": "Use algoritmos modernos como SHA-256 o SHA-3."
        },
        r'AES/ECB': {
            "type": "Weak Encryption Mode", "severity": "High",
            "cwe": "CWE-327", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "El modo ECB no oculta patrones en los datos.",
            "fix": "Use modos autenticados como AES-GCM o AES-CBC con IV aleatorio."
        },

        # --- Secrets (General) ---
        r'(?i)api_key\s*=\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]': {
            "type": "Hardcoded Secret", "severity": "Critical",
            "cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures",
            "desc": "Parece haber una API Key hardcodeada en el código.",
            "fix": "Mueva las credenciales a variables de entorno o un gestor de secretos."
        },
        r'(?i)password\s*=\s*[\'"][^\'"]+[\'"]': {
            "type": "Hardcoded Password", "severity": "High",
            "cwe": "CWE-798", "owasp": "A07:2021-Identification and Authentication Failures",
            "desc": "Contraseña en texto plano detectada.",
            "fix": "Nunca guarde contraseñas en el código fuente."
        },
        r'-----BEGIN PRIVATE KEY-----': {
            "type": "Private Key Leak", "severity": "Critical",
            "cwe": "CWE-312", "owasp": "A07:2021-Identification and Authentication Failures",
            "desc": "Clave privada RSA/DSA detectada en el código.",
            "fix": "Elimine la clave inmediatamente y rótela."
        },
        
        # --- SQL Injection (General) ---
        r'(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+.*\w|\w.*\+)': {
            "type": "SQL Injection", "severity": "High",
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "Concatenación de cadenas en consultas SQL.",
            "fix": "Use consultas parametrizadas (Prepared Statements) o un ORM."
        }
    }

    for i, line in enumerate(lines):
        line_num = i + 1
        for pattern, info in knowledge_base.items():
            if re.search(pattern, line):
                findings.append({
                    "line": line_num,
                    "content": line.strip()[:100], # Truncate long lines
                    "type": info["type"],
                    "severity": info["severity"],
                    "cwe": info.get("cwe", "N/A"),
                    "owasp": info.get("owasp", "N/A"),
                    "description": info["desc"],
                    "remediation": info["fix"]
                })

    return findings

def count_dangerous_calls(code):
    """Counts occurrences of known dangerous functions (C, Python, Java)."""
    return len(get_dangerous_details(code))

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
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from sample.data_loader import load_data
    df = load_data()
    X_train, X_test, y_train, y_test = preprocess_data(df)
    X_train_vec, X_test_vec = extract_features(X_train, X_test)
    print(f"Training features shape: {X_train_vec.shape}")
    print(f"Testing features shape: {X_test_vec.shape}")
