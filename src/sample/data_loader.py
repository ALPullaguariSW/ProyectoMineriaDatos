import pandas as pd
import os
import numpy as np
import requests
import io

DATA_PATH = "data/dataset.csv"
REAL_DATA_URL = "https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv"

def generate_synthetic_data(num_samples=100):
    """Generates a synthetic dataset for demonstration purposes."""
    print("Generating synthetic dataset (Fallback)...")
    
    data = []
    
    # Vulnerable patterns (C/C++)
    vuln_patterns_c = [
        ("strcpy(dest, src);", 1, "CWE-120"),
        ("gets(buffer);", 1, "CWE-120"),
        ("sprintf(query, \"SELECT * FROM users WHERE id = '%s'\", user_id);", 1, "CWE-89"),
        ("strcat(dest, src);", 1, "CWE-120"),
        ("system(cmd);", 1, "CWE-78"),
        ("memcpy(dest, src, len);", 1, "CWE-120"),
        ("printf(user_input);", 1, "CWE-134"),
        ("char *p = malloc(10); free(p); free(p);", 1, "CWE-415"),
        ("int *p = NULL; *p = 1;", 1, "CWE-476"),
    ]
    
    # Vulnerable patterns (Python - OWASP)
    vuln_patterns_py = [
        ("def login(user): query = 'SELECT * FROM users WHERE name = ' + user", 1, "CWE-89"),
        ("def exec_cmd(cmd): os.system(cmd)", 1, "CWE-78"),
        ("def load_yaml(data): yaml.load(data)", 1, "CWE-502"),
        ("eval(user_input)", 1, "CWE-94"),
        ("pickle.loads(data)", 1, "CWE-502"),
        ("subprocess.call(cmd, shell=True)", 1, "CWE-78"),
        ("input(prompt)", 1, "CWE-20"), # Python 2 input() is eval()
    ]

    # Vulnerable patterns (Java - OWASP)
    vuln_patterns_java = [
        ("String query = \"SELECT * FROM users WHERE name = \" + user;", 1, "CWE-89"),
        ("Runtime.getRuntime().exec(cmd);", 1, "CWE-78"),
        ("ObjectInputStream ois = new ObjectInputStream(is); ois.readObject();", 1, "CWE-502"),
    ]

    vuln_patterns = (vuln_patterns_c + vuln_patterns_py + vuln_patterns_java) * 50
    
    # Safe patterns
    safe_patterns = [
        ("def login(user): query = 'SELECT * FROM users WHERE name = ?', (user,)", 0, "None"),
        ("def exec_cmd(cmd): subprocess.run(cmd, shell=False)", 0, "None"),
        ("def load_yaml(data): yaml.safe_load(data)", 0, "None"),
        ("strncpy(dest, src, sizeof(dest));", 0, "None"),
        ("fgets(buffer, sizeof(buffer), stdin);", 0, "None"),
        ("snprintf(buf, sizeof(buf), \"Safe string\");", 0, "None"),
        ("printf(\"Hello World\");", 0, "None"),
        ("int a = 5; int b = 6; int c = a + b;", 0, "None"),
        ("if (x > 0) { y = x; }", 0, "None"),
        ("for (int i=0; i<10; i++) { sum += i; }", 0, "None"),
        ("std::string s = \"safe\";", 0, "None"),
        ("cout << \"Hello\" << endl;", 0, "None"),
        ("PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");", 0, "None"),
    ] * 50
    
    for _ in range(num_samples // 2):
        item = vuln_patterns[np.random.randint(0, len(vuln_patterns))]
        data.append(item)
        
    for _ in range(num_samples // 2):
        item = safe_patterns[np.random.randint(0, len(safe_patterns))]
        data.append(item)
        
    df = pd.DataFrame(data, columns=["code", "is_vulnerable", "cwe_id"])
    
    # Integrate External Knowledge Base
    try:
        from external_data import VulnerabilityKnowledgeBase
        kb = VulnerabilityKnowledgeBase()
        # Fetch if empty, or just load
        kb.fetch_nvd_data() 
        df_ext = kb.get_as_dataframe()
        if not df_ext.empty:
            print(f"Merging {len(df_ext)} external CVEs into dataset...")
            # Ensure columns match
            df_ext = df_ext[['code', 'is_vulnerable']]
            df_ext['cwe_id'] = "External-CVE"
            df = pd.concat([df, df_ext], ignore_index=True)
    except ImportError:
        print("External data module not found, skipping.")
    except Exception as e:
        print(f"Error merging external data: {e}")
    
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    df.to_csv(DATA_PATH, index=False)
    print(f"Saved synthetic dataset to {DATA_PATH}")
    return df

def download_real_data():
    """Attempts to download real datasets from GitHub."""
    dfs = []
    
    # 1. ZeoVan Dataset (C/C++)
    print(f"Attempting to download ZeoVan dataset from {REAL_DATA_URL}...")
    try:
        response = requests.get(REAL_DATA_URL, timeout=10)
        if response.status_code == 200:
            print("Download successful. Processing...")
            content = response.content.decode('utf-8', errors='ignore')
            df = pd.read_csv(io.StringIO(content))
            
            # Heuristic mapping for ZeoVan
            if 'functionSource' in df.columns and 'vulnerability' in df.columns:
                 df = df.rename(columns={'functionSource': 'code', 'vulnerability': 'is_vulnerable'})
                 df['is_vulnerable'] = df['is_vulnerable'].apply(lambda x: 1 if str(x).lower() in ['1', 'true', 'yes', 'vulnerable'] else 0)
                 df['cwe_id'] = "N/A" # ZeoVan might not have CWEs easily accessible in this CSV
                 dfs.append(df[['code', 'is_vulnerable', 'cwe_id']])
                 print(f"Loaded ZeoVan dataset: {len(df)} samples")
    except Exception as e:
        print(f"Error downloading ZeoVan data: {e}")

    # 2. Security-Patches-Dataset (Multi-language)
    PATCHES_URL = "https://raw.githubusercontent.com/security-commits/security-patches-dataset/master/final-dataset/vulnerabilities.csv"
    print(f"Attempting to download Security-Patches-Dataset from {PATCHES_URL}...")
    try:
        response = requests.get(PATCHES_URL, timeout=15)
        if response.status_code == 200:
            print("Download successful. Processing...")
            content = response.content.decode('utf-8', errors='ignore')
            df = pd.read_csv(io.StringIO(content))
            
            # This dataset usually has 'code' (patch) and 'cwe_id'. 
            # Note: It might contain diffs. We need the 'vulnerable_code' if available, or we treat the diff as the sample.
            # Let's inspect columns if we could, but for now we assume standard names or map them.
            # Common columns: 'commit_message', 'code', 'vuln_type'
            # If it's not straightforward, we might need to skip or adapt.
            # Let's assume a generic 'code' column exists or we try to find it.
            
            # Fallback: If we can't find 'code', we look for 'patch' or 'diff'
            code_col = None
            for col in ['code', 'patch', 'diff', 'content']:
                if col in df.columns:
                    code_col = col
                    break
            
            if code_col:
                df = df.rename(columns={code_col: 'code'})
                df['is_vulnerable'] = 1 # These are all vulnerabilities
                if 'cwe' in df.columns:
                    df = df.rename(columns={'cwe': 'cwe_id'})
                else:
                    df['cwe_id'] = "Unknown"
                
                dfs.append(df[['code', 'is_vulnerable', 'cwe_id']])
                print(f"Loaded Security-Patches dataset: {len(df)} samples")
            else:
                print("Could not find code column in Security-Patches dataset.")
    except Exception as e:
        print(f"Error downloading Security-Patches data: {e}")

    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return None

def load_data():
    """Loads the dataset, merging synthetic, downloaded, and mined data."""
    dfs = []
    
    # 1. Existing Synthetic/Downloaded Data
    if os.path.exists(DATA_PATH):
        print(f"Loading base dataset from {DATA_PATH}")
        dfs.append(pd.read_csv(DATA_PATH))
    else:
        # Try download or generate
        df_base = download_real_data()
        if df_base is None:
            df_base = generate_synthetic_data()
        dfs.append(df_base)

    # 2. Mined Real Data (Massive)
    mined_path = "data/mined_dataset.csv"
    if os.path.exists(mined_path):
        print(f"Loading mined real dataset from {mined_path}")
        try:
            df_mined = pd.read_csv(mined_path)
            # Ensure compatibility
            if 'cwe_id' not in df_mined.columns:
                df_mined['cwe_id'] = "None"
            
            # Keep only relevant columns
            df_mined = df_mined[['code', 'is_vulnerable', 'cwe_id']]
            dfs.append(df_mined)
        except Exception as e:
            print(f"Error loading mined data: {e}")

    # Merge all sources
    if not dfs:
        return pd.DataFrame(columns=["code", "is_vulnerable", "cwe_id"])
        
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Deduplicate
    initial_len = len(full_df)
    full_df.drop_duplicates(subset=['code'], inplace=True)
    print(f"Merged dataset size: {len(full_df)} (Dropped {initial_len - len(full_df)} duplicates)")
    
    return full_df

if __name__ == "__main__":
    df = load_data()
    print(df.head())
    print(df["is_vulnerable"].value_counts())
