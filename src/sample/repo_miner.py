import os
import subprocess
import pandas as pd
import shutil
import sys
import time

# Add src to sys.path to import preprocessing
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modify.preprocessing import get_dangerous_details

DATA_DIR = "data/mined_repos"
OUTPUT_CSV = "data/mined_dataset.csv"

# Top Open Source Repositories by Language
# Selected for high quality and variety of code patterns
REPOS = {
    # Python
    "requests": "https://github.com/psf/requests.git",
    "flask": "https://github.com/pallets/flask.git",
    "django": "https://github.com/django/django.git",
    
    # JavaScript / TypeScript
    "react": "https://github.com/facebook/react.git",
    "node": "https://github.com/nodejs/node.git",
    "typescript": "https://github.com/microsoft/TypeScript.git",
    
    # Java
    "guava": "https://github.com/google/guava.git",
    "spring-boot": "https://github.com/spring-projects/spring-boot.git",
    "elasticsearch": "https://github.com/elastic/elasticsearch.git",
    
    # C / C++
    "linux-kernel-stable": "https://github.com/gregkh/linux.git", # Smaller mirror if possible, or limit depth
    "redis": "https://github.com/redis/redis.git",
    "tensorflow": "https://github.com/tensorflow/tensorflow.git",
    
    # Go
    "kubernetes": "https://github.com/kubernetes/kubernetes.git",
    "docker": "https://github.com/moby/moby.git",
    "go-ethereum": "https://github.com/ethereum/go-ethereum.git",
    
    # Ruby
    "rails": "https://github.com/rails/rails.git",
    "gitlab": "https://github.com/gitlabhq/gitlabhq.git",
    
    # C#
    "dotnet-runtime": "https://github.com/dotnet/runtime.git",
    "powershell": "https://github.com/PowerShell/PowerShell.git",
    
    # Swift
    "swift": "https://github.com/apple/swift.git",
    "alamofire": "https://github.com/Alamofire/Alamofire.git"
}

def clone_repo(name, url):
    """Clones a repository to the data directory."""
    target_dir = os.path.join(DATA_DIR, name)
    
    if os.path.exists(target_dir):
        print(f"Repo {name} already exists. Skipping clone.")
        return target_dir
        
    print(f"Cloning {name} from {url}...")
    try:
        # Depth 1 to save space and time
        subprocess.check_call(["git", "clone", "--depth", "1", url, target_dir])
        return target_dir
    except Exception as e:
        print(f"Error cloning {name}: {e}")
        return None

def mine_files(repo_dir, repo_name):
    """Walks through the repo, extracts code, and auto-labels it."""
    data = []
    extensions = {".py", ".java", ".c", ".cpp", ".h", ".js", ".ts", ".tsx", ".go", ".rb", ".cs", ".swift"}
    
    print(f"Scanning {repo_name}...")
    file_count = 0
    vuln_count = 0
    
    for root, dirs, files in os.walk(repo_dir):
        # Skip hidden and test directories to reduce noise
        dirs[:] = [d for d in dirs if not d.startswith('.') and 'test' not in d.lower()]
        
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in extensions:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        
                        # Skip tiny files or huge files
                        if len(content) < 50 or len(content) > 100000:
                            continue
                            
                        # Weak Supervision: Auto-labeling
                        # Use our Knowledge Base to detect potential vulnerabilities
                        findings = get_dangerous_details(content)
                        is_vulnerable = 1 if len(findings) > 0 else 0
                        
                        # Extract CWEs if vulnerable
                        cwe_ids = list(set([f.get('cwe', 'N/A') for f in findings])) if is_vulnerable else ["None"]
                        
                        data.append({
                            "code": content,
                            "is_vulnerable": is_vulnerable,
                            "cwe_id": ";".join(cwe_ids),
                            "source": repo_name,
                            "language": ext
                        })
                        
                        file_count += 1
                        if is_vulnerable:
                            vuln_count += 1
                            
                except Exception:
                    pass
                    
    print(f"  - Processed: {file_count} files")
    print(f"  - Potential Vulnerabilities: {vuln_count}")
    return data

def run_miner():
    print("Starting Massive Repository Miner...")
    print("Note: This process requires significant internet bandwidth and disk space.")
    os.makedirs(DATA_DIR, exist_ok=True)
    
    all_data = []
    
    for name, url in REPOS.items():
        repo_dir = clone_repo(name, url)
        if repo_dir:
            repo_data = mine_files(repo_dir, name)
            all_data.extend(repo_data)
            
            # Optional: Delete repo after mining to save space
            # shutil.rmtree(repo_dir)
            
    if all_data:
        df = pd.DataFrame(all_data)
        
        # Basic Stats
        print("\n--- Mining Stats ---")
        print(f"Total Samples: {len(df)}")
        print(df['is_vulnerable'].value_counts())
        print(df['language'].value_counts())
        
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\nMined dataset saved to {OUTPUT_CSV}")
    else:
        print("No data mined.")

if __name__ == "__main__":
    run_miner()
