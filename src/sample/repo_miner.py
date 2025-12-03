import os
import subprocess
import pandas as pd
import shutil

DATA_DIR = "data/mined_repos"
OUTPUT_CSV = "data/mined_dataset.csv"

# List of popular open source repos to mine (Demonstration)
# In a real "Big Data" scenario, this list would be dynamic or much larger.
REPOS = [
    "https://github.com/psf/requests.git", # Python
    "https://github.com/google/guava.git",   # Java
    # "https://github.com/torvalds/linux.git" # C (Too big for demo, commented out)
]

def clone_repo(repo_url):
    """Clones a repository to the data directory."""
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    target_dir = os.path.join(DATA_DIR, repo_name)
    
    if os.path.exists(target_dir):
        print(f"Repo {repo_name} already exists. Skipping clone.")
        return target_dir
        
    print(f"Cloning {repo_url}...")
    try:
        subprocess.check_call(["git", "clone", "--depth", "1", repo_url, target_dir])
        return target_dir
    except Exception as e:
        print(f"Error cloning {repo_url}: {e}")
        return None

def mine_files(repo_dir):
    """Walks through the repo and extracts code files."""
    data = []
    extensions = {".py", ".java", ".c", ".cpp", ".h"}
    
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in extensions:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        # Simple heuristic labeling for demo:
                        # If it contains "FIXME" or "TODO", maybe it's interesting?
                        # Or we just label everything as "0" (Safe) for now to build a background dataset.
                        # In a real miner, we would look for commit messages fixing CVEs.
                        data.append({
                            "code": content,
                            "is_vulnerable": 0, # Default to safe (background data)
                            "cwe_id": "None",
                            "source": "GitHub"
                        })
                except Exception:
                    pass
    return data

def run_miner():
    print("Starting Repository Miner...")
    os.makedirs(DATA_DIR, exist_ok=True)
    
    all_data = []
    
    for repo in REPOS:
        repo_dir = clone_repo(repo)
        if repo_dir:
            print(f"Mining {repo_dir}...")
            repo_data = mine_files(repo_dir)
            print(f"Extracted {len(repo_data)} files.")
            all_data.extend(repo_data)
            
            # Cleanup to save space (Optional)
            # shutil.rmtree(repo_dir)
            
    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"Mined data saved to {OUTPUT_CSV} with {len(df)} samples.")
    else:
        print("No data mined.")

if __name__ == "__main__":
    run_miner()
