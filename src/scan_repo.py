import os
import sys
import shutil
import subprocess
import argparse
from predict import load_model, scan_directory, generate_report
from report_generator import generate_html_report

import stat

def remove_readonly(func, path, excinfo):
    """
    Error handler for shutil.rmtree to remove read-only files (like .git objects) on Windows.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

def scan_external_repo(repo_url):
    """
    Clones a repo, scans it, generates reports, and cleans up.
    """
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    temp_dir = f"temp_scan_{repo_name}"
    
    print(f"\n🚀 Starting Security Scan for: {repo_name}")
    print(f"🔗 URL: {repo_url}")
    
    # 1. Clone Repository
    if os.path.exists(temp_dir):
        print(f"🧹 Removing existing temp directory: {temp_dir}")
        shutil.rmtree(temp_dir, onerror=remove_readonly)
    
    print("⬇️  Cloning repository (shallow clone)...")
    try:
        subprocess.check_call(["git", "clone", "--depth", "1", repo_url, temp_dir])
    except subprocess.CalledProcessError:
        print("❌ Error: Failed to clone repository. Check the URL and your internet connection.")
        return

    # 2. Load Model
    print("🧠 Loading AI Model...")
    try:
        model, vectorizer = load_model()
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return

    # 3. Scan Directory
    print(f"🔍 Scanning files in {temp_dir}...")
    results = scan_directory(temp_dir, model, vectorizer)
    
    # 4. Generate Reports
    json_report = f"report_{repo_name}.json"
    html_report = f"report_{repo_name}.html"
    
    print("📊 Generating reports...")
    generate_report(results, output_file=json_report)
    generate_html_report(scan_results_file=json_report, output_file=html_report)
    
    # 5. Cleanup
    print("🧹 Cleaning up temporary files...")
    try:
        shutil.rmtree(temp_dir, onerror=remove_readonly)
    except Exception as e:
        print(f"⚠️ Warning: Could not fully remove temp dir: {e}")

    print(f"\n✅ Scan Complete!")
    print(f"📄 JSON Report: {os.path.abspath(json_report)}")
    print(f"🌐 HTML Report: {os.path.abspath(html_report)}")
    
    # Open HTML report
    if sys.platform == 'win32':
        os.startfile(os.path.abspath(html_report))
    elif sys.platform == 'darwin':
        subprocess.call(('open', html_report))
    else:
        subprocess.call(('xdg-open', html_report))

if __name__ == "__main__":
    print("=============================================")
    print("   🛡️  AI-Powered Security Scanner  🛡️")
    print("=============================================")
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("👉 Enter GitHub Repository URL to scan: ").strip()
    
    if url:
        scan_external_repo(url)
    else:
        print("❌ No URL provided.")
