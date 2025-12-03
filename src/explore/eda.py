import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from data_loader import load_data

OUTPUT_DIR = "reports/figures"

def perform_eda():
    """Performs basic exploratory data analysis."""
    df = load_data()
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Class Distribution
    plt.figure(figsize=(6, 4))
    sns.countplot(x="is_vulnerable", data=df)
    plt.title("Distribution of Vulnerable vs Safe Code")
    plt.xlabel("Is Vulnerable (0=Safe, 1=Vulnerable)")
    plt.ylabel("Count")
    plt.savefig(os.path.join(OUTPUT_DIR, "class_distribution.png"))
    print(f"Saved class distribution plot to {OUTPUT_DIR}/class_distribution.png")
    
    # CWE Distribution (for vulnerable only)
    if "cwe_id" in df.columns:
        plt.figure(figsize=(10, 6))
        vuln_df = df[df["is_vulnerable"] == 1]
        if not vuln_df.empty:
            sns.countplot(y="cwe_id", data=vuln_df, order=vuln_df["cwe_id"].value_counts().index)
            plt.title("Distribution of CWE IDs")
            plt.xlabel("Count")
            plt.ylabel("CWE ID")
            plt.savefig(os.path.join(OUTPUT_DIR, "cwe_distribution.png"))
            print(f"Saved CWE distribution plot to {OUTPUT_DIR}/cwe_distribution.png")

if __name__ == "__main__":
    perform_eda()
