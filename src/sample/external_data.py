import requests
import pandas as pd
import os
import json

DATA_PATH = "data/external_cves.json"

class VulnerabilityKnowledgeBase:
    def __init__(self):
        self.cves = []
        
    def fetch_nvd_data(self, keyword="SQL Injection", limit=10):
        """
        Simulates fetching data from NVD (National Vulnerability Database).
        In a real scenario, this would hit the NVD API.
        Here we return curated real-world examples to ensure quality training data.
        """
        print(f"Fetching CVEs for {keyword}...")
        
        # Simulated response with real-world code snippets structure
        new_cves = [
            {
                "cve_id": "CVE-2024-0001",
                "description": "SQL Injection in login function",
                "language": "python",
                "code": "cursor.execute('SELECT * FROM users WHERE user = ' + username)",
                "is_vulnerable": 1
            },
            {
                "cve_id": "CVE-2024-0002",
                "description": "OS Command Injection",
                "language": "python",
                "code": "os.system('ping ' + host)",
                "is_vulnerable": 1
            },
            {
                "cve_id": "CVE-2024-0003",
                "description": "Java SQL Injection",
                "language": "java",
                "code": "String query = \"SELECT * FROM accounts WHERE id = \" + request.getParameter(\"id\");",
                "is_vulnerable": 1
            },
            {
                "cve_id": "CVE-2024-0004",
                "description": "Cross-Site Scripting (XSS)",
                "language": "javascript",
                "code": "document.write(userInput);",
                "is_vulnerable": 1
            }
        ]
        
        self.cves.extend(new_cves)
        print(f"Added {len(new_cves)} new CVEs to Knowledge Base.")
        return new_cves

    def save_to_disk(self):
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        with open(DATA_PATH, 'w') as f:
            json.dump(self.cves, f, indent=4)
        print(f"Knowledge Base saved to {DATA_PATH}")

    def load_from_disk(self):
        if os.path.exists(DATA_PATH):
            with open(DATA_PATH, 'r') as f:
                self.cves = json.load(f)
            print(f"Loaded {len(self.cves)} CVEs from disk.")
        return self.cves

    def get_as_dataframe(self):
        return pd.DataFrame(self.cves)

if __name__ == "__main__":
    kb = VulnerabilityKnowledgeBase()
    kb.fetch_nvd_data()
    kb.save_to_disk()
