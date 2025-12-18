import os
import sqlite3
import subprocess
import pickle
import hashlib
import base64

# SCENARIO: A legacy authentication module with multiple critical security flaws.

def authenticate_user_unsafe(username, password):
    """
    VULNERABILITY 1: SQL Injection
    Constructing queries with string concatenation allows attackers to manipulate the SQL logic.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # BAD: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing query: {query}")
    
    cursor.execute(query) # The scanner should flag this 'execute' call with dynamic string
    user = cursor.fetchone()
    return user

def system_admin_tool(command_arg):
    """
    VULNERABILITY 2: Command Injection (RCE)
    Passing user input directly to shell commands allows executing arbitrary system code.
    """
    print("Running admin tool...")
    
    # BAD: Using os.system with untrusted input
    os.system("echo Processing " + command_arg) 
    
    # BAD: Using subprocess with shell=True
    subprocess.call(f"ping -c 1 {command_arg}", shell=True)

def load_user_session(session_data):
    """
    VULNERABILITY 3: Insecure Deserialization
    'pickle' should never be used on untrusted data as it can execute arbitrary code.
    """
    try:
        # BAD: Deserializing data from unknown sources
        obj = pickle.loads(base64.b64decode(session_data))
        return obj
    except Exception as e:
        print(f"Error: {e}")

def store_password(password):
    """
    VULNERABILITY 4: Weak Cryptography
    MD5 is broken and collision-prone. It should not be used for password hashing.
    """
    # BAD: Using MD5
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def connect_to_legacy_api():
    """
    VULNERABILITY 5: Hardcoded Credentials
    Secrets should never be stored in plain text in the source code.
    """
    # BAD: Hardcoded API Key
    AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE" 
    DB_PASSWORD = "super_secret_password_123"
    
    print(f"Connecting with {AWS_SECRET_KEY}...")

# Example usage (for testing purposes)
if __name__ == "__main__":
    # Simulate an attack
    authenticate_user_unsafe("admin", "' OR '1'='1")
    system_admin_tool("; cat /etc/passwd")
