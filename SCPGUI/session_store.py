# session_store.py
import json
import os

CONFIG_FILE = "scp_sessions.json"

def save_session(data):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Error saving session: {e}")

def load_session():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None
