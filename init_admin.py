#!/usr/bin/env python3
"""Initialize admin user with hashed password for OpenShift deployment."""
import json
import os
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Run: pip install bcrypt")
    exit(1)

USERS_DB = Path("users.json")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def create_admin():
    """Create initial admin user from environment variables."""
    username = os.environ.get("DOCLING_UI_USERNAME")
    password = os.environ.get("DOCLING_UI_PASSWORD")
    
    if not username or not password:
        print("ERROR: Set DOCLING_UI_USERNAME and DOCLING_UI_PASSWORD environment variables")
        exit(1)
    
    # Create hashed user record
    admin_user = {
        "username": username,
        "password": hash_password(password),
        "role": "admin"
    }
    
    # Write to users.json
    with open(USERS_DB, "w") as f:
        json.dump([admin_user], f, indent=2)
    
    # Set restrictive permissions
    os.chmod(USERS_DB, 0o600)
    
    print(f"✓ Admin user '{username}' created with hashed password")
    print(f"✓ users.json created with permissions 0600 (owner read/write only)")

if __name__ == "__main__":
    create_admin()
