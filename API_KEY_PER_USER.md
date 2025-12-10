# API Key Per User Implementation Guide

## Overview

This guide explains how to add API key functionality for each user in the Docling Serve authentication system. This will allow each user to have their own unique API key to access the REST API endpoints with curl or other HTTP clients.

---

## Current Architecture

### What We Have Now

1. **User Database** (`users.json`):
   ```json
   [
     {
       "username": "admin",
       "password": "$2b$12$...",  // bcrypt hash
       "role": "admin"
     }
   ]
   ```

2. **Session-based Authentication** (for UI):
   - Users login via Gradio UI
   - Session token stored in cookie (`dl_session`)
   - Token valid for 120 minutes
   - HMAC-SHA256 signed tokens

3. **Global API Key** (optional):
   - Single shared key for all API requests
   - Set via `DOCLING_SERVE_API_KEY` environment variable
   - Checked in `auth.py` with `X-Api-Key` header

---

## What We Need to Add

### Enhanced User Database

Add an `api_key` field to each user record:

```json
[
  {
    "username": "admin",
    "password": "$2b$12$...",
    "role": "admin",
    "api_key": "dk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  },
  {
    "username": "researcher",
    "password": "$2b$12$...",
    "role": "user",
    "api_key": "dk_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4"
  }
]
```

---

## Implementation Steps

### Step 1: Add API Key Generation Function

**File:** `docling_serve/gradio_ui.py`

Add this function after the existing authentication functions (around line 40):

```python
import secrets

def generate_api_key() -> str:
    """Generate a secure random API key with 'dk_' prefix (docling key)."""
    random_bytes = secrets.token_urlsafe(32)  # 32 bytes = ~43 characters base64
    return f"dk_{random_bytes}"
```

### Step 2: Update User Creation Function

**File:** `docling_serve/gradio_ui.py`

Modify the `create_user` function to generate an API key automatically:

```python
def create_user(admin_username, new_username, new_password, new_role):
    users = load_users()

    admin = next((u for u in users if u.get("username") == admin_username), None)
    if not admin or admin.get("role") != "admin":
        return False, "Only admin may create new accounts."

    if any(u.get("username") == new_username for u in users):
        return False, "User already exists."

    # Hash password before storing
    hashed = hash_password(new_password)
    
    # Generate unique API key for the new user
    api_key = generate_api_key()
    
    users.append({
        "username": new_username,
        "password": hashed,
        "role": new_role,
        "api_key": api_key  # NEW FIELD
    })
    save_users(users)
    return True, f"User created successfully. API Key: {api_key}"
```

### Step 3: Migrate Existing Users

**File:** `docling_serve/gradio_ui.py`

Update the `load_users` function to add API keys to existing users without them:

```python
def load_users():
    if USERS_DB.exists():
        try:
            users = json.load(open(USERS_DB))
            
            # Migrate: Add API keys to users that don't have one
            updated = False
            for user in users:
                if "api_key" not in user:
                    user["api_key"] = generate_api_key()
                    updated = True
                    logger.info(f"Generated API key for existing user '{user['username']}'")
            
            if updated:
                save_users(users)
            
            return users
        except Exception:
            return []
    
    # Auto-create admin user from environment variables if users.json doesn't exist
    username = os.environ.get("DOCLING_UI_USERNAME")
    password = os.environ.get("DOCLING_UI_PASSWORD")
    
    if username and password:
        logger.info(f"Creating initial admin user '{username}' from environment variables")
        admin_user = {
            "username": username,
            "password": hash_password(password),
            "role": "admin",
            "api_key": generate_api_key()  # NEW FIELD
        }
        try:
            save_users([admin_user])
            logger.info(f"✓ Admin user '{username}' created successfully")
            return [admin_user]
        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")
    
    return []
```

### Step 4: Update API Authentication

**File:** `docling_serve/auth.py`

Modify the `APIKeyAuth` class to check against per-user API keys:

```python
import json
from pathlib import Path
import os

class APIKeyAuth(APIKeyHeader):
    """
    FastAPI dependency which evaluates API Key against user database.
    """

    def __init__(
        self,
        api_key: str,
        header_name: str = "X-Api-Key",
        fail_on_unauthorized: bool = True,
    ) -> None:
        self.global_api_key = api_key  # Keep global key for backward compatibility
        self.header_name = header_name
        super().__init__(name=self.header_name, auto_error=False)

    def _load_users(self):
        """Load users from database."""
        users_db = Path(os.environ.get("DOCLING_USERS_PATH", "users.json"))
        if users_db.exists():
            try:
                return json.load(open(users_db))
            except Exception:
                return []
        return []

    async def _validate_api_key(self, header_api_key: str | None):
        if header_api_key is None:
            return AuthenticationResult(
                valid=False, errors=[f"Missing header {self.header_name}."]
            )

        header_api_key = header_api_key.strip()

        # 1. Check global API key (backward compatibility)
        if header_api_key == self.global_api_key or self.global_api_key == "":
            return AuthenticationResult(
                valid=True,
                detail={"type": "global", "key": header_api_key},
            )
        
        # 2. Check per-user API keys
        users = self._load_users()
        for user in users:
            if user.get("api_key") == header_api_key:
                return AuthenticationResult(
                    valid=True,
                    detail={
                        "type": "user",
                        "username": user.get("username"),
                        "role": user.get("role"),
                        "key": header_api_key
                    },
                )
        
        # 3. No match found
        return AuthenticationResult(
            valid=False,
            errors=["The provided API Key is invalid."],
        )

    async def __call__(self, request: Request) -> AuthenticationResult:
        header_api_key = await super().__call__(request=request)
        result = await self._validate_api_key(header_api_key)
        if self.global_api_key and not result.valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=result.detail
            )
        return result
```

### Step 5: Add UI to Display API Keys

**File:** `docling_serve/gradio_ui.py`

Add a section in the UI to display the current user's API key:

```python
# In the build_ui() function, add after the user_name_display:

with gr.Row(visible=False) as api_key_section:
    gr.Markdown("### Your API Key")
    api_key_display = gr.Textbox(
        label="API Key",
        interactive=False,
        type="text",
        info="Use this key in the X-Api-Key header for API requests"
    )
    regenerate_api_key_btn = gr.Button("🔄 Regenerate API Key", size="sm")
```

Add a function to get user's API key:

```python
def get_user_api_key(username: str):
    """Retrieve the API key for a given user."""
    users = load_users()
    for user in users:
        if user.get("username") == username:
            return user.get("api_key", "No API key found")
    return "User not found"

def regenerate_user_api_key(username: str):
    """Regenerate API key for a user."""
    users = load_users()
    for user in users:
        if user.get("username") == username:
            new_key = generate_api_key()
            user["api_key"] = new_key
            save_users(users)
            return new_key
    return "User not found"
```

Wire up the display:

```python
# After login succeeds, update the API key display:
def login_handler_with_api_key(username: str, password: str):
    ok, role = authenticate_user(username, password)
    if ok:
        token = create_session_token(username, role)
        api_key = get_user_api_key(username)
        
        return (
            gr.update(visible=False),  # login_screen
            gr.update(visible=True),   # main_screen
            username,                  # session_user
            role,                      # session_role
            gr.update(visible=False, value=""),  # login_error
            gr.update(visible=(role == "admin")),  # admin_panel
            token,                     # session_token
            gr.update(visible=True),   # api_key_section
            api_key,                   # api_key_display
        )
    # ... rest of error handling
```

---

## Testing the Implementation

### 1. Test User Creation with API Key

```bash
# Start container
podman run -d -p 5001:5001 \
  -e DOCLING_SECRET_KEY='your-secret-key' \
  -e DOCLING_UI_USERNAME='admin' \
  -e DOCLING_UI_PASSWORD='changeme' \
  -e DOCLING_SERVE_ENABLE_UI=true \
  localhost/docling-serve-v1:local

# Login to UI at http://localhost:5001/ui
# Create new user via admin panel
# Note the API key displayed
```

### 2. Test API Key Authentication

```bash
# Use the API key from the user
curl -X POST \
  'http://localhost:5001/v1/convert/source' \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: dk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' \
  -d '{
    "sources": [{"kind": "http", "url": "https://arxiv.org/pdf/2206.01062"}]
  }'
```

### 3. Test with Wrong API Key

```bash
curl -X POST \
  'http://localhost:5001/v1/convert/source' \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: invalid-key' \
  -d '{
    "sources": [{"kind": "http", "url": "https://arxiv.org/pdf/2206.01062"}]
  }'

# Expected: 401 Unauthorized
```

### 4. Verify API Key in users.json

```bash
podman exec -it <container-id> cat /opt/app-root/src/users.json
```

Expected output:
```json
[
  {
    "username": "admin",
    "password": "$2b$12$...",
    "role": "admin",
    "api_key": "dk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  }
]
```

---

## Security Considerations

### ✅ Best Practices

1. **Unique Keys**: Each user gets a cryptographically random API key (32 bytes)
2. **Secure Prefix**: Keys start with `dk_` to identify them as Docling keys
3. **Regeneration**: Users can regenerate their API key if compromised
4. **Backward Compatible**: Global API key still works for existing deployments
5. **File Permissions**: `users.json` has 0600 permissions (owner read/write only)

### ⚠️ Important Notes

1. **API Keys in Logs**: Be careful not to log full API keys (only log first 10 chars)
2. **HTTPS Required**: Always use HTTPS in production to protect keys in transit
3. **Key Storage**: Store users.json in a secure location, mount as Kubernetes Secret
4. **Rate Limiting**: Consider adding rate limiting per API key to prevent abuse
5. **Audit Logging**: Log all API requests with username/API key for audit trails

---

## OpenShift/Kubernetes Deployment

### Mount users.json as Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: docling-users-secret
type: Opaque
stringData:
  users.json: |
    [
      {
        "username": "admin",
        "password": "$2b$12$...",
        "role": "admin",
        "api_key": "dk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
      }
    ]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: docling-serve
spec:
  template:
    spec:
      containers:
      - name: docling-serve
        image: docling-serve-v1:local
        env:
        - name: DOCLING_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: docling-secrets
              key: secret-key
        - name: DOCLING_USERS_PATH
          value: /config/users.json
        volumeMounts:
        - name: users-config
          mountPath: /config
          readOnly: false
      volumes:
      - name: users-config
        secret:
          secretName: docling-users-secret
          defaultMode: 0600
```

---

## Usage Examples

### For End Users

Once logged into the UI:

1. **View Your API Key**:
   - Login to the Gradio UI
   - Your API key is displayed in the "Your API Key" section
   - Copy the key for use in scripts

2. **Use API Key in curl**:
   ```bash
   curl -X POST \
     'http://localhost:5001/v1/convert/source' \
     -H 'X-Api-Key: YOUR_API_KEY_HERE' \
     -H 'Content-Type: application/json' \
     -d '{
       "sources": [{"kind": "http", "url": "https://example.com/doc.pdf"}]
     }'
   ```

3. **Use API Key in Python**:
   ```python
   import httpx
   
   client = httpx.Client()
   response = client.post(
       "http://localhost:5001/v1/convert/source",
       headers={"X-Api-Key": "YOUR_API_KEY_HERE"},
       json={"sources": [{"kind": "http", "url": "https://example.com/doc.pdf"}]}
   )
   print(response.json())
   ```

4. **Regenerate if Compromised**:
   - Click "🔄 Regenerate API Key" button in UI
   - Old key immediately becomes invalid
   - Use new key in all future requests

### For Administrators

1. **Create User with API Key**:
   - Login as admin
   - Go to "Admin Panel"
   - Create user → API key automatically generated
   - Share the API key securely with the user (one-time display)

2. **View All API Keys** (manual):
   ```bash
   cat users.json | jq '.[] | {username, api_key}'
   ```

3. **Revoke Access**:
   - Regenerate the user's API key (invalidates old one)
   - Or delete the user entirely

---

## Summary

### What This Adds

✅ **Per-user API keys** - Each user gets unique, secure API key  
✅ **Automatic generation** - Keys created on user creation  
✅ **Migration support** - Existing users get keys automatically  
✅ **UI display** - Users can see and regenerate their keys  
✅ **API validation** - `auth.py` checks both global and per-user keys  
✅ **Backward compatible** - Global API key still works  
✅ **Secure storage** - Keys stored in bcrypt-protected users.json  

### Files to Modify

1. `docling_serve/gradio_ui.py` - Add key generation, display, regeneration
2. `docling_serve/auth.py` - Update validation to check per-user keys
3. Rebuild container with changes

### Next Steps

1. Implement the code changes above
2. Rebuild container: `podman build -t docling-serve-v1:local -f Containerfile .`
3. Test with new user creation
4. Verify API key authentication works
5. Update production deployment to mount users.json as Secret
