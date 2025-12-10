# Security Hardening Summary

## Changes Made for OpenShift Production Deployment

### 1. ✅ **Containerfile Updates**
- Added secure configuration directory (`/opt/app-root/src/config`)
- Set restrictive directory permissions (700)
- Added `PYTHONHASHSEED=random` for additional randomization
- Updated comments for secret/config mounting via OpenShift
- Non-root user (1001) runs the container

**File**: `Containerfile`

### 2. ✅ **Code Security Improvements**

#### gradio_ui.py Changes:

**a) Bcrypt Password Hashing**
```python
from bcrypt import hashpw, gensalt, checkpw

def hash_password(password: str) -> str:
    """Hash password with bcrypt (12 rounds)."""
    return hashpw(password.encode(), gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Safely verify password without exposing plaintext."""
    return checkpw(password.encode(), hashed.encode())
```

**b) Updated Authentication**
```python
def authenticate_user(username, password):
    users = load_users()
    for u in users:
        if u.get("username") == username:
            if verify_password(password, u.get("password", "")):
                return True, u.get("role")
    return False, None
```

**c) Configurable Users Path**
```python
# Support OpenShift Secret/ConfigMap mounting
USERS_DB = Path(os.environ.get("DOCLING_USERS_PATH", "users.json"))
```

**d) Cookie Security**
- HttpOnly flag (prevents JavaScript access)
- Secure flag (HTTPS only)
- SameSite=Strict (prevents CSRF)

### 3. ✅ **Deployment Documentation**

Created `SECURITY_DEPLOYMENT.md` with:

- **OpenShift Secret Setup**: Step-by-step guide for creating secrets
- **Deployment YAML**: Complete secure deployment configuration
- **RBAC Setup**: Proper role-based access control
- **Security Checklist**: Pre-deployment verification
- **Secret Rotation**: Procedures for rotating keys/passwords
- **Monitoring & Auditing**: Log aggregation setup
- **Troubleshooting**: Common issues and solutions

### 4. ✅ **Validation Completed**

✓ Dev server starts with security updates
✓ Bcrypt password hashing works
✓ HMAC-signed tokens validated
✓ 120-minute session TTL enforced
✓ No plaintext passwords in code
✓ Config directory properly restricted

## Security Checklist for OpenShift

### Before Deployment
- [ ] Create `users.json` with hashed passwords (use script in SECURITY_DEPLOYMENT.md)
- [ ] Create OpenShift Secret for users: `docling-users`
- [ ] Create OpenShift Secret for session key: `docling-session-key`
- [ ] Generate strong `DOCLING_SECRET_KEY` (32+ bytes)
- [ ] Set `DOCLING_USERS_PATH=/config/users.json` in deployment
- [ ] Enable HTTPS/TLS on Route
- [ ] Set resource limits (memory, CPU)
- [ ] Configure health checks
- [ ] Setup RBAC and ServiceAccount

### Deployment Verification
- [ ] Pod starts with non-root user (1001)
- [ ] Secrets are mounted read-only
- [ ] File permissions are correct: `users.json` = 600
- [ ] Login works with bcrypt-hashed passwords
- [ ] Sessions persist across page refresh (120 min)
- [ ] Logout clears session properly
- [ ] HTTPS is enforced

### Post-Deployment
- [ ] Monitor login failures
- [ ] Setup log aggregation
- [ ] Enable secret encryption at rest
- [ ] Schedule secret rotation (annual)
- [ ] Perform security scan of image
- [ ] Document any customizations

## Files Modified

1. **Containerfile**
   - Added secure config directory
   - Added `PYTHONHASHSEED=random`
   - Added comments for secret mounting

2. **docling_serve/gradio_ui.py**
   - Added bcrypt import
   - Updated password hashing/verification
   - Made users path configurable via `DOCLING_USERS_PATH`
   - Cookies now have Secure, HttpOnly, SameSite=Strict flags

3. **SECURITY_DEPLOYMENT.md** (NEW)
   - Complete deployment guide
   - OpenShift-specific instructions
   - Secret management procedures
   - Troubleshooting guide

## Environment Variables for Production

Required for OpenShift deployment:

```bash
# Session key (from OpenShift Secret)
DOCLING_SECRET_KEY=<32-byte-base64-encoded-key>

# Path to users.json mounted from Secret
DOCLING_USERS_PATH=/config/users.json

# Enable UI
DOCLING_SERVE_ENABLE_UI=true

# Optional: Custom port
DOCLING_SERVE_PORT=5001

# Optional: API host
DOCLING_SERVE_API_HOST=0.0.0.0
```

## Quick Start - OpenShift Deployment

```bash
# 1. Create users with hashed passwords
python3 << 'EOF'
import json
from pathlib import Path
from bcrypt import hashpw, gensalt

def hash_password(password: str) -> str:
    return hashpw(password.encode(), gensalt()).decode()

users = [
    {
        "username": "admin",
        "password": hash_password("your-secure-password"),
        "role": "admin"
    }
]

with open("users.json", "w") as f:
    json.dump(users, f, indent=2)

print("✓ users.json created with hashed passwords")
EOF

# 2. Create secrets
oc create secret generic docling-users --from-file=users.json
oc create secret generic docling-session-key --from-literal=secret-key=$(head -c 32 /dev/urandom | base64)

# 3. Deploy with SECURITY_DEPLOYMENT.md yaml
oc apply -f deployment.yaml

# 4. Verify
oc get pods -l app=docling-serve
oc logs deployment/docling-serve
```

## Security Best Practices Summary

✅ **Authentication**: Bcrypt password hashing (12 rounds)
✅ **Session Management**: HMAC-SHA256 signed tokens, 120-min TTL
✅ **Secrets**: OpenShift Secret/ConfigMap mounting
✅ **Transport**: HTTPS/TLS enforced via Route
✅ **Authorization**: Role-based access control (admin/user)
✅ **Container Security**: Non-root user, read-only filesystem option
✅ **Secrets Rotation**: Documented procedures
✅ **Audit Logging**: Log aggregation recommended
✅ **Network Policy**: Can be enforced via OpenShift
✅ **Resource Limits**: Configured in deployment

## Next Steps

1. **Review** `SECURITY_DEPLOYMENT.md` for complete deployment guide
2. **Create** users.json with bcrypt hashing
3. **Setup** OpenShift Secrets
4. **Deploy** using provided YAML template
5. **Monitor** logs and authentication events
6. **Schedule** security scans and secret rotation

---

**Last Updated**: December 6, 2025
**Status**: ✅ Production-Ready with Security Hardening


## Now Ready For

✅ **Development** - Working with secure defaults  
✅ **Testing** - Use `init_admin.py` to setup test users  
✅ **OpenShift Deployment** - Follow SECURITY.md guide  

## Next Steps (Recommended)

1. **Deploy to OpenShift** using guide in `SECURITY.md`
2. **Test login** with credentials set in env vars
3. **Create additional users** via admin panel
4. **Monitor logs** for authentication events
5. **Rotate secret key** quarterly (optional but recommended)

## Testing the Implementation

```bash
# Terminal 1: Start server
export DOCLING_SECRET_KEY='your-secret-key-32-chars-minimum'
export DOCLING_SERVE_ENABLE_UI=true
python -m docling_serve dev

# Terminal 2: Test with credentials
curl -X POST http://127.0.0.1:5001/ui \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Browser: Open http://127.0.0.1:5001/ui
# - Login with credentials from init_admin
# - Check browser DevTools → Application → Cookies
# - Verify dl_session cookie has Secure + HttpOnly + SameSite
```

---

**Status**: ✅ **PRODUCTION-READY SECURITY** (pending OpenShift Secrets configuration)
