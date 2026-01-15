# Authentication & Session Management Implementation
## Docling Serve - Security Enhancement Report

**Date:** December 9, 2025  
**Project:** Docling Serve v1.9.0  
**Prepared by:** Hamza EL-FRTASS

---

## Executive Summary

This document outlines the implementation of a comprehensive authentication and session management system for Docling Serve. The solution includes secure login, persistent sessions with 120-minute timeout, password hashing, and OpenShift-ready container deployment.

### Key Achievements
- ✅ Secure login system with bcrypt password hashing
- ✅ Cookie-based session persistence (120 minutes)
- ✅ Admin panel for user management
- ✅ OpenShift-compatible container deployment
- ✅ Auto-initialization from environment variables

---

## 1. Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (Client)                     │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────┐      │
│  │ Login Screen │  │ Main UI    │  │ Admin Panel │      │
│  └──────────────┘  └────────────┘  └─────────────┘      │
│         │                 │                 │           │
│         └─────────────────┴─────────────────┘           │
│                           │                             │
│                   Cookie: dl_session                    │
│                      (120 min TTL)                      │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Gradio UI (gradio_ui.py)                   │
│  ┌────────────────────────────────────────────────┐     │
│  │ • login_handler()                              │     │
│  │ • auto_login_handler()                         │     │
│  │ • logout_handler()                             │     │
│  │ • Session token creation/verification (HMAC)   │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Authentication Layer                       │
│  ┌────────────────────────────────────────────────┐     │
│  │ • User authentication (bcrypt)                 │     │
│  │ • Password hashing/verification                │     │
│  │ • HMAC-SHA256 token signing                    │     │
│  │ • Role-based access control                    │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              User Database (users.json)                 │
│  {                                                      │
│    "username": "admin",                                 │
│    "password": "$2b$12$...",  // bcrypt hash            │
│    "role": "admin"                                      │
│  }                                                      │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Authentication Flow

### Login Workflow

```
┌─────────┐                    ┌──────────────┐                    ┌──────────┐
│ Browser │                    │ Gradio UI    │                    │ Database │
└────┬────┘                    └──────┬───────┘                    └────┬─────┘
     │                                │                                  │
     │ 1. Enter credentials           │                                  │
     ├────────────────────────────────>                                  │
     │                                │                                  │
     │                                │ 2. Authenticate user             │
     │                                ├─────────────────────────────────>│
     │                                │                                  │
     │                                │ 3. Verify password (bcrypt)      │
     │                                │<─────────────────────────────────┤
     │                                │                                  │
     │                                │ 4. Create session token (HMAC)   │
     │                                │                                  │
     │ 5. Return token + UI state     │                                  │
     │<────────────────────────────────                                  │
     │                                │                                  │
     │ 6. Store in cookie (120 min)   │                                  │
     │ document.cookie = dl_session   │                                  │
     │                                │                                  │
     │ 7. Show main UI                │                                  │
     │<───────────────────────────────|                                  │
     │                                │                                  │
```

### Session Persistence (Page Refresh)

```
┌─────────┐                    ┌──────────────┐
│ Browser │                    │ Gradio UI    │
└────┬────┘                    └──────┬───────┘
     │                                │
     │ 1. Page load (refresh)         │
     ├────────────────────────────────>
     │                                │
     │ 2. Read dl_session cookie      │
     │    (JavaScript on load)        │
     │                                │
     │ 3. Send token to server        │
     ├────────────────────────────────>
     │                                │
     │                                │ 4. Verify token signature
     │                                │    Check expiry (< 120 min?)
     │                                │
     │ 5a. Valid → Show main UI       │
     │<────────────────────────────────
     │                                │
     │ 5b. Invalid/Expired            │
     │     → Show login screen        │
     │<────────────────────────────────
     │                                │
```

---

## 3. Implementation Details

### 3.1 Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Login UI** | `gradio_ui.py` | Login screen with username/password fields |
| **Session Token** | `gradio_ui.py` | HMAC-SHA256 signed tokens with 120-min expiry |
| **Password Storage** | `users.json` | Bcrypt-hashed passwords (salt rounds: 12) |
| **Cookie Management** | JavaScript (client) | Store/retrieve session token (120-min TTL) |
| **Admin Panel** | `gradio_ui.py` | User creation interface (admin role only) |
| **Container Config** | `Containerfile` | Secure deployment configuration |

### 3.2 Security Features

#### Password Hashing (bcrypt)

```python
# Hash password with bcrypt (salt rounds: 12)
def hash_password(password: str) -> str:
    if bcrypt:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Fallback for dev only
    logger.warning("bcrypt not available. Using plaintext (INSECURE)")
    return password

# Verify password
def verify_password(password: str, hashed: str) -> bool:
    if bcrypt:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    return password == hashed
```

#### Session Token (HMAC-SHA256)

```python
# Token structure: base64(payload + signature)
# Payload: {"u": username, "r": role, "exp": timestamp}
# Signature: HMAC-SHA256(payload, SECRET_KEY)

def create_session_token(username: str, role: str) -> str:
    payload = {
        "u": username,
        "r": role,
        "exp": int(time.time()) + 7200  # 120 minutes
    }
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload_bytes + b"." + sig).decode()

def verify_session_token(token: str):
    # Verify signature and check expiry
    # Returns (username, role) or (None, None)
```

#### Cookie Configuration

```javascript
// Client-side cookie management
const ttlMinutes = 120;
const expires = new Date(Date.now() + ttlMinutes * 60 * 1000).toUTCString();
document.cookie = `dl_session=${encodeURIComponent(token)}; expires=${expires}; path=/; SameSite=Lax`;
```

---

## 4. Deployment Configuration

### 4.1 Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `DOCLING_SECRET_KEY` | Token signing key (required) | `a-long-random-secret` |
| `DOCLING_UI_USERNAME` | Initial admin username | `admin` |
| `DOCLING_UI_PASSWORD` | Initial admin password | `changeme` |
| `DOCLING_SERVE_ENABLE_UI` | Enable Gradio UI | `true` |
| `DOCLING_USERS_PATH` | Users database location | `/opt/app-root/src/config/users.json` |

### 4.2 Container Deployment

```bash
# Build container image
podman build -t docling-serve-v1:local -f Containerfile .

# Run container
podman run -d -p 5001:5001 \
  -e DOCLING_SECRET_KEY='your-secret-key' \
  -e DOCLING_UI_USERNAME='admin' \
  -e DOCLING_UI_PASSWORD='changeme' \
  -e DOCLING_SERVE_ENABLE_UI=true \
  docling-serve-v1:local
```

### 4.3 OpenShift Deployment

```yaml
# Mount users.json as Secret
apiVersion: v1
kind: Secret
metadata:
  name: docling-users
type: Opaque
stringData:
  users.json: |
    [
      {
        "username": "admin",
        "password": "$2b$12$...",
        "role": "admin"
      }
    ]
---
# Deployment with volume mount
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: docling-serve
        env:
        - name: DOCLING_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: docling-secret
              key: secret-key
        - name: DOCLING_USERS_PATH
          value: /opt/app-root/src/config/users.json
        volumeMounts:
        - name: config
          mountPath: /opt/app-root/src/config
          readOnly: true
      volumes:
      - name: config
        secret:
          secretName: docling-users
          defaultMode: 0600
```

---

## 5. File Modifications Summary

### Modified Files

| File | Changes | Lines Modified |
|------|---------|----------------|
| `gradio_ui.py` | Added authentication system, session management, admin panel | +400 lines |
| `pyproject.toml` | Added bcrypt dependency | +1 line |
| `Containerfile` | Added secure config directory, permissions | +5 lines |
| `.vscode/settings.json` | Python interpreter configuration | +5 lines (new) |

### New Files Created

| File | Purpose |
|------|---------|
| `SECURITY_DEPLOYMENT.md` | OpenShift deployment guide with security best practices |
| `SECURITY_SUMMARY.md` | Security features summary and checklist |
| `users.json` | User database (runtime, not in git) |

---

## 6. Testing Results

### Functional Tests

| Test Case | Status | Notes |
|-----------|--------|-------|
| Login with valid credentials | ✅ Pass | Admin user created automatically |
| Login with invalid credentials | ✅ Pass | Error message displayed |
| Session persistence (refresh) | ✅ Pass | User stays logged in for 120 minutes |
| Session expiry | ✅ Pass | Login required after 120 minutes |
| Logout functionality | ✅ Pass | Session cleared, redirected to login |
| Admin user creation | ✅ Pass | Only admins can create users |
| Password hashing | ✅ Pass | Bcrypt with proper salt |
| Token signature verification | ✅ Pass | HMAC-SHA256 validation |

### Container Deployment Tests

| Test Case | Status | Notes |
|-----------|--------|-------|
| Build container image | ✅ Pass | Image: docling-serve-v1:local |
| Start container | ✅ Pass | Listens on port 5001 |
| Auto-create admin user | ✅ Pass | From environment variables |
| UI accessible | ✅ Pass | http://localhost:5001/ui |
| API accessible | ✅ Pass | http://localhost:5001/docs |

---

## 7. Security Considerations

### Implemented Security Measures

1. **Password Security**
   - bcrypt hashing with salt (cost factor: 12)
   - No plaintext passwords in production
   - Secure password verification

2. **Session Security**
   - HMAC-SHA256 signed tokens
   - 120-minute session timeout
   - Token includes expiry timestamp
   - Signature verification on every request

3. **Container Security**
   - Non-root user (UID 1001)
   - Restrictive file permissions (0600 for users.json)
   - Secret mounting via OpenShift Secrets
   - Secure config directory (/opt/app-root/src/config)

4. **Cookie Security**
   - SameSite=Lax (prevents CSRF)
   - URL-encoded values
   - 120-minute expiry
   - Path restricted to /

### Limitations & Future Improvements

| Item | Current State | Recommendation |
|------|---------------|----------------|
| Cookie HttpOnly flag | ❌ Cannot be set client-side | Implement server-side cookie setting via middleware |
| Cookie Secure flag | ❌ Cannot be set client-side | Enforce HTTPS and set via server |
| Rate limiting | ❌ Not implemented | Add rate limiting to login endpoint |
| Multi-factor auth | ❌ Not implemented | Consider TOTP/WebAuthn for high-security environments |
| Audit logging | ⚠️ Basic logging | Implement comprehensive audit trail |

---

## 8. Conclusion

The authentication and session management system has been successfully implemented with the following benefits:

### Achievements
- ✅ Secure user authentication with industry-standard bcrypt
- ✅ Persistent sessions with 120-minute timeout
- ✅ Role-based access control (admin/user roles)
- ✅ Container-ready deployment for OpenShift
- ✅ Auto-initialization from environment variables

### Production Readiness
The system is ready for production deployment with the following prerequisites:
1. Set strong `DOCLING_SECRET_KEY` (minimum 32 characters)
2. Deploy behind HTTPS reverse proxy
3. Mount users.json as OpenShift Secret with 0600 permissions
4. Enable audit logging in production
5. Regular security reviews and updates

### Next Steps
1. Implement server-side cookie setting for HttpOnly/Secure flags
2. Add rate limiting to prevent brute-force attacks
3. Implement comprehensive audit logging
4. Consider adding MFA for admin accounts
5. Regular security assessments and penetration testing

---

**Document Version:** 1.0  
**Last Updated:** December 9, 2025  
**Status:** Ready for Production Deployment
