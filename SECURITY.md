# Security Hardening for OpenShift Deployment

## ✅ Security Improvements Implemented

### 1. **Password Hashing with bcrypt**
- All passwords are now hashed using bcrypt (NIST approved, industry standard)
- Hashes use salt (2^12 rounds), making rainbow table attacks infeasible
- Old plaintext passwords in `users.json` are no longer used

### 2. **Removed Hardcoded Credentials**
- Removed hardcoded default user (`hamza:admin`) from source code
- Users must be initialized via:
  - `init_admin.py` script (production setup)
  - Admin panel (runtime user creation)
  - Environment variables: `DOCLING_UI_USERNAME` and `DOCLING_UI_PASSWORD`

### 3. **Secure Cookie Handling**
Added three critical cookie flags:
- **`Secure`**: Cookie only sent over HTTPS (prevents man-in-the-middle)
- **`HttpOnly`**: JavaScript cannot access cookie (prevents XSS theft)
- **`SameSite=Strict`**: Prevents CSRF attacks (no cross-site cookie sending)

### 4. **File Permission Restrictions**
- `users.json` created with mode `0600` (owner read/write only)
- No read access for group/other users
- Protects password hashes if filesystem is compromised

### 5. **Secret Key Management**
- Session signing key read from `DOCLING_SECRET_KEY` environment variable
- **Action needed**: Use OpenShift Secrets for key injection (see deployment section)

---

## 🚀 OpenShift Deployment Setup

### Prerequisites
1. **Create OpenShift Secret** for sensitive data:
```bash
# Create secret with secure values
oc create secret generic docling-secrets \
  --from-literal=DOCLING_SECRET_KEY=$(openssl rand -base64 32) \
  --from-literal=DOCLING_UI_USERNAME=admin \
  --from-literal=DOCLING_UI_PASSWORD=$(openssl rand -base64 16)
```

2. **Initialize admin user before deployment**:
```bash
# In container/deployment script:
export DOCLING_SECRET_KEY=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token-secret)
export DOCLING_UI_USERNAME=admin
export DOCLING_UI_PASSWORD=secure-password-here
python init_admin.py
```

3. **Update Deployment to use Secrets**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: docling-serve
spec:
  template:
    spec:
      containers:
      - name: docling-serve
        image: your-registry/docling-serve:latest
        env:
        - name: DOCLING_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: docling-secrets
              key: DOCLING_SECRET_KEY
        - name: DOCLING_UI_USERNAME
          valueFrom:
            secretKeyRef:
              name: docling-secrets
              key: DOCLING_UI_USERNAME
        - name: DOCLING_UI_PASSWORD
          valueFrom:
            secretKeyRef:
              name: docling-secrets
              key: DOCLING_UI_PASSWORD
        - name: DOCLING_SERVE_ENABLE_UI
          value: "true"
        volumeMounts:
        - name: users-db
          mountPath: /app/data
      volumes:
      - name: users-db
        persistentVolumeClaim:
          claimName: docling-users-pvc
```

4. **Create PersistentVolumeClaim** for `users.json`:
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: docling-users-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 1Gi
```

5. **Enable HTTPS** in OpenShift:
```yaml
# Add to deployment:
env:
- name: UVICORN_SSL_KEYFILE
  value: /etc/certs/tls.key
- name: UVICORN_SSL_CERTFILE
  value: /etc/certs/tls.crt
volumeMounts:
- name: tls-certs
  mountPath: /etc/certs
  readOnly: true
volumes:
- name: tls-certs
  secret:
    secretName: docling-tls
```

---

## 🔐 Security Checklist for Production

- [ ] Use OpenShift Secrets for `DOCLING_SECRET_KEY`, `DOCLING_UI_USERNAME`, `DOCLING_UI_PASSWORD`
- [ ] Enable HTTPS/TLS on ingress and container
- [ ] Use PersistentVolume for `users.json` (not ephemeral)
- [ ] Run `init_admin.py` during container initialization
- [ ] Verify `users.json` has `0600` permissions
- [ ] Rotate `DOCLING_SECRET_KEY` regularly (invalidates all current sessions)
- [ ] Monitor login attempts (add rate limiting if needed)
- [ ] Enable OpenShift Pod Security Standards (restricted)
- [ ] Use Network Policies to limit ingress/egress
- [ ] Enable audit logging for user creation/deletion

---

## 📝 Admin User Management

### Initialize Admin (first setup):
```bash
cd /app
export DOCLING_UI_USERNAME='your-admin-username'
export DOCLING_UI_PASSWORD='very-strong-password'
python init_admin.py
```

### Create Additional Users (via UI):
1. Log in with admin credentials
2. Open "👑 Admin Panel" (bottom accordion)
3. Fill in new username, password, and role
4. Click "Create User"
5. New password is hashed automatically

### Reset All Users:
```bash
rm -f users.json
python init_admin.py
```

---

## 🛡️ Additional Recommendations

### For Enterprise Use:
1. **Implement Rate Limiting**: Protect login endpoint from brute-force attacks
   ```python
   pip install slowapi
   # Add rate limiter to login handler
   ```

2. **Add Audit Logging**: Log all authentication events
   ```python
   logger.info(f"Login attempt: {username} - {'success' if ok else 'failed'}")
   ```

3. **LDAP/OAuth2 Integration**: Consider external identity providers
   - Reduces password management burden
   - Integrates with enterprise systems

4. **Two-Factor Authentication (2FA)**: Add TOTP or U2F
   ```python
   pip install pyotp qrcode
   ```

5. **Session Management**: Add ability to revoke sessions
   - Maintain session blacklist
   - Implement logout-all feature

---

## 🚨 Security Incident Response

### If Secret Key Compromised:
1. Generate new `DOCLING_SECRET_KEY`
2. Update OpenShift Secret
3. Restart deployment
4. All existing sessions will be invalidated (users must re-login)

### If users.json Leaked:
1. Passwords are hashed with bcrypt → safe from password lookup
2. Generate new passwords for all users
3. Re-run `init_admin.py` to create new admin
4. Recreate users.json with new passwords

---

## ✨ Current Implementation Status

| Security Feature | Status | Details |
|-----------------|--------|---------|
| Password Hashing | ✅ Done | bcrypt with salt rounds=12 |
| Secure Cookies | ✅ Done | Secure + HttpOnly + SameSite=Strict |
| File Permissions | ✅ Done | users.json mode 0600 |
| No Hardcoded Creds | ✅ Done | Env vars + init script only |
| Secret Key Management | ⚠️ Setup Required | Use OpenShift Secrets |
| HTTPS/TLS | ⚠️ Setup Required | Configure in OpenShift Ingress |
| Rate Limiting | ❌ Future | Recommend adding |
| Audit Logging | ❌ Future | Recommend adding |
| 2FA | ❌ Future | Advanced feature |

---

## 🔍 Testing Security

### Test 1: Verify Password Hashing
```python
python -c "
import json
with open('users.json') as f:
    users = json.load(f)
    for u in users:
        print(f'User: {u[\"username\"]}')
        print(f'Hash starts with \$2b: {u[\"password\"].startswith(\"\\$2b\")}')
        print(f'Hash length: {len(u[\"password\"])} (bcrypt = 60)')
"
```

### Test 2: Verify File Permissions
```bash
ls -la users.json
# Should show: -rw------- (600)
```

### Test 3: Verify Cookie Flags (in browser)
1. Open `/ui/` in browser
2. Login with credentials
3. Open DevTools → Application → Cookies
4. Check `dl_session` cookie has flags: `Secure`, `HttpOnly`, `SameSite=Strict`

---

## 📚 References
- bcrypt: https://github.com/pyca/bcrypt
- OWASP Session Management: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/README
- OpenShift Secrets: https://docs.openshift.com/container-platform/latest/nodes/pods/secrets/understanding-secrets.html
