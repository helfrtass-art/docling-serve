# Security Deployment Guide for OpenShift

This guide outlines best practices for deploying docling-serve securely on OpenShift.

## Security Hardening Implemented

### 1. **Password Hashing (bcrypt)**
- All passwords are hashed using bcrypt (not plaintext)
- Uses 12 salt rounds for strong security
- Passwords are verified securely without exposing plaintext

### 2. **Session Management**
- Tokens are HMAC-SHA256 signed
- 120-minute expiration time
- HttpOnly and Secure flags on cookies (when HTTPS enabled)
- SameSite=Strict prevents CSRF attacks

### 3. **Secret Management**
- `DOCLING_SECRET_KEY` from environment (not in code)
- Supports OpenShift Secrets for key rotation
- Token signing key must be kept secret

### 4. **User Credentials**
- No hardcoded defaults in code
- Users stored in JSON with hashed passwords
- Users file must be in OpenShift Secret/ConfigMap
- File permissions: `600` (owner-only readable)

### 5. **Container Security**
- Non-root user (UID 1001)
- Read-only filesystem recommended
- Secure configuration directory

## OpenShift Deployment Setup

### Step 1: Create OpenShift Secret for Users

First, create a `users.json` file with hashed passwords:

```bash
# On your local machine, create users.json using the init script
python3 << 'EOF'
import json
from pathlib import Path
from bcrypt import hashpw, gensalt

def hash_password(password: str) -> str:
    return hashpw(password.encode(), gensalt()).decode()

users = [
    {
        "username": "admin",
        "password": hash_password("your-secure-password-here"),
        "role": "admin"
    },
    {
        "username": "user1",
        "password": hash_password("another-secure-password"),
        "role": "user"
    }
]

with open("users.json", "w") as f:
    json.dump(users, f, indent=2)

print("✓ users.json created with hashed passwords")
EOF
```

Then create the OpenShift Secret:

```bash
# Create secret from users.json
oc create secret generic docling-users \
  --from-file=users.json=./users.json \
  -n your-namespace

# Verify
oc get secret docling-users -o yaml
```

### Step 2: Create Secret for Session Key

```bash
# Generate a secure random key
DOCLING_SECRET_KEY=$(head -c 32 /dev/urandom | base64)

# Create secret
oc create secret generic docling-session-key \
  --from-literal=secret-key="${DOCLING_SECRET_KEY}" \
  -n your-namespace
```

### Step 3: Deploy on OpenShift

Create a deployment YAML with proper secret mounting:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: docling-serve
  namespace: your-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: docling-serve
  template:
    metadata:
      labels:
        app: docling-serve
    spec:
      serviceAccountName: docling-serve
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 0
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: docling-serve
        image: quay.io/your-org/docling-serve:latest
        imagePullPolicy: Always
        
        # Security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false  # Set to true after testing
          capabilities:
            drop:
              - ALL
        
        # Environment variables
        env:
        - name: DOCLING_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: docling-session-key
              key: secret-key
        
        - name: DOCLING_USERS_PATH
          value: /config/users.json
        
        - name: DOCLING_SERVE_ENABLE_UI
          value: "true"
        
        # Port
        ports:
        - name: http
          containerPort: 5001
          protocol: TCP
        
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: 5001
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 5
        
        readinessProbe:
          httpGet:
            path: /health
            port: 5001
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
        
        # Resource limits
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        
        # Volume mounts
        volumeMounts:
        - name: config
          mountPath: /opt/app-root/src/config
          readOnly: true
        
        - name: cache
          mountPath: /opt/app-root/src/.cache
        
        - name: tmp
          mountPath: /tmp
      
      # Volumes
      volumes:
      - name: config
        secret:
          secretName: docling-users
          defaultMode: 0600
      
      - name: cache
        emptyDir:
          sizeLimit: 10Gi
      
      - name: tmp
        emptyDir:
          sizeLimit: 5Gi

---
apiVersion: v1
kind: Service
metadata:
  name: docling-serve
  namespace: your-namespace
spec:
  type: ClusterIP
  ports:
  - port: 5001
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: docling-serve

---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: docling-serve
  namespace: your-namespace
spec:
  to:
    kind: Service
    name: docling-serve
    weight: 100
  port:
    targetPort: http
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
  wildcardPolicy: None
```

### Step 4: Create RBAC (ServiceAccount)

```bash
oc create serviceaccount docling-serve -n your-namespace

oc create role docling-serve \
  --verb=get,list,watch \
  --resource=configmaps,secrets \
  -n your-namespace

oc create rolebinding docling-serve \
  --role=docling-serve \
  --serviceaccount=your-namespace:docling-serve \
  -n your-namespace
```

### Step 5: Deploy

```bash
# Create ConfigMap/Secret
oc apply -f users-secret.yaml
oc apply -f session-key-secret.yaml

# Deploy
oc apply -f deployment.yaml

# Check status
oc get pods -l app=docling-serve
oc logs -f deployment/docling-serve
```

## Security Checklist

- [ ] `DOCLING_SECRET_KEY` is stored in OpenShift Secret
- [ ] `users.json` is stored in OpenShift Secret (not in code)
- [ ] All passwords are bcrypt-hashed
- [ ] HTTPS/TLS is enabled on Route
- [ ] Non-root user (1001) is running the container
- [ ] File permissions on users.json are `600`
- [ ] Resource limits are set
- [ ] Health checks are configured
- [ ] Network policies restrict traffic if needed
- [ ] Container image is scanned for vulnerabilities
- [ ] Secret rotation is scheduled (annual minimum)

## Rotating Secrets

### Rotate Session Key

```bash
# Generate new key
NEW_KEY=$(head -c 32 /dev/urandom | base64)

# Update secret
oc patch secret docling-session-key -p \
  "{\"data\":{\"secret-key\":\"$(echo -n $NEW_KEY | base64)\"}}"

# Restart pods (existing tokens become invalid)
oc rollout restart deployment/docling-serve
```

### Update Users Password

```bash
# Update users.json with new password
python3 << 'EOF'
import json
from pathlib import Path
from bcrypt import hashpw, gensalt

with open("users.json", "r") as f:
    users = json.load(f)

# Update password for user
for u in users:
    if u["username"] == "admin":
        u["password"] = hashpw(b"new-secure-password", gensalt()).decode()
        break

with open("users.json", "w") as f:
    json.dump(users, f, indent=2)
EOF

# Update secret
oc create secret generic docling-users \
  --from-file=users.json=./users.json \
  --dry-run=client -o yaml | oc apply -f -

# Restart pods
oc rollout restart deployment/docling-serve
```

## Monitoring & Auditing

### Enable Audit Logging

Add to your deployment:

```yaml
env:
- name: LOG_LEVEL
  value: "INFO"

volumeMounts:
- name: logs
  mountPath: /var/log/docling

volumes:
- name: logs
  emptyDir:
    sizeLimit: 1Gi
```

### Monitor Failed Logins

Configure log aggregation (e.g., ELK stack) to alert on:
- Multiple failed login attempts
- Invalid token errors
- Password validation failures

## Additional Security Measures

1. **Network Policies**: Restrict egress to only necessary services
2. **Pod Security Standards**: Enforce restricted security policies
3. **Image Scanning**: Scan container images for vulnerabilities
4. **Secrets Encryption**: Enable encryption of secrets at rest
5. **RBAC**: Limit access to secrets and config maps
6. **Backup**: Regularly backup users.json and configuration
7. **Compliance**: Ensure GDPR/compliance with audit logging

## Troubleshooting

### Users cannot login

1. Check if `users.json` secret is mounted:
   ```bash
   oc exec -it deployment/docling-serve -- ls -la /opt/app-root/src/config/
   ```

2. Verify secret content:
   ```bash
   oc get secret docling-users -o yaml
   ```

3. Check pod logs:
   ```bash
   oc logs deployment/docling-serve | grep -i "auth\|login"
   ```

### Session timeout issues

1. Verify `DOCLING_SECRET_KEY` matches in all pods
2. Check clock synchronization between nodes
3. Increase TTL if needed in `gradio_ui.py` (SESSION_TTL_SECONDS)

## References

- [OpenShift Security Guide](https://docs.openshift.com/container-platform/latest/security/index.html)
- [Kubernetes Secrets Best Practices](https://kubernetes.io/docs/concepts/configuration/secret/)
- [bcrypt Security](https://github.com/pyca/bcrypt)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
