# App — Setup & Deployment Guide

## Application URLs

| URL | Page | Storage |
|-----|------|---------|
| `http://localhost:8080/` | Portfolio | None |
| `http://localhost:8080/calculator` | Financial Calculator | None — pure client-side JS |
| `http://localhost:8080/todo` | To-do List | Browser localStorage |
| `http://localhost:8080/vault` | Password Manager | Firestore (AES-256 encrypted) |
| `http://localhost:8080/health` | Cloud Run probe | None |

Each page is a fully standalone single-page application.
No page links to any other page.

---

## Project Structure

```
app/
├── app.py                 ← Flask factory, 4 blueprints, /health, CSP headers
├── config.py              ← 3-tier secret resolution (Secret Manager → env var → fallback)
├── crypto.py              ← AES-256 Fernet encryption + PBKDF2 password hashing
├── db.py                  ← Firestore singleton client
│
├── portfolio/routes.py    ← GET /          → templates/portfolio.html
├── calculator/
│   ├── routes.py          ← GET /calculator → templates/calculator.html
│   └── logic.py           ← Python reference implementations of all 7 calculators
├── todo/routes.py         ← GET /todo      → templates/todo.html
├── vault/
│   ├── auth.py            ← register_user, login_user, login_required decorator
│   ├── passwords.py       ← CRUD + per-field AES-256 encryption
│   └── routes.py          ← GET|POST /vault/* + all /vault/api/* endpoints
│
├── templates/             ← Flat folder — one file per page (no sub-folders)
│   ├── portfolio.html
│   ├── calculator.html
│   ├── todo.html
│   └── vault.html
│
├── Dockerfile             ← Multi-stage build, non-root user
├── cloudbuild.yaml        ← Auto-deploy on git push to main
├── requirements.txt
├── .gitignore
└── .dockerignore
```

---

## About FLASK_DEBUG

`FLASK_DEBUG=true` is a **local development only** setting.

What it does when enabled:
- Shows an interactive Python debugger in the browser on any error
- Auto-reloads the server whenever you save a Python file

Why it must NEVER be set in production:
- The interactive debugger allows **arbitrary code execution** by anyone who
  triggers an error — a critical security vulnerability
- Auto-reload wastes memory and causes random request failures

In this codebase the flag is consumed via `cfg.DEBUG` in `config.py`,
which controls `SESSION_COOKIE_SECURE`. In production (Cloud Run) this
env var is simply not set, so `cfg.DEBUG = False` and secure cookies
are enforced automatically.

Local dev workflow:
```bash
export FLASK_DEBUG="true"      # only set this locally, never in Cloud Run
python app.py
```

---

## Step 1 — Firebase Setup

1. https://console.firebase.google.com → **Add project**
2. Left sidebar → **Firestore Database** → **Create database** → **Production mode**
   - Region: `asia-south1` (Mumbai — lowest latency from Chennai)
3. **Firestore → Rules** → replace with:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

Click **Publish**. All access goes through the Flask backend (Admin SDK bypasses these rules).

4. **Project Settings → Service accounts → Generate new private key**
   Save the JSON file. Never commit it.

---

## Step 2 — Set Secrets

### Option A — Cloud Run env vars (simplest)

Cloud Run → Edit Revision → Variables & Secrets tab:

| Variable | Value |
|----------|-------|
| `FLASK_SECRET_KEY` | Any 64-char random string |
| `APP_MASTER_KEY` | Any 32+ char string |
| `FIREBASE_CREDENTIALS_JSON` | Full contents of `firebase-credentials.json` |

### Option B — GCP Secret Manager (recommended for production)

1. https://console.cloud.google.com/security/secret-manager → create:
   - `flask-secret-key` → random 64-char string
   - `app-master-key` → random 32+ char string
   - `firebase-creds` → paste entire `firebase-credentials.json`

2. IAM → Cloud Run service account → add role: **Secret Manager Secret Accessor**

3. Cloud Run → Variables & Secrets → reference each secret as env var

---

## Step 3 — Local Development

```bash
cd app/
python -m venv venv && source venv/bin/activate
# Windows: venv\Scripts\activate
pip install -r requirements.txt

export GOOGLE_APPLICATION_CREDENTIALS="./firebase-credentials.json"
export FLASK_SECRET_KEY="local-dev-secret-key"
export APP_MASTER_KEY="local-dev-master-key-32chars!!!"
export FLASK_DEBUG="true"

$env:GOOGLE_APPLICATION_CREDENTIALS=".\firebase-credentials.json"
$env:FLASK_SECRET_KEY="your-random-secret-key-here"
$env:APP_MASTER_KEY="your-32-char-master-encryption-key!!"

python app.py
# → http://localhost:8080
```

---

## Step 4 — Auto-Deploy from GitHub (Cloud Build)

### One-time setup (Console UI, no CLI)

1. **Artifact Registry** → Create repository
   - Name: `vault-repo` | Format: Docker | Region: `asia-south1`

2. **Cloud Build → Settings** → enable:
   - Cloud Run Admin ✅
   - Service Account User ✅
   - Artifact Registry Writer ✅

3. **Cloud Build → Triggers → Connect Repository** → select GitHub repo
   - Event: Push to branch `^main$`
   - Configuration: `cloudbuild.yaml`

4. Edit `cloudbuild.yaml` → set `_PROJECT` to your GCP project ID

### Deploy

```bash
git add .
git commit -m "deploy"
git push origin main
# Cloud Build triggers automatically → build → push → deploy
```

---

## GCP Free Tier — $0/month for personal use

| Service | Free allowance |
|---------|---------------|
| Cloud Run | 2M requests/month, 360K GB-seconds |
| Firestore | 50K reads/day, 20K writes/day, 1 GB |
| Cloud Build | 120 min/day (~2 min per deploy) |
| Artifact Registry | 0.5 GB |
| Secret Manager | 10K access ops/month |

---

## Security Summary

| Layer | Implementation |
|-------|---------------|
| Login passwords | PBKDF2-SHA256, 390K rounds, unique salt per user |
| Stored credentials | AES-256 Fernet, unique PBKDF2-derived key per record |
| Timing attack | `hmac.compare_digest` constant-time comparison |
| Session | HttpOnly, SameSite=Lax, Secure (prod only) |
| HTTP headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Firestore | Rules deny all direct client access |
| Docker | Multi-stage build, non-root user |
| Debug mode | Only enabled locally via FLASK_DEBUG env var |

---

## Firestore Data Model

```
users/{uid}
  uid            plain    random hex, document ID
  email          plain    indexed for login query
  email_enc      AES-256  {ciphertext, salt}
  username_enc   AES-256  {ciphertext, salt}
  password_hash  PBKDF2   "hex_salt:hex_digest" — irreversible
  created_at     timestamp

  passwords/{pid}
    site_name_enc  AES-256
    site_url_enc   AES-256
    username_enc   AES-256
    password_enc   AES-256  ← never returned in list API
    notes_enc      AES-256
    created_at     timestamp
    updated_at     timestamp (optional)
```
