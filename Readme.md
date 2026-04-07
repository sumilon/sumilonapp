# Sumilon App

A Python/Flask web application with four independent single-page tools. The Vault module uses Google Firestore as its database and encrypts all sensitive data with AES-256 before storing it.

## Application URLs

| URL | Module | Storage |
|-----|--------|---------|
| `/` | Portfolio | None |
| `/calculator` | Financial Calculator | None — pure client-side JS |
| `/todo` | To-do List | Browser localStorage |
| `/vault` | Password Manager | AES-256 + Firestore |
| `/health` | Cloud Run liveness probe | None |

## Project Structure

```
app/
├── app.py                   Flask factory — 4 blueprints, /health, CSP headers
├── config.py                3-tier secret resolution (Secret Manager → env var → fallback)
├── crypto.py                AES-256 Fernet encryption + PBKDF2 password hashing
├── db.py                    Firestore singleton client with credential auto-detection
├── requirements.txt
│
├── vault/
│   ├── auth.py              register_user, login_user, login_required decorator
│   ├── passwords.py         CRUD + per-field AES-256 encryption
│   └── routes.py            GET|POST /vault/* and all /vault/api/* endpoints
│
├── portfolio/routes.py
├── calculator/
│   ├── routes.py
│   └── logic.py
├── todo/routes.py
│
└── templates/               One HTML file per page
    ├── portfolio.html
    ├── calculator.html
    ├── todo.html
    └── vault.html
```

---

## 1. Firebase / Firestore Setup

### Step 1 — Create a Firebase Project

1. Go to https://console.firebase.google.com
2. Click **Add project** and enter your project name
3. Disable Google Analytics (not needed) and click **Create project**

### Step 2 — Create Firestore Database

1. Left sidebar → **Firestore Database** → **Create database**
2. Select **Production mode**
3. Region: `asia-south1` (Mumbai — lowest latency from India)
4. Click **Enable**

### Step 3 — Set Firestore Security Rules

Go to **Firestore → Rules** tab, replace all content with the following and click **Publish**:

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

> All access goes through the Flask backend. The Admin SDK bypasses these rules server-side.

### Step 4 — Download Service Account Credentials

1. **Project Settings** (gear icon) → **Service accounts** tab
2. Click **Generate new private key** → **Confirm**
3. Save the downloaded file as `firebase-credentials.json`

> ⚠️ **Never commit this file to Git.** Add `firebase-credentials.json` to your `.gitignore` immediately.

---

## 2. GCP Secret Manager Setup

### Step 1 — Enable the Secret Manager API

1. Go to https://console.cloud.google.com
2. Search for **Secret Manager** in the top search bar
3. Click **Enable API** if it is not already enabled

### Step 2 — Create the Three Required Secrets

Go to **Security → Secret Manager → Create Secret** and create each of the following:

| Secret Name | Value to Store |
|-------------|---------------|
| `flask-secret-key` | Any random 64-character string |
| `app-master-key` | Any random 32+ character string |
| `firebase-creds` | Entire contents of `firebase-credentials.json` |

For each secret:

1. Enter the exact **Name** from the table above
2. Paste the value into **Secret value** (or click **Upload file** for `firebase-creds`)
3. Leave all other settings as default and click **Create secret**

---

## 3. IAM — Granting Secret Manager Access

Your Cloud Run service runs under a service account that needs permission to read secrets.

### Step 1 — Find the Cloud Run Service Account

1. Go to **Cloud Run** → click your service name
2. Click the **Security** tab
3. Note down the **Service account** email — it looks like:
   ```
   <project-number>-compute@developer.gserviceaccount.com
   ```

### Step 2 — Grant Access via IAM Page

1. Go to **IAM & Admin → IAM**
2. Click **Grant Access** (blue button at the top)
3. **New principals** → paste the service account email from Step 1
4. **Select a role** → search for and select `Secret Manager Secret Accessor`
5. Click **Save**

**Alternative — Grant Access via Secret Manager directly:**

1. Go to **Security → Secret Manager**
2. Click on a secret (e.g. `firebase-creds`) → **Permissions** tab
3. Click **Grant Access**
4. Paste the service account email, select `Secret Manager Secret Accessor`, click **Save**
5. Repeat for each of the three secrets

### Step 3 — Verify

1. Go to **IAM & Admin → IAM**
2. Search for your service account email
3. Confirm `Secret Manager Secret Accessor` appears under its roles

> ℹ️ IAM changes can take 1–2 minutes to propagate. If Cloud Run still fails after granting access, wait a moment and redeploy.

---

## 4. Cloud Run — Linking Secrets as Environment Variables

After granting IAM access, link each secret to an environment variable in Cloud Run.

1. Go to **Cloud Run → your service → Edit & Deploy New Revision**
2. Open the **Variables & Secrets** tab
3. Scroll down to the **Secrets** section → click **Reference a Secret**
4. For each secret, fill in:
   - **Secret** → select from dropdown
   - **Reference method** → `Exposed as environment variable`
   - **Environment variable name** → see table below
   - **Version** → `latest`
5. Click **Done** after each, then click **Deploy**

| Secret Manager Name | Environment Variable Name |
|---------------------|--------------------------|
| `flask-secret-key` | `FLASK_SECRET_KEY` |
| `app-master-key` | `APP_MASTER_KEY` |
| `firebase-creds` | `FIREBASE_CREDENTIALS_JSON` |

---

## 5. Local Development Setup

### Step 1 — Install Dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows PowerShell
venv\Scripts\activate

pip install -r requirements.txt
```

### Step 2 — Set Environment Variables

**macOS / Linux:**
```bash
export FLASK_SECRET_KEY="any-local-dev-secret-key"
export APP_MASTER_KEY="your-32-char-master-encryption-key!!"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/firebase-credentials.json"
export FLASK_DEBUG="true"
```

**Windows PowerShell:**
```powershell
$env:FLASK_SECRET_KEY               = "any-local-dev-secret-key"
$env:APP_MASTER_KEY                 = "your-32-char-master-encryption-key!!"
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\to\firebase-credentials.json"
$env:FLASK_DEBUG                    = "true"
```

> ⚠️ **Use the same `APP_MASTER_KEY` locally and in production.** Data encrypted with one key cannot be decrypted with another. A mismatch causes an `InvalidToken` error when reading Firestore data.

### Step 3 — Run the App

```bash
python app.py
# http://localhost:8080
```

```

---

## 6. Firebase Credential Resolution Order

`db.py` resolves credentials in the following priority order — first match wins:

| Priority | Source | Best for |
|----------|--------|----------|
| 1 (highest) | `FIREBASE_CREDENTIALS_JSON` — JSON string | Production (Cloud Run via Secret Manager) |
| 2 | `GOOGLE_APPLICATION_CREDENTIALS` — file path | Local development |
| 3 (fallback) | Application Default Credentials | Cloud Run service account with Firebase role |

> ✅ Always use `FIREBASE_CREDENTIALS_JSON` via Secret Manager in production.
> Reserve `GOOGLE_APPLICATION_CREDENTIALS` for local file paths only.

---

## 7. Cloud Run Deployment Checklist

After the latest code changes, deploy as follows:

1. Build and push the container image:
   ```bash
   gcloud builds submit --tag gcr.io/<PROJECT_ID>/sumilonapp
   ```
2. Go to **Cloud Run → your service → Edit & Deploy New Revision**
3. Set **Memory** to `256 MiB`, **CPU** to `1`, **Min instances** to `0`, **Max instances** to `1`
4. Ensure the three secrets are linked as env vars (see Section 4)
5. Ensure `FLASK_DEBUG` is **not set** (or set to `false`) in Cloud Run
6. Click **Deploy** and wait for the green checkmark
7. Verify `/health` returns `{"status": "ok"}` after deployment

**Security baseline applied in this build:**

| Concern | Implementation |
|---------|---------------|
| Stored passwords | AES-256 Fernet, unique random salt, 600,000-iteration PBKDF2 key derivation |
| Login passwords | PBKDF2-SHA256, 600,000 rounds, unique salt |
| Timing attacks | `hmac.compare_digest` constant-time comparison |
| Sessions | HttpOnly, SameSite=Lax, Secure cookie, 2-hour lifetime |
| HTTP headers | CSP nonce, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, HSTS |
| Firestore rules | Deny all direct client access — Admin SDK bypasses rules server-side |
| Debug mode | Only enabled locally via `FLASK_DEBUG` env var, never in Cloud Run |

---

## 8. Firestore Data Model

```
users/{uid}
  uid            string     Random hex — also the document ID
  email          string     Plain text — indexed for login query
  email_enc      map        AES-256 {ciphertext, salt}
  username_enc   map        AES-256 {ciphertext, salt}
  password_hash  string     PBKDF2 "hex_salt:hex_digest" — irreversible
  created_at     timestamp

  passwords/{pid}
    site_name_enc  map      AES-256
    site_url_enc   map      AES-256 (optional)
    username_enc   map      AES-256
    password_enc   map      AES-256  ← never returned in list API
    notes_enc      map      AES-256 (optional)
    created_at     timestamp
    updated_at     timestamp (optional)
```

---
