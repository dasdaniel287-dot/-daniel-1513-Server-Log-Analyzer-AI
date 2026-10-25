# Deployment Guide — Server Log Analyzer AI

This platform is architected to run seamlessly on Linux, Windows, macOS, Docker, and Termux (Android).

---

## 1. Quickstart (Node & Full-Stack Development)

```bash
# Install dependencies
npm install

# Start the full-stack development server on port 3000
npm run dev
```

Visit `http://localhost:3000` to access the interactive web console.

---

## 2. Python Backend & CLI Deployment (Linux / Ubuntu / Debian)

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run backend API
python -m uvicorn app.main:app --host 0.0.0.0 --port 3000
```

---

## 3. Docker Deployment

```bash
# Run with Docker Compose
docker compose up -d

# Verify container health
docker ps
curl http://localhost:3000/api/health
```

---

## 4. Windows Setup (PowerShell)

```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies and start server
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

---

## 5. Termux Compatibility Notes (Android)

Termux provides a lightweight terminal environment on Android.

```bash
pkg update && pkg upgrade
pkg install python nodejs git libxml2 libxslt
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

> **Note on Termux**: Pre-compiled binary wheels may be required for `scikit-learn`. If C-extensions fail to build, Server Log Analyzer AI gracefully switches to the internal pure-Python mathematical anomaly detector.
