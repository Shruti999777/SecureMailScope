@echo off
title SecureMailScope - Demonstration Launcher
echo ======================================================================
echo           SECUREMAILSCOPE - CRYPTOGRAPHIC POSTURE ANALYZER
echo ======================================================================
echo.

cd /d "%~dp0backend"
echo [*] Initializing database and pre-trained models...
python -c "from app.database import init_db; init_db()"
python scripts/generate_ca_hierarchy.py
python scripts/generate_synthetic_pcaps.py
python scripts/train_ml_models.py

echo.
echo [*] Starting FastAPI Backend on http://127.0.0.1:8000 ...
start "SecureMailScope Backend" uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

echo.
echo [*] Starting React Frontend on http://localhost:5173 ...
cd /d "%~dp0frontend"
start "SecureMailScope Frontend" npm run dev

echo.
echo ======================================================================
echo  [+] SecureMailScope is running!
echo      - Frontend UI: http://localhost:5173
echo      - Backend API: http://127.0.0.1:8000/docs
echo ======================================================================
pause
