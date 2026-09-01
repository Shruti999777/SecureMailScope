#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "          SECUREMAILSCOPE - CRYPTOGRAPHIC POSTURE ANALYZER"
echo "======================================================================"
echo ""

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR/backend"
echo "[*] Initializing database and pre-trained models..."
python -c "from app.database import init_db; init_db()"
python scripts/generate_ca_hierarchy.py
python scripts/generate_synthetic_pcaps.py
python scripts/train_ml_models.py

echo ""
echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

echo ""
echo "[*] Starting React Frontend on http://localhost:5173 ..."
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "======================================================================"
echo " [+] SecureMailScope is running!"
echo "     - Frontend UI: http://localhost:5173"
echo "     - Backend API: http://127.0.0.1:8000/docs"
echo "======================================================================"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
