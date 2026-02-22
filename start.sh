#!/bin/bash
set -e

echo -e "\033[1;36m================================================\033[0m"
echo -e "\033[1;32m    HB-IDS v2: One-Click Start Script\033[0m"
echo -e "\033[1;36m================================================\033[0m"

# Trap ctrl-c and call cleanup
trap cleanup INT

function cleanup() {
    echo -e "\n\033[1;33mStopping services...\033[0m"
    kill $(jobs -p) 2>/dev/null
    docker compose stop postgres redis
    echo -e "\033[1;32mCleanup complete. Goodbye!\033[0m"
    exit
}

echo -e "\n\033[1;33m1. Starting PostgreSQL & Redis via Docker...\033[0m"
docker compose up -d postgres redis

echo -e "\n\033[1;33m2. Setting up and Starting FastAPI Backend...\033[0m"
cd backend
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate || source .venv/Scripts/activate
python -m pip install --upgrade pip > /dev/null
pip install poetry > /dev/null
poetry install

export DATABASE_URL="postgresql://user:password@localhost:5432/ids"
export REDIS_URL="redis://localhost:6379/0"
export MODE="hybrid"
echo -e "\033[1;32mStarting FastAPI Backend in the background (Port 8000)...\033[0m"
uvicorn api.main:app --reload --port 8000 &
cd ..

echo -e "\n\033[1;33m3. Setting up and Starting React Frontend...\033[0m"
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing NPM dependencies..."
    npm install
fi
echo -e "\033[1;32mStarting React Frontend in the background (Port 3000)...\033[0m"
npm run dev -- --port 3000 &
cd ..

echo -e "\n\033[1;36m================================================\033[0m"
echo -e "\033[1;32m All services are starting!\033[0m"
echo -e " -> Frontend Dashboard: \033[1mhttp://localhost:3000\033[0m"
echo -e " -> Backend API Docs:   \033[1mhttp://localhost:8000/docs\033[0m"
echo -e "\033[1;36m================================================\033[0m"
echo -e "\033[1;31mPress Ctrl+C to stop all services and exit.\033[0m"

wait
