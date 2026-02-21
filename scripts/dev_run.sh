#!/bin/bash
set -em

echo "Starting local HB-IDS v2 Development Sandbox..."

# Trap ctrl-c and call cleanup
trap cleanup INT

function cleanup() {
    echo "Stopping services..."
    kill $(jobs -p) 2>/dev/null
    exit
}

echo "1. Starting PostgreSQL & Redis via Docker..."
docker-compose up -d postgres redis

echo "2. Starting FastAPI Backend..."
cd backend
source .venv/bin/activate || source .venv/Scripts/activate
# Make sure DB is ready conceptually
export DATABASE_URL="postgresql://user:password@localhost:5432/ids"
export REDIS_URL="redis://localhost:6379/0"
export MODE="hybrid"
uvicorn api.main:app --reload --port 8000 &
cd ..

echo "3. Starting React Frontend..."
cd frontend
npm run dev -- --port 3000 &
cd ..

echo "Services running! Press Ctrl+C to terminate."
wait
