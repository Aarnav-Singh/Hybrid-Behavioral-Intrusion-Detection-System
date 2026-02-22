#!/bin/bash
set -e

echo "================================================"
echo "    HB-IDS v2: Development Environment Setup"
echo "================================================"

# Python Backend
echo "-> Setting up Backend..."
cd backend
python3 -m venv .venv
source .venv/bin/activate || source .venv/Scripts/activate
pip install --upgrade pip
if [ -f "pyproject.toml" ]; then
    pip install poetry
    poetry install
else
    pip install -r requirements.txt
fi
cd ..

# Node Frontend
echo "-> Setting up Frontend..."
cd frontend
npm install
cd ..

echo "================================================"
echo " Setup Complete! You can now run './scripts/dev_run.sh'"
echo " or use 'docker compose up' for full containerized runs."
echo "================================================"
