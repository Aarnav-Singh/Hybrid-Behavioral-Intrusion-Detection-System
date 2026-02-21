#!/bin/bash
echo "Triggering manual ML model retrain..."
curl -X POST "http://localhost:8000/api/v1/train" -H "Content-Type: application/json" -d '{"mode": "hybrid"}'
echo -e "\nJob queued."
