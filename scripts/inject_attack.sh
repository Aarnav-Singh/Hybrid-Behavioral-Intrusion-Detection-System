#!/bin/bash
ATTACK_TYPE=${1:-dns_tunneling}
TARGET=${2:-10.0.0.45}
INTENSITY=${3:-1.5}

echo "Injecting ${ATTACK_TYPE} against ${TARGET} at ${INTENSITY}x intensity..."

curl -X POST "http://localhost:8000/api/v1/redteam/run" \
     -H "Content-Type: application/json" \
     -d "{\"attack_type\": \"${ATTACK_TYPE}\", \"target_ip\": \"${TARGET}\", \"intensity\": ${INTENSITY}}"

echo -e "\nAttack scenario spawned and metrics aggregated."
