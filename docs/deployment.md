# Deployment Guide

## Local Development

docker compose up -d --build
python run_project.py

## Services

- Frontend: <http://localhost:5173>
- API: <http://localhost:8888/docs>
- Prometheus: <http://localhost:9090>
- MLflow: <http://localhost:5000>
- Kibana: <http://localhost:5601>

## Kubernetes

Apply manifests:

kubectl apply -f k8s/
