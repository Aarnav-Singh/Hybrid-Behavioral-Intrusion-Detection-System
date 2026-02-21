# Infrastructure Configurations

This directory contains all infrastructure-as-code and operational configs for HB-IDS.

## Structure

```
infrastructure/
├── prometheus/         # Prometheus scrape configs + alert rules
├── filebeat/           # Filebeat log shipping configuration
├── kubernetes/         # Kubernetes deployment manifests
└── grafana/            # Grafana dashboard JSONs (optional)
```

---

## Quick Reference

| Component | Config File | Purpose |
|---|---|---|
| Prometheus | `prometheus/prometheus.yml` | Scrape targets + global settings |
| Alert Rules | `prometheus/rules/alerts.yml` | Alerting thresholds |
| Filebeat | `filebeat/filebeat.yml` | Log shipping from Nginx → ES |
| Kubernetes | `kubernetes/*.yaml` | Deployment + Service manifests |

---

## Deploying to Kubernetes

```bash
# Apply all manifests
kubectl apply -f infrastructure/kubernetes/

# Scale detection engine
kubectl scale deployment hbids-detection --replicas=3

# Check pod status
kubectl get pods -l app=hbids
```
