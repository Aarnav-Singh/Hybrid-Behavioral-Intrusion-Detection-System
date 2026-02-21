# API Reference

Base URL: <http://localhost:8888>

## POST /api/v2/infer

Request:
{
  "host": "10.0.0.5",
  "timestamp": "2026-02-21T10:15:00"
}

Response:
{
  "risk_score": 0.87,
  "risk_level": "HIGH",
  "rule_score": 0.92,
  "ml_score": 0.84,
  "behavioral_confidence": 0.95
}

---

## POST /api/v2/train

Triggers model retraining.

---

## GET /api/v2/alerts

Returns paginated alerts.

---

## POST /api/v2/redteam/run

Launch adversarial simulation.
