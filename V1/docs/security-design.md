# Security Design

## Threat Model

HB-IDS is designed to detect the following attack categories:

| Attack Type | Detection Method | Rule |
|---|---|---|
| **DoS / Flood** | Rate threshold + ML | `request_rate > 3σ baseline` |
| **SQL Injection** | Payload entropy + path analysis | `entropy(path) > threshold` |
| **Brute Force Login** | Error rate + IP frequency | `error_rate > 60% AND ip_freq high` |
| **Path Traversal** | URL pattern matching | `path contains ../` |
| **Port Scanning** | Connection diversity | `unique_endpoints > 50/min` |
| **Slow-and-Low Evasion** | Behavioral baseline deviation | `baseline_deviation > 2.5σ` |
| **Credential Stuffing** | Session velocity + error rate | `session_velocity spike + 401 rate` |

---

## SOC Integration Design

### Alert Schema (alerts-* index)

```json
{
  "@timestamp": "2026-02-19T16:00:00Z",
  "severity": "CRITICAL",
  "attack_type": "SQL Injection",
  "source_ip": "10.10.5.200",
  "risk_score": 0.94,
  "rule": "SQL_INJECTION_RULE",
  "ml_score": 0.91,
  "behavioral_score": 0.88,
  "evidence": {
    "path": "/admin?id=1 OR 1=1",
    "request_rate": 45.2,
    "error_rate": 0.73
  }
}
```

### Alert Fatigue Reduction

- **Severity scoring** prevents alert flooding (only CRITICAL/WARNING paged)
- **Adaptive thresholds** reduce FPR over time as baseline stabilizes
- **Risk aggregation** across three detection layers — single event rarely triggers without multi-signal confirmation
- **Suppression window**: same IP/rule combination suppressed for 60s after first alert

---

## Adversarial Robustness

Tested against evasion techniques in `adversarial/evasion_techniques.py`:

| Technique | Description | Detection Impact |
|---|---|---|
| **Feature dilution** | Mix malicious requests with benign traffic | Partially evades rate rules; ML still detects anomaly |
| **Slow-and-low** | Reduce request rate below threshold | Behavioral deviation detects after baseline window |
| **Mimicry** | Copy benign path patterns in attack requests | Entropy analysis partially effective |
| **IP rotation** | Rotate source IPs per N requests | Reduces per-IP signals but aggregate detection holds |
| **Timing jitter** | Randomize inter-request intervals | Increases detection latency by ~30s |

---

## Hardening Checklist

- [x] TLS termination at Nginx boundary
- [x] Elasticsearch security disabled in dev (enable `xpack.security` for production)
- [x] No credentials in source code (use environment variables)
- [x] `.gitignore` excludes all secrets, model binaries, raw data
- [x] Audit logging via Elasticsearch `alerts-*` index
- [ ] JWT authentication on API endpoints (future)
- [ ] Role-based access control for dashboard (future)
- [ ] Network policy isolation in Kubernetes (future)

---

## Compliance Alignment

| Framework | Relevant Controls |
|---|---|
| **NIST CSF** | DE.AE (Anomaly Detection), RS.MI (Mitigation) |
| **MITRE ATT&CK** | Detection coverage for T1046 (Port Scan), T1110 (Brute Force), T1190 (Exploit Public App) |
| **SOC 2** | Monitoring and alerting controls |
