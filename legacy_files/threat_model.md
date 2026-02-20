# Threat Model — Hybrid Behavioral Intrusion Detection System

## 1. Overview

This document defines the formal threat model for the Hybrid Behavioral IDS (HBIDS). It specifies what the system is designed to detect, what assumptions it makes about the environment, and the boundaries of its detection capability.

A threat model is not optional documentation — it is what separates a research-grade security system from an engineering project. It forces explicit reasoning about adversary capability and system limitations.

---

## 2. System Assets and Scope

The HBIDS protects the following assets:

| Asset | Description |
|---|---|
| Network endpoints | Hosts generating traffic (workstations, servers, IoT) |
| Authentication systems | Login infrastructure (SSH, Kerberos, LDAP, AD) |
| Internal services | Databases, file servers, internal APIs |
| Privileged accounts | Accounts with escalated access |
| Sensitive data stores | Repositories containing confidential data |

**Out of scope:** Encrypted payload content, physical security, application-layer logic (e.g., SQL injection), social engineering.

---

## 3. Attacker Model

### 3.1 Attacker Capability

HBIDS is designed to detect adversaries across the following capability spectrum:

| Level | Description | Example | Detectable? |
|---|---|---|---|
| L1 — Script Kiddie | Automated tools, no evasion | Metasploit default configs, masscan | ✅ Yes (Rules + ML) |
| L2 — Skilled Attacker | Manual techniques, basic evasion | Slow scans, mimicry | ✅ Yes (Behavioral) |
| L3 — Advanced Persistent Threat | Long-dwell, custom tooling, living-off-the-land | APT groups | ⚠️ Partial |
| L4 — Nation-State | Zero-days, supply chain compromise, AI-assisted | — | ❌ Out of scope |

### 3.2 Attacker Position

| Position | Description | Detection Confidence |
|---|---|---|
| External | Attacking from outside the network perimeter | HIGH |
| Compromised endpoint | Attacker on an internal host | MEDIUM–HIGH |
| Insider threat | Legitimate user with malicious intent | MEDIUM |
| Compromised admin | Privileged insider | LOW–MEDIUM |

### 3.3 Attacker Goals (in order of difficulty to detect)

1. **Reconnaissance** — port scanning, service fingerprinting
2. **Credential access** — brute force, credential stuffing, phishing aftermath
3. **Lateral movement** — pivoting between internal hosts
4. **Privilege escalation** — gaining elevated access
5. **Command and control** — maintaining persistent communication
6. **Data exfiltration** — removing sensitive data
7. **Impact** — ransomware, destructive attacks

---

## 4. Attack Scenarios Covered

### 4.1 Port Scanning

**Description:** Systematic scanning of ports/hosts to enumerate network topology.

**Evasion technique considered:** Slow scan (1 packet per minute to evade rate-based detection).

**Detection approach:** Behavioral baseliner detects per-entity deviation in `unique_ports_1min` and `conn_count_1min`. Even slow scans accumulate anomaly evidence over time.

**Known limitation:** Distributed scanning (many source IPs each scanning a small number of ports) is harder to detect without cross-entity correlation.

---

### 4.2 Brute Force / Credential Stuffing

**Description:** Repeated authentication attempts against a service.

**Evasion technique considered:** Password spraying (one password across many accounts) to stay below per-account lockout thresholds.

**Detection approach:** Rule R002 triggers on `failed_auth_count` threshold. Behavioral baseliner detects when an entity's failure rate deviates from its own baseline (even if absolute count is low).

**Known limitation:** Slow spray attacks (one attempt per hour) may evade threshold-based rules but will be caught by behavioral drift over time.

---

### 4.3 Data Exfiltration

**Description:** Large outbound data transfers to external destinations.

**Evasion technique considered:** Slow exfil — transferring data in small chunks over a long period to avoid volume-based detection.

**Detection approach:** Rule R004 catches volume spikes. For slow exfil, behavioral baseliner tracks `bytes_sent` EMA and flags sustained elevation above entity baseline.

**Known limitation:** Exfiltration over allowed cloud services (e.g., uploading to attacker-controlled S3 bucket) is difficult to distinguish from legitimate cloud sync at the feature level. Requires URL/DNS analysis (not currently in scope).

---

### 4.4 Command and Control Beaconing

**Description:** Compromised host periodically communicates with C2 server.

**Evasion technique considered:** Jittered beacon intervals to avoid periodic pattern detection.

**Detection approach:** Rule R005 identifies high-frequency, low-volume, short-duration connection patterns. Behavioral baseliner detects deviation from entity's normal connection rhythm.

**Known limitation:** Beaconing over HTTPS to legitimate-looking domains bypasses connection-pattern analysis. DNS analysis would be required.

---

### 4.5 Lateral Movement

**Description:** Attacker moves from compromised host to other internal systems.

**Evasion technique considered:** "Living off the land" — using legitimate admin tools (PsExec, WMI, RDP) that generate normal-looking traffic.

**Detection approach:** Rule R006 flags multi-destination connections with auth failures. Behavioral baseliner detects when an entity suddenly connects to new destinations it has never contacted before (`unique_dsts_1min` deviation).

**Known limitation:** An attacker who studies the target's normal traffic patterns and perfectly mimics them will evade behavioral detection.

---

### 4.6 Privilege Escalation

**Description:** Attacker gains elevated access beyond initial foothold permissions.

**Evasion technique considered:** Gradual escalation — acquiring privileges incrementally to avoid sudden spikes.

**Detection approach:** Rule R003 fires on any `privilege_escalations > 0` for entities where this is not baseline behaviour. Behavioral baseliner flags entities whose escalation count deviates from their own history.

---

## 5. Evasion Assumptions

The following adversarial evasion techniques are explicitly considered in system design:

| Evasion Technique | Description | System Response |
|---|---|---|
| Low-and-slow | Spreading attack activity over time | EMA-based baseliner accumulates evidence |
| Mimicry | Imitating normal traffic patterns | Per-entity profiling makes global mimicry harder |
| Threshold evasion | Staying just below rule thresholds | Behavioral scoring complements rigid thresholds |
| Log poisoning | Injecting false normal events to corrupt baseline | EMA limits influence of individual events; large-scale poisoning detectable as drift |
| Concept drift exploitation | Triggering model retraining with adversarial inputs | Warmup period and drift detection limit rapid baseline corruption |
| Distributed attack | Splitting attack across many source entities | Current scope: per-entity; cross-entity correlation is future work |

---

## 6. Concept Drift

Concept drift — gradual changes in normal traffic patterns over time — is a first-class concern for the system.

### 6.1 Sources of Drift

- **Organic growth:** More users, more traffic, new services deployed
- **Business cycle changes:** Backup windows, end-of-quarter reporting spikes
- **Infrastructure changes:** New cloud services, VPN rollouts, remote work policy changes
- **Seasonal patterns:** Holiday reduced traffic, conference-period peaks

### 6.2 Drift Handling in HBIDS

| Mechanism | How it handles drift |
|---|---|
| EMA (α=0.05) on behavioral features | Gradually adapts baseline to new normal without wholesale retraining |
| Time-bucket profiling | Separates day/night/weekend patterns to reduce false positives from schedule drift |
| ML partial_update buffer | Periodic Isolation Forest retraining as new normal data accumulates |
| Adaptive fusion weights | Reduces weight of detector that becomes noisy during drift periods |

### 6.3 Drift That Cannot Be Handled

Sudden, complete replacement of all traffic patterns (e.g., complete network re-architecture overnight) will require manual baseline reset. This is a known limitation.

---

## 7. Assumptions About the Environment

The following assumptions must hold for HBIDS to operate correctly:

| Assumption | Consequence if violated |
|---|---|
| Feature extraction is accurate and tamper-resistant | Attackers who can manipulate log sources can evade detection |
| Training data is predominantly benign | Contaminated training data degrades ML detector performance |
| Network is reasonably stable during baseline warmup | Attacks during warmup period are scored with lower confidence |
| Entity IDs (IPs, usernames) are reliable | IP spoofing or DHCP churn would cause profile misattribution |
| Feature values are numeric and bounded | Extreme outlier injection (e.g., negative byte counts) is sanitised |

---

## 8. What HBIDS Does NOT Detect

It is equally important to be explicit about detection gaps:

- **Zero-day exploits** with no observable behavioral change
- **Insider abuse within normal behavioral profile** (e.g., admin exfiltrating data using normal admin tools at normal volumes)
- **Encrypted C2 over legitimate services** (Slack, GitHub, DNS over HTTPS)
- **Physical access attacks**
- **Application-layer attacks** (SQL injection, XSS) — these require WAF/RASP
- **Supply chain compromise** at build-time
- **Social engineering / phishing** at the email level

---

## 9. False Positive Analysis

High false positive rates are the primary reason IDS deployments fail in practice. HBIDS explicitly addresses this through hybrid scoring:

| Detector alone | FP characteristic |
|---|---|
| Rule-only | Low FP for known signatures, high FP for tuned thresholds on variable traffic |
| ML-only | Higher FP during concept drift; no context awareness |
| Behavioral-only | Low FP once warmed up; blind to never-before-seen entity attacks |
| **Hybrid (all three)** | Noisy-OR fusion requires corroboration — single-detector noise is damped |

The fusion engine's weighted scoring means a false positive from one detector is dampened unless corroborated by at least one other. This is the primary architectural mechanism for false positive reduction.

---

## 10. Limitations Summary

| Limitation | Priority for future work |
|---|---|
| No cross-entity correlation (distributed attacks) | HIGH |
| No DNS/HTTP payload analysis | HIGH |
| Log poisoning resistance is partial | MEDIUM |
| Nation-state adversaries out of scope | LOW (by design) |
| No real-time rule update without restart | MEDIUM |

---

*Last updated: 2025 | Version 1.0*
