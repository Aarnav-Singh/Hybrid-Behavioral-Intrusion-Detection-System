"""
detectors/rule_engine.py
=========================
Deterministic Rule-Based Detection Engine.

Produces a rule_score in [0.0, 1.0] for use in the fusion engine.

Rules are defined as composable, data-driven objects rather than
hardcoded conditionals. This allows:
  - Adding/removing rules at runtime
  - Assigning severity weights per rule
  - Multi-condition rules (AND/OR logic)
  - A default rule set covering common attack signatures

Rule categories covered:
  - Port scanning
  - Brute force / credential stuffing
  - Data exfiltration
  - Privilege escalation
  - Lateral movement
  - Beaconing behaviour
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base Rule
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: float      # 0.0 to 1.0
    matched: bool
    evidence: dict


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    def __init__(self, rule_id: str, name: str, severity: float, description: str = ""):
        self.rule_id = rule_id
        self.name = name
        self.severity = float(severity)
        self.description = description

        if not (0.0 <= severity <= 1.0):
            raise ValueError(f"Rule severity must be in [0, 1], got {severity}")

    @abstractmethod
    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        """Return a RuleMatch for the given feature dict."""
        ...

    def _match(self, evidence: dict) -> RuleMatch:
        return RuleMatch(self.rule_id, self.name, self.severity, True, evidence)

    def _no_match(self) -> RuleMatch:
        return RuleMatch(self.rule_id, self.name, self.severity, False, {})


# ---------------------------------------------------------------------------
# Concrete Rules
# ---------------------------------------------------------------------------

class PortScanRule(BaseRule):
    """Detects horizontal or vertical port scanning."""

    def __init__(self, port_threshold: int = 50, conn_threshold: int = 100):
        super().__init__(
            "R001", "Port Scan Detection", severity=0.75,
            description="High unique port or destination count in short time window"
        )
        self.port_threshold = port_threshold
        self.conn_threshold = conn_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        unique_ports = features.get("unique_ports_1min", 0)
        unique_dsts = features.get("unique_dsts_1min", 0)
        conn_count = features.get("conn_count_1min", 0)

        if unique_ports >= self.port_threshold or (
            conn_count >= self.conn_threshold and unique_dsts >= 20
        ):
            return self._match({
                "unique_ports_1min": unique_ports,
                "unique_dsts_1min": unique_dsts,
                "conn_count_1min": conn_count,
                "port_threshold": self.port_threshold,
            })
        return self._no_match()


class BruteForceRule(BaseRule):
    """Detects brute force / credential stuffing attempts."""

    def __init__(self, failed_auth_threshold: int = 15):
        super().__init__(
            "R002", "Brute Force Detection", severity=0.85,
            description="Elevated failed authentication attempts"
        )
        self.failed_auth_threshold = failed_auth_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        failed = features.get("failed_auth_count", 0)
        if failed >= self.failed_auth_threshold:
            return self._match({"failed_auth_count": failed, "threshold": self.failed_auth_threshold})
        return self._no_match()


class PrivilegeEscalationRule(BaseRule):
    """Detects unusual privilege escalation."""

    def __init__(self, escalation_threshold: int = 1):
        super().__init__(
            "R003", "Privilege Escalation", severity=0.90,
            description="Unexpected privilege escalation event"
        )
        self.escalation_threshold = escalation_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        escalations = features.get("privilege_escalations", 0)
        if escalations >= self.escalation_threshold:
            return self._match({"privilege_escalations": escalations})
        return self._no_match()


class DataExfiltrationRule(BaseRule):
    """Detects large outbound data transfers."""

    def __init__(self, bytes_threshold: float = 100_000_000):  # 100 MB
        super().__init__(
            "R004", "Data Exfiltration", severity=0.80,
            description="Unusually large outbound data volume"
        )
        self.bytes_threshold = bytes_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        sent = features.get("bytes_sent", 0)
        if sent >= self.bytes_threshold:
            return self._match({
                "bytes_sent": sent,
                "threshold_bytes": self.bytes_threshold,
                "threshold_mb": self.bytes_threshold / 1e6,
            })
        return self._no_match()


class BeaconingRule(BaseRule):
    """
    Detects beaconing: high connection count with very short durations
    and low data volume — characteristic of C2 check-ins.
    """

    def __init__(
        self,
        min_conn_count: int = 30,
        max_duration: float = 2.0,
        max_bytes_per_conn: float = 500,
    ):
        super().__init__(
            "R005", "Beaconing / C2 Activity", severity=0.85,
            description="High-frequency short-duration low-volume connections (C2 pattern)"
        )
        self.min_conn = min_conn_count
        self.max_dur = max_duration
        self.max_bpc = max_bytes_per_conn

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        conn_count = features.get("conn_count_1min", 0)
        duration = features.get("conn_duration", 9999)
        bytes_sent = features.get("bytes_sent", 0)
        bytes_per_conn = bytes_sent / max(conn_count, 1)

        if (conn_count >= self.min_conn
                and duration <= self.max_dur
                and bytes_per_conn <= self.max_bpc):
            return self._match({
                "conn_count_1min": conn_count,
                "conn_duration": duration,
                "bytes_per_conn": round(bytes_per_conn, 2),
            })
        return self._no_match()


class LateralMovementRule(BaseRule):
    """
    Detects lateral movement: moderate conn count with many unique
    destinations and elevated failed auths.
    """

    def __init__(self, dst_threshold: int = 10, conn_threshold: int = 20):
        super().__init__(
            "R006", "Lateral Movement", severity=0.80,
            description="Connections to multiple internal destinations with auth failures"
        )
        self.dst_threshold = dst_threshold
        self.conn_threshold = conn_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        dsts = features.get("unique_dsts_1min", 0)
        conns = features.get("conn_count_1min", 0)
        failed = features.get("failed_auth_count", 0)

        if dsts >= self.dst_threshold and conns >= self.conn_threshold and failed >= 3:
            return self._match({
                "unique_dsts_1min": dsts,
                "conn_count_1min": conns,
                "failed_auth_count": failed,
            })
        return self._no_match()


class ProcessInjectionRule(BaseRule):
    """Detects abnormally high process spawn rates."""

    def __init__(self, spawn_threshold: int = 10):
        super().__init__(
            "R007", "Process Injection / Spawn Anomaly", severity=0.75,
            description="Unusually high child process spawn rate"
        )
        self.spawn_threshold = spawn_threshold

    def evaluate(self, features: Dict[str, float], context: dict) -> RuleMatch:
        spawns = features.get("process_spawns", 0)
        if spawns >= self.spawn_threshold:
            return self._match({"process_spawns": spawns, "threshold": self.spawn_threshold})
        return self._no_match()


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Runs all registered rules against an event and produces a combined
    rule_score in [0.0, 1.0] for use in the fusion engine.

    Score computation:
      - Each matched rule contributes its severity
      - Final score = 1 - product of (1 - severity_i) for all matched rules
        This is the "noisy-OR" combination — each rule independently
        boosts the final score without simple averaging (which would dilute high-severity hits).

    Usage:
        engine = RuleEngine()
        engine.load_default_rules()
        score, matches = engine.evaluate(features)
    """

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}
        logger.info("RuleEngine initialized")

    def register(self, rule: BaseRule):
        self._rules[rule.rule_id] = rule
        logger.debug(f"Rule registered: {rule.rule_id} ({rule.name})")

    def deregister(self, rule_id: str):
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.debug(f"Rule deregistered: {rule_id}")

    def load_default_rules(self) -> "RuleEngine":
        defaults = [
            PortScanRule(),
            BruteForceRule(),
            PrivilegeEscalationRule(),
            DataExfiltrationRule(),
            BeaconingRule(),
            LateralMovementRule(),
            ProcessInjectionRule(),
        ]
        for rule in defaults:
            self.register(rule)
        logger.info(f"Loaded {len(defaults)} default rules")
        return self

    def evaluate(
        self,
        features: Dict[str, float],
        context: Optional[dict] = None,
    ) -> Tuple[float, List[RuleMatch]]:
        """
        Evaluate all rules against the feature dict.

        Returns:
            (rule_score, list_of_matches)
            rule_score in [0.0, 1.0]
        """
        context = context or {}
        matches = []

        for rule in self._rules.values():
            try:
                match = rule.evaluate(features, context)
                if match.matched:
                    matches.append(match)
                    logger.debug(f"Rule fired: {match.rule_id} | {match.rule_name} | severity={match.severity}")
            except Exception as e:
                logger.warning(f"Rule {rule.rule_id} raised exception: {e}")

        # Noisy-OR combination
        if not matches:
            rule_score = 0.0
        else:
            product = 1.0
            for m in matches:
                product *= (1.0 - m.severity)
            rule_score = 1.0 - product

        return round(rule_score, 4), matches

    def list_rules(self) -> List[dict]:
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity,
                "description": r.description,
            }
            for r in self._rules.values()
        ]

    def rule_count(self) -> int:
        return len(self._rules)


# ---------------------------------------------------------------------------
# Quick sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    engine = RuleEngine().load_default_rules()
    print(f"Rules loaded: {engine.rule_count()}")

    normal = {
        "bytes_sent": 5000, "bytes_recv": 12000, "conn_count_1min": 8,
        "unique_ports_1min": 3, "unique_dsts_1min": 2, "failed_auth_count": 0,
        "conn_duration": 30, "privilege_escalations": 0, "process_spawns": 2,
    }
    score, matches = engine.evaluate(normal)
    print(f"\nNormal traffic → rule_score={score}, matches={[m.rule_id for m in matches]}")

    port_scan = {
        "bytes_sent": 200, "bytes_recv": 100, "conn_count_1min": 350,
        "unique_ports_1min": 280, "unique_dsts_1min": 90, "failed_auth_count": 45,
        "conn_duration": 0.2, "privilege_escalations": 2, "process_spawns": 15,
    }
    score, matches = engine.evaluate(port_scan)
    print(f"\nPort scan attack → rule_score={score}")
    for m in matches:
        print(f"  [{m.rule_id}] {m.rule_name} | severity={m.severity} | evidence={m.evidence}")
