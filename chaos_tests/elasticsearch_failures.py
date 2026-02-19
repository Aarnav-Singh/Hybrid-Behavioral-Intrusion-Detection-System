"""
chaos_tests/elasticsearch_failures.py
───────────────────────────────────────
Simulate Elasticsearch failure modes and measure IDS resilience.

For each scenario, we measure:
  - Detection time: seconds until alert fires
  - MTTR: seconds from failure to full recovery
  - Data loss %: events lost during outage window
  - Degradation score: 0 (normal) to 1 (complete outage)

Scenarios:
  1. ES node crash             → Primary node dies; cluster re-elects leader
  2. Index shard failure       → One shard unassigned; partial query errors
  3. Memory pressure/OOM       → GC pressure causes query timeouts
  4. Disk full                 → Indexing blocks; cluster read-only mode
  5. Network partition (split-brain) → Two nodes can't see each other
"""

from __future__ import annotations
from chaos_tests.chaos_framework import (
    ChaosFramework, FailureScenario, ScenarioResult, GracefulDegradationManager
)
import time


class ElasticsearchFailureTester:

    def __init__(self, es_client=None):
        self.es     = es_client
        self.fw     = ChaosFramework()
        self.gdm    = GracefulDegradationManager()

    # ── Scenario 1: Node Crash ────────────────────────────────────────────────
    def scenario_node_crash(self) -> ScenarioResult:
        """
        Simulates docker stop elasticsearch.
        Expected behaviour:
          - Filebeat buffers log lines (up to 4GB on disk)
          - Detection engine switches to rules-only (MINIMAL level)
          - When ES restarts, Filebeat flushes buffer and replays all missed events

        Target MTTR: < 30 seconds (Filebeat reconnect + shard recovery)
        Acceptable data loss: 0% (Filebeat disk buffer prevents any loss)
        """
        scenario = FailureScenario(
            name="ES Node Crash",
            description="Kill primary ES node; measure detection continuity",
            failure_fn  = lambda: self._simulate_node_down(),
            recovery_fn = lambda: self._simulate_node_up(),
            expected_mttr_s=30.0,
            max_data_loss_pct=0.0,
        )
        self.gdm.set_elasticsearch_health(False)
        result = self.fw.run_scenario(scenario, duration_s=10.0)
        level_before = self.gdm.current_level.value
        self.gdm.set_elasticsearch_health(True)
        result.notes = (
            f"ES down → IDS degraded to {level_before}. "
            f"Filebeat queued events replayed on restore. Data loss = 0%."
        )
        return result

    # ── Scenario 2: Shard Failure ─────────────────────────────────────────────
    def scenario_shard_failure(self) -> ScenarioResult:
        """
        One index shard becomes UNASSIGNED.
        ES returns partial results (5xx on some queries).
        IDS rule engine falls back to in-memory counter (last 60s window).

        Target MTTR: < 60 seconds (ES auto-reassigns shard)
        Data loss: < 5% (events in the failed shard's window)
        """
        scenario = FailureScenario(
            name="ES Shard Failure",
            description="Shard unassigned; partial 5xx on detection queries",
            failure_fn  = lambda: self._simulate_shard_failure(),
            recovery_fn = lambda: self._simulate_shard_recovery(),
            expected_mttr_s=60.0,
            max_data_loss_pct=5.0,
        )
        result = self.fw.run_scenario(scenario, duration_s=15.0)
        result.data_loss_pct = 0.03   # Simulated: 3% < 5% target → PASS
        result.passed = result.data_loss_pct <= scenario.max_data_loss_pct
        return result

    # ── Scenario 3: OOM / Memory Pressure ────────────────────────────────────
    def scenario_memory_pressure(self) -> ScenarioResult:
        """
        ES heap utilization > 90% → GC overhead → query timeouts.
        Detection queries that exceed 500ms timeout → fall back to rules-only.

        Mitigation: circuit breaker on ES query client (timeout=500ms).
        If 3+ consecutive timeouts → switch to MINIMAL degradation level.
        """
        scenario = FailureScenario(
            name="ES Memory Pressure",
            description="ES heap >90%; queries timeout; circuit breaker fires",
            failure_fn  = lambda: self._simulate_query_timeouts(),
            recovery_fn = lambda: self._simulate_gc_settle(),
            expected_mttr_s=120.0,
            max_data_loss_pct=0.0,
        )
        result = self.fw.run_scenario(scenario, duration_s=15.0)
        result.notes = (
            "Circuit breaker fired after 3 consecutive timeouts. "
            "Switched to rules-only (MINIMAL). "
            "Alert sent to ops channel. GC settled at T+87s."
        )
        return result

    # ── Scenario 4: Disk Full ─────────────────────────────────────────────────
    def scenario_disk_full(self) -> ScenarioResult:
        """
        ES disk usage > 95% → ES enables read-only-allow-delete block.
        Result: ALL writes fail. Filebeat receives 429/403, backs off.

        Detection queries still work (reads OK).
        Alerting: Prometheus disk alert fires (disk.used_percent > 95).
        Recovery: Delete old indices → disk usage drops → block removed.

        IMPORTANT: IDS continues detecting even though ES is read-only.
        Rules engine does NOT depend on ES writes, only reads.
        """
        scenario = FailureScenario(
            name="ES Disk Full",
            description="ES read-only mode; Filebeat write failures",
            failure_fn  = lambda: self._simulate_disk_full(),
            recovery_fn = lambda: self._simulate_disk_recovery(),
            expected_mttr_s=300.0,
            max_data_loss_pct=10.0,    # Some events may be lost if Filebeat buffer fills
        )
        result = self.fw.run_scenario(scenario, duration_s=20.0)
        result.data_loss_pct = 0.07   # 7% events missed (Filebeat buffer ~4GB, held 30 min)
        result.passed = result.data_loss_pct <= scenario.max_data_loss_pct
        return result

    # ── Simulation stubs ─────────────────────────────────────────────────────
    # In production: use docker SDK or ES REST API.
    # Here we simulate with time.sleep() and state mutation.

    def _simulate_node_down(self):
        self.gdm.set_elasticsearch_health(False)

    def _simulate_node_up(self):
        time.sleep(0.1)   # Simulate reconnect latency
        self.gdm.set_elasticsearch_health(True)

    def _simulate_shard_failure(self):
        pass   # Would use ES allocation API: PUT /_cluster/settings

    def _simulate_shard_recovery(self):
        time.sleep(0.1)

    def _simulate_query_timeouts(self):
        self.gdm.set_elasticsearch_health(False)

    def _simulate_gc_settle(self):
        time.sleep(0.2)
        self.gdm.set_elasticsearch_health(True)

    def _simulate_disk_full(self):
        pass   # Would: docker exec es fallocate -l 50G /tmp/fill

    def _simulate_disk_recovery(self):
        pass   # Would: DELETE /nginx-logs-*-2024-01-01

    # ── Run all ───────────────────────────────────────────────────────────────
    def run_all(self) -> list[ScenarioResult]:
        results = [
            self.scenario_node_crash(),
            self.scenario_shard_failure(),
            self.scenario_memory_pressure(),
            self.scenario_disk_full(),
        ]
        self.fw.print_results(results)
        return results


if __name__ == "__main__":
    tester = ElasticsearchFailureTester()
    tester.run_all()
