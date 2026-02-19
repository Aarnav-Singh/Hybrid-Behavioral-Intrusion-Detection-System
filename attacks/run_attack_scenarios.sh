#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# attacks/run_attack_scenarios.sh
# Orchestrates all Locust attack scenarios and captures results.
#
# USAGE
#   bash attacks/run_attack_scenarios.sh
#   bash attacks/run_attack_scenarios.sh --scenario dos
#   bash attacks/run_attack_scenarios.sh --scenario brute sqli
#
# OUTPUT
#   data/locust_results/<scenario>_<timestamp>.csv
#   data/locust_results/<scenario>_<timestamp>_stats.csv
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

HOST="${HOST:-http://localhost:8080}"
RESULTS_DIR="data/locust_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${BOLD}$1${NC}"; }

# ─── Preflight checks ────────────────────────────────────────────────────────
check_prerequisites() {
    header "Preflight Checks"

    # Check Nginx is up
    if curl -sf "$HOST/health" > /dev/null 2>&1; then
        info "Nginx reachable at $HOST"
    else
        warn "Nginx not reachable at $HOST — start with: docker-compose up -d nginx"
        exit 1
    fi

    # Check Locust installed
    if ! command -v locust &> /dev/null; then
        warn "Locust not installed. Run: pip install locust"
        exit 1
    fi

    info "Locust version: $(locust --version 2>&1 | head -1)"
    info "Results directory: $RESULTS_DIR"
    info "Timestamp prefix: $TIMESTAMP"
}

# ─── Wait helper ─────────────────────────────────────────────────────────────
wait_and_breathe() {
    local seconds=${1:-30}
    echo -e "\n${YELLOW}Cooling down ${seconds}s — allowing detection windows to reset...${NC}"
    sleep "$seconds"
}

# ─── Generic Locust runner ───────────────────────────────────────────────────
run_locust() {
    local scenario=$1
    local class=$2
    local users=$3
    local spawn_rate=$4
    local run_time=$5
    local csv_prefix="$RESULTS_DIR/${scenario}_${TIMESTAMP}"

    section "▶ Running: $scenario | Users=$users | SpawnRate=$spawn_rate | Duration=$run_time"

    locust \
        -f attacks/locustfile.py \
        "$class" \
        --users          "$users" \
        --spawn-rate     "$spawn_rate" \
        --run-time       "$run_time" \
        --host           "$HOST" \
        --headless \
        --only-summary \
        --csv            "$csv_prefix" \
        2>&1 | tee "$RESULTS_DIR/${scenario}_${TIMESTAMP}.log"

    info "Results saved → ${csv_prefix}_stats.csv"
}

# ─── Scenario: Fast Brute Force ──────────────────────────────────────────────
scenario_brute_force() {
    header "SCENARIO 1: Fast Brute Force"
    echo "Target rule     : LoginBruteForceRule"
    echo "Detection signal: >10 auth failures / 60s"
    echo "Expected result : Detected within 2 seconds (~10 requests)"
    echo ""

    run_locust "brute_force_fast" "AttackerBruteForce" 20 10 "2m"

    echo ""
    echo "Prometheus query to verify detection:"
    echo '  rate(ids_detections_total{rule_name="login_brute_force"}[1m])'
    echo ""
    echo "Elasticsearch query:"
    echo '  GET nginx-logs-*/_search'
    echo '  {"query": {"bool": {"must": [{"term": {"status": 403}}, {"term": {"request_uri": "/admin"}}]}}}'
}

# ─── Scenario: Slow Brute Force (evasion) ────────────────────────────────────
scenario_slow_brute_force() {
    header "SCENARIO 2: Slow Brute Force (Evasion)"
    echo "Target rule     : LoginBruteForceRule (evasion test)"
    echo "Evasion tech    : 9 attempts / 65s — just below 10/60s threshold"
    echo "Expected result : May evade rule; ML anomaly should catch pattern"
    echo ""

    run_locust "brute_force_slow" "AttackerSlowBruteForce" 5 1 "10m"

    echo ""
    echo "Prometheus query:"
    echo '  rate(ids_detections_total{rule_name="login_brute_force"}[5m])'
}

# ─── Scenario: SQL Injection ─────────────────────────────────────────────────
scenario_sql_injection() {
    header "SCENARIO 3: SQL Injection"
    echo "Target rule     : SQLInjectionRule"
    echo "Detection signal: OWASP regex patterns in URI"
    echo "Expected result : Detected on FIRST request (signature match)"
    echo ""

    run_locust "sql_injection" "AttackerSQLi" 10 5 "3m"

    echo ""
    echo "Prometheus query:"
    echo '  rate(ids_detections_total{rule_name="sql_injection"}[1m])'
    echo ""
    echo "Elasticsearch query (find SQLi events):"
    echo "  GET nginx-logs-*/_search"
    echo '  {"query": {"match": {"request_uri": "UNION SELECT"}}}'
}

# ─── Scenario: Path Traversal ────────────────────────────────────────────────
scenario_path_traversal() {
    header "SCENARIO 4: Path Traversal / LFI"
    echo "Target rule     : PathTraversalRule"
    echo "Detection signal: ../ and %2e%2e patterns in URI"
    echo "Expected result : Detected on first request"
    echo ""

    run_locust "path_traversal" "AttackerPathTraversal" 10 5 "3m"

    echo ""
    echo "Prometheus query:"
    echo '  rate(ids_detections_total{rule_name="path_traversal"}[1m])'
}

# ─── Scenario: Web Scanner ───────────────────────────────────────────────────
scenario_scanner() {
    header "SCENARIO 5: Web Scanner (High Entropy)"
    echo "Target rule     : ErrorRateSpikeRule + entropy-based detection"
    echo "Detection signal: High Shannon entropy (uniform endpoint access)"
    echo "Expected result : Detected after ~20 requests"
    echo ""

    run_locust "scanner" "AttackerScanner" 15 5 "5m"

    echo ""
    echo "Prometheus query:"
    echo '  ids_active_threat_ips{rule_name="error_rate_spike"}'
}

# ─── Scenario: Mixed realistic traffic ───────────────────────────────────────
scenario_mixed() {
    header "SCENARIO 6: Mixed Realistic Traffic (85% normal / 15% attack)"
    echo "File            : attacks/mixed_traffic.py"
    echo "Challenge       : IDS must maintain FPR ≤ 5% while catching attackers"
    echo ""

    local csv_prefix="$RESULTS_DIR/mixed_${TIMESTAMP}"
    locust \
        -f attacks/mixed_traffic.py \
        --users      100 \
        --spawn-rate 10 \
        --run-time   "15m" \
        --host       "$HOST" \
        --headless \
        --only-summary \
        --csv        "$csv_prefix" \
        2>&1 | tee "$RESULTS_DIR/mixed_${TIMESTAMP}.log"

    echo ""
    echo "Prometheus queries for mixed scenario:"
    echo '  # Alert rate by rule'
    echo '  rate(ids_detections_total[5m])'
    echo '  # False positive estimate'
    echo '  ids_false_positives_total'
    echo '  # Active threats'
    echo '  ids_active_threat_ips'
}

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary() {
    header "Run Complete"
    info "All scenario results saved to $RESULTS_DIR/"
    echo ""
    echo "  CSV files:"
    ls "$RESULTS_DIR"/*_"$TIMESTAMP"* 2>/dev/null | sed 's/^/    /'
    echo ""
    echo "  Prometheus UI:    http://localhost:9090"
    echo "  Kibana logs:      http://localhost:5601"
    echo "  MLflow runs:      http://localhost:5000"
    echo "  IDS metrics:      http://localhost:8000/metrics"
    echo "  Locust metrics:   http://localhost:9646/metrics"
    echo ""
    echo "  Next step: Fill in docs/attack_scenarios_template.md with results"
}

# ─── Main ────────────────────────────────────────────────────────────────────
# Parse --scenario flag
SCENARIOS_TO_RUN=()
if [[ $# -eq 0 ]]; then
    SCENARIOS_TO_RUN=("brute" "slow_brute" "sqli" "traversal" "scanner" "mixed")
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scenario) shift; SCENARIOS_TO_RUN+=("$1") ;;
            brute|slow_brute|sqli|traversal|scanner|mixed) SCENARIOS_TO_RUN+=("$1") ;;
            *) warn "Unknown argument: $1" ;;
        esac
        shift
    done
fi

check_prerequisites

for s in "${SCENARIOS_TO_RUN[@]}"; do
    case "$s" in
        brute)      scenario_brute_force ;;
        slow_brute) wait_and_breathe 30; scenario_slow_brute_force ;;
        sqli)       wait_and_breathe 30; scenario_sql_injection ;;
        traversal)  wait_and_breathe 30; scenario_path_traversal ;;
        scanner)    wait_and_breathe 30; scenario_scanner ;;
        mixed)      wait_and_breathe 60; scenario_mixed ;;
        *) warn "Unknown scenario: $s" ;;
    esac
done

print_summary
