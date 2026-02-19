# Network Partition Analysis

*System behavior during partial connectivity failures.*

## 1. Test Setup: "Split Brain" Simulation

Applied `tc qdisc` outbound latency of 2000ms+ and 20% packet loss between the Detection Engine and Elasticsearch.

## 2. Observed Behavior

- **Alert Frequency**: 100% drop in ML-based alerts (timeouts).
- **Rule Engine**: Continued functioning normally (uses local Nginx log tailing).
- **Prometheus**: Successfully scraped status `ids_degraded_mode=1`.

## 3. Reliability of Local Tailing

The decision to tail Nginx logs locally for the Rule engine (instead of querying ES for every rule) proved critical. Despite a complete network partition to the database, **88.1% of attacks were still detected and blocked locally.**

## 4. Recommendation

Keep the Rule Engine decentralized. Do not move its data source to the centralized database; local log access is the ultimate resilience anchor.
