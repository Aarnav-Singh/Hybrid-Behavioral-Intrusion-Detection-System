"""
tests/load_test_suite.py
──────────────────────────
Locust load test suite for breaking point discovery and bottleneck identification.
"""
from locust import HttpUser, task, between, events
import random
import time


class LoadTestUser(HttpUser):
    """90% normal browsing, 10% attack traffic. Models production mix."""
    wait_time = between(1, 3)

    @task(9)
    def normal_traffic(self):
        endpoints = ["/", "/api/users", "/api/data", "/about", "/products",
                     "/api/products", "/login", "/api/orders"]
        self.client.get(random.choice(endpoints))

    @task(1)
    def attack_traffic(self):
        attacks = [
            "/api/data?id=' OR '1'='1",
            "/admin",
            "/.env",
            "/api/data?id=1 UNION SELECT username, password FROM users --",
            "/../../../../etc/passwd",
        ]
        self.client.get(random.choice(attacks))


class HighVolumeUser(HttpUser):
    """Simulates API client hammering endpoints — tests rate limits."""
    wait_time = between(0.1, 0.5)
    weight = 3

    @task
    def api_spam(self):
        self.client.get("/api/users")
        self.client.get("/api/orders")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print(f"\nLoad test starting — target: {environment.host}")
    print(f"Users: {environment.runner.target_user_count if hasattr(environment, 'runner') else 'N/A'}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.stats.total
    p95   = stats.get_response_time_percentile(0.95) if stats.num_requests > 0 else 0
    p99   = stats.get_response_time_percentile(0.99) if stats.num_requests > 0 else 0
    print(f"\n{'=' * 60}")
    print(f"Load Test Complete")
    print(f"{'=' * 60}")
    print(f"  Total requests:  {stats.num_requests:,}")
    print(f"  Failures:        {stats.num_failures:,} ({stats.num_failures/max(stats.num_requests,1):.1%})")
    print(f"  RPS (actual):    {stats.total_rps:.1f}")
    print(f"  P50 latency:     {stats.get_response_time_percentile(0.50):.0f}ms")
    print(f"  P95 latency:     {p95:.0f}ms")
    print(f"  P99 latency:     {p99:.0f}ms")
    print(f"{'=' * 60}")
    if p95 > 500 or stats.num_failures / max(stats.num_requests, 1) > 0.01:
        print("  ⚠  Breaking point reached: P95>500ms or failure rate >1%")
    else:
        print("  ✓  System stable at this load level")
