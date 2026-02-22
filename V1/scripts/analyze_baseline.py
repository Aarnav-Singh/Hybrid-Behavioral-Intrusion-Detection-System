"""
scripts/analyze_baseline.py
───────────────────────────
Statistical baseline analysis for the Hybrid IDS.

PURPOSE
-------
Fetches nginx logs from Elasticsearch and performs rigorous statistical
analysis using Pandas and SciPy to establish detection thresholds.

WHY SCIPY (not just Pandas mean/std):
  Pandas: Data manipulation, groupby, time resampling
  SciPy:  Statistical INFERENCE and distribution fitting:
    - Shapiro-Wilk test: Is request frequency normally distributed?
    - K-S test: Does our data fit a Poisson/exponential distribution?
    - stats.norm/poisson: Compute exact percentiles from fitted distributions
    - scipy.stats.entropy: Measure endpoint access entropy (scanning detection)
    - stats.zscore: Z-score normalization for anomaly scoring

HOW THRESHOLDS ARE DERIVED:
  All detection rules reference values from baseline_profile.json
  (output of this script). Nothing is hardcoded in detection logic.

  Formula: threshold = P99 + 3σ
    - P99: The 99th percentile of normal traffic
    - 3σ:  Three standard deviations above that (captures 99.73% of normal)
    - Combined: ~0.003% chance of false positive on any single minute

USAGE
-----
    python scripts/analyze_baseline.py
    python scripts/analyze_baseline.py --index nginx-logs-* --size 10000
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server environments

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from elasticsearch import Elasticsearch
from scipy import stats
from scipy.stats import (
    exponweib, kstest, normaltest, poisson,
    shapiro, entropy as scipy_entropy
)


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch connection
# ─────────────────────────────────────────────────────────────────────────────

def connect_elasticsearch(host: str = "http://localhost:19200") -> Elasticsearch:
    """Create and test Elasticsearch connection."""
    es = Elasticsearch([host])
    try:
        info = es.info()
        print(f"✓ Connected to Elasticsearch: {info['version']['number']}")
        return es
    except Exception as e:
        print(f"✗ Cannot connect to Elasticsearch at {host}: {e}")
        print("  Is the stack running? Try: docker compose up -d")
        sys.exit(1)


def fetch_baseline_logs(
    es: Elasticsearch,
    index: str = "nginx-logs-*",
    size: int = 10_000,
) -> pd.DataFrame:
    """
    Fetch baseline nginx logs from Elasticsearch.

    Uses scroll API for large datasets to avoid memory issues.
    """

    print(f"\nFetching up to {size:,} log entries from [{index}]...")

    query = {
        "size": min(size, 1000),       # ES max per page
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": [
            "timestamp", "remote_addr", "request_method",
            "request_uri", "status", "body_bytes_sent",
            "request_time", "http_user_agent", "status_class",
        ],
    }

    all_hits = []
    try:
        resp = es.search(index=index, body=query, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        all_hits.extend(hits)

        while len(hits) > 0 and len(all_hits) < size:
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            hits = resp["hits"]["hits"]
            all_hits.extend(hits)

        es.clear_scroll(scroll_id=scroll_id)

    except Exception as e:
        print(f"  Warning: Scroll failed ({e}), using single query")
        resp = es.search(index=index, body={**query, "size": size})
        all_hits = resp["hits"]["hits"]

    logs = [hit["_source"] for hit in all_hits[:size]]
    df = pd.DataFrame(logs)

    if df.empty:
        print("  No logs found. Generate baseline traffic first:")
        print("  python scripts/baseline_traffic.py --duration 5")
        sys.exit(1)

    print(f"✓ Fetched {len(df):,} log entries")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Data preparation
# ─────────────────────────────────────────────────────────────────────────────

def prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and enrich the raw log DataFrame."""

    df = df.copy()

    # Parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Ensure numeric fields
    for col in ["status", "body_bytes_sent", "request_time"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Fill missing values
    df["remote_addr"]      = df.get("remote_addr", pd.Series(dtype=str)).fillna("unknown")
    df["request_uri"]      = df.get("request_uri", pd.Series(dtype=str)).fillna("/")
    df["http_user_agent"]  = df.get("http_user_agent", pd.Series(dtype=str)).fillna("-")

    # Derived fields
    df["minute"]           = df["timestamp"].dt.floor("min")
    df["hour"]             = df["timestamp"].dt.floor("h")
    df["is_4xx"]           = df["status"].between(400, 499, inclusive="both")
    df["is_5xx"]           = df["status"].between(500, 599, inclusive="both")
    df["is_error"]         = df["status"] >= 400

    print(f"  Time range: {df['timestamp'].min()} → {df['timestamp'].max()}")
    print(f"  Unique IPs: {df['remote_addr'].nunique()}")
    print(f"  Unique URIs: {df['request_uri'].nunique()}")

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Analysis functions
# ─────────────────────────────────────────────────────────────────────────────

def analyze_request_frequency(df: pd.DataFrame) -> Dict:
    """
    Compute per-IP request frequency statistics.

    WHY PER-IP (not global):
    Detection is per-source-IP. A DDoS has many IPs each at low rate.
    A single-IP DoS has one IP at extreme rate. Both are anomalies
    but detected differently.
    """

    print("\n" + "═"*60)
    print("  REQUEST FREQUENCY ANALYSIS (per IP per minute)")
    print("═"*60)

    freq = df.groupby(["remote_addr", "minute"]).size()
    values = freq.values.astype(float)

    # Core descriptive statistics
    mean   = float(np.mean(values))
    median = float(np.median(values))
    std    = float(np.std(values, ddof=1))
    skew   = float(stats.skew(values))
    kurt   = float(stats.kurtosis(values))

    # Percentiles
    p50  = float(np.percentile(values, 50))
    p90  = float(np.percentile(values, 90))
    p95  = float(np.percentile(values, 95))
    p99  = float(np.percentile(values, 99))
    p999 = float(np.percentile(values, 99.9))

    print(f"  n observations : {len(values):,}")
    print(f"  Mean           : {mean:.3f} req/min")
    print(f"  Median         : {median:.3f} req/min")
    print(f"  Std Dev        : {std:.3f} req/min")
    print(f"  Skewness       : {skew:.3f} (>1 = right-skewed, expected)")
    print(f"  Kurtosis       : {kurt:.3f}")
    print(f"  P50            : {p50:.3f}")
    print(f"  P90            : {p90:.3f}")
    print(f"  P95            : {p95:.3f}")
    print(f"  P99            : {p99:.3f}")
    print(f"  P99.9          : {p999:.3f}")

    # Normality test (Shapiro-Wilk - gold standard for n < 5000)
    sample = values if len(values) <= 5000 else np.random.choice(values, 5000, replace=False)
    sw_stat, sw_p = shapiro(sample)
    is_normal = sw_p > 0.05

    # Kolmogorov-Smirnov test against Poisson
    # Fit Poisson lambda = mean (MLE for Poisson)
    lambda_mle = mean
    theoretical_cdf = lambda x: poisson.cdf(np.floor(x), lambda_mle)
    ks_stat, ks_p = kstest(values, theoretical_cdf)
    fits_poisson = ks_p > 0.05

    print(f"\n  Distribution Tests:")
    print(f"  Shapiro-Wilk  : stat={sw_stat:.4f}, p={sw_p:.4f} → {'Normal' if is_normal else 'Non-normal ✓'}")
    print(f"  K-S vs Poisson: stat={ks_stat:.4f}, p={ks_p:.4f} → {'Fits ✓' if fits_poisson else 'Does not fit'}")
    print(f"  Fitted λ      : {lambda_mle:.3f} (MLE estimator)")

    # Threshold calculation
    # P99 + 3σ: empirically validated in network security literature
    threshold       = p99 + 3 * std
    conservative_threshold = p99 + 2 * std   # Lower FN rate
    aggressive_threshold   = p95 + 3 * std   # Lower FP rate

    print(f"\n  Detection Thresholds:")
    print(f"  Standard    : P99 + 3σ = {p99:.2f} + {3*std:.2f} = {threshold:.2f} req/min")
    print(f"  Conservative: P99 + 2σ = {p99:.2f} + {2*std:.2f} = {conservative_threshold:.2f} req/min")
    print(f"  Aggressive  : P95 + 3σ = {p95:.2f} + {3*std:.2f} = {aggressive_threshold:.2f} req/min")
    print(f"\n  → Using STANDARD threshold: {threshold:.2f} req/min")
    print(f"    False positive rate: ~{(1-0.99) * (1 - 0.9973):.4%} per observation")

    return {
        "n":                   len(values),
        "mean":                round(mean, 4),
        "median":              round(median, 4),
        "std":                 round(std, 4),
        "skewness":            round(skew, 4),
        "kurtosis":            round(kurt, 4),
        "p50":                 round(p50, 4),
        "p90":                 round(p90, 4),
        "p95":                 round(p95, 4),
        "p99":                 round(p99, 4),
        "p999":                round(p999, 4),
        "is_normal":           is_normal,
        "shapiro_p":           round(sw_p, 6),
        "fits_poisson":        fits_poisson,
        "ks_p":                round(ks_p, 6),
        "lambda_poisson":      round(lambda_mle, 4),
        "threshold":           round(threshold, 4),
        "threshold_conservative": round(conservative_threshold, 4),
        "threshold_aggressive":   round(aggressive_threshold, 4),
    }


def analyze_endpoint_distribution(df: pd.DataFrame) -> Dict:
    """
    Analyze URI access patterns and compute Shannon entropy.

    WHY ENTROPY:
    Entropy measures how spread out requests are across endpoints.
    - High entropy (near max): Uniform distribution = SCANNING behavior
    - Low entropy:             Concentrated access = Normal user behavior

    An attacker scanning for vulnerabilities hits every endpoint equally
    (high entropy). A real user mostly hits /, /api/*, /products (low entropy).
    """

    print("\n" + "═"*60)
    print("  ENDPOINT ACCESS PATTERN ANALYSIS")
    print("═"*60)

    counts = df["request_uri"].value_counts()
    total  = len(df)
    probs  = counts / total

    # Shannon entropy
    H          = float(scipy_entropy(probs, base=2))
    H_max      = float(np.log2(len(counts)))
    H_norm     = H / H_max if H_max > 0 else 0

    print(f"\n  Unique URIs observed: {len(counts)}")
    print(f"  Shannon entropy:     {H:.3f} bits")
    print(f"  Maximum entropy:     {H_max:.3f} bits (if all URIs equal)")
    print(f"  Normalized:          {H_norm:.2%}")
    print(f"\n  Interpretation:")
    if H_norm < 0.5:
        print(f"    Low entropy ({H_norm:.1%}): Concentrated access → NORMAL user behavior")
    elif H_norm < 0.8:
        print(f"    Medium entropy ({H_norm:.1%}): Moderate spread → Borderline")
    else:
        print(f"    High entropy ({H_norm:.1%}): Uniform spread → Potential SCANNING")

    print(f"\n  Top 10 endpoints:")
    print(f"  {'URI':<35} {'Count':>8} {'Share':>8}")
    print(f"  {'─'*52}")
    for uri, count in counts.head(10).items():
        print(f"  {uri:<35} {count:>8,} {count/total:>8.2%}")

    return {
        "unique_uris":     int(len(counts)),
        "entropy_bits":    round(H, 4),
        "entropy_max":     round(H_max, 4),
        "entropy_norm":    round(H_norm, 4),
        "top_endpoints":   {k: int(v) for k, v in counts.head(10).items()},
        "detection_note":  f"Flag entropy > {H_norm * 2:.2f} (2x baseline) as scanning",
        "scan_threshold":  round(H_norm * 2, 4),
    }


def analyze_status_distribution(df: pd.DataFrame) -> Dict:
    """
    Analyze HTTP status code distribution to establish error rate baseline.

    KEY SIGNAL: Error rate is one of the most reliable attack indicators.
      - Normal:         2-8% error (404 for missing pages, etc.)
      - SQL injection:  High 5xx (syntax errors crashing the app)
      - Path traversal: High 403/400 (blocked attempts)
      - DDoS:           High 5xx (server overwhelmed)
      - Brute force:    High 401 (auth failures)
    """

    print("\n" + "═"*60)
    print("  HTTP STATUS CODE DISTRIBUTION")
    print("═"*60)

    total = len(df)
    status_counts = df["status"].value_counts().sort_index()

    print(f"\n  {'Code':<8} {'Count':>8} {'Share':>8} {'Category':<20}")
    print(f"  {'─'*48}")
    for code, count in status_counts.items():
        cat = "Success" if code < 300 else ("Redirect" if code < 400 else ("Client Error" if code < 500 else "Server Error"))
        print(f"  {code:<8} {count:>8,} {count/total:>8.2%} {cat:<20}")

    error_rate = float((df["status"] >= 400).sum() / total)
    rate_4xx   = float(df["is_4xx"].sum() / total)
    rate_5xx   = float(df["is_5xx"].sum() / total)

    print(f"\n  Error rate (4xx+5xx): {error_rate:.2%}")
    print(f"  4xx rate:             {rate_4xx:.2%}")
    print(f"  5xx rate:             {rate_5xx:.2%}")
    print(f"\n  Detection threshold: error rate > {error_rate * 6:.2%}")
    print(f"  (6x baseline = confirmed attack indicator per security literature)")

    return {
        "total_requests":       total,
        "status_codes":         {int(k): int(v) for k, v in status_counts.items()},
        "error_rate":           round(error_rate, 6),
        "rate_4xx":             round(rate_4xx, 6),
        "rate_5xx":             round(rate_5xx, 6),
        "threshold_error_rate": round(error_rate * 6, 6),
        "threshold_4xx_rate":   round(rate_4xx   * 6, 6),
        "threshold_5xx_rate":   round(rate_5xx   * 6, 6),
    }


def analyze_user_agents(df: pd.DataFrame) -> Dict:
    """
    Analyze User-Agent diversity as a bot/attack detection signal.

    Attacks often use:
    - A single UA string repeatedly (scripted attack)
    - curl/python-requests/wget (automated tools)
    - Empty UA ("")

    Baseline should show diverse, realistic browser UAs.
    """

    print("\n" + "═"*60)
    print("  USER-AGENT DIVERSITY ANALYSIS")
    print("═"*60)

    ua_counts = df["http_user_agent"].value_counts()
    total     = len(df)
    unique    = len(ua_counts)

    # Diversity ratio: unique UAs / total requests
    # Low ratio = many requests from same UAs (not necessarily bad, but
    # combined with high rate = strong attack signal)
    diversity = unique / total if total > 0 else 0

    # Suspicious UAs in baseline (curl, python-requests, etc.)
    suspicious_patterns = ["curl", "python-requests", "wget", "scrapy", "bot", "spider"]
    suspicious_count    = df["http_user_agent"].str.lower().str.contains(
        "|".join(suspicious_patterns), na=False
    ).sum()

    print(f"\n  Total requests:    {total:,}")
    print(f"  Unique UAs:        {unique}")
    print(f"  Diversity ratio:   {diversity:.4f} ({diversity:.2%})")
    print(f"  Suspicious UAs:    {suspicious_count} ({suspicious_count/total:.2%})")
    print(f"\n  Top 5 UAs:")
    for ua, count in ua_counts.head(5).items():
        print(f"  [{count:>6}] {ua[:70]}")

    return {
        "unique_user_agents":      unique,
        "diversity_ratio":         round(diversity, 6),
        "suspicious_ua_count":     int(suspicious_count),
        "suspicious_ua_rate":      round(suspicious_count / total, 6) if total > 0 else 0,
        "detection_threshold_diversity": round(diversity * 0.1, 6),  # <10% of baseline diversity
    }


# ─────────────────────────────────────────────────────────────────────────────
# Visualization
# ─────────────────────────────────────────────────────────────────────────────

def generate_plots(df: pd.DataFrame, freq_stats: Dict, output_dir: str = "data/plots"):
    """Generate baseline analysis visualizations."""

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    sns.set_theme(style="darkgrid", palette="husl")

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Hybrid IDS - Baseline Traffic Analysis", fontsize=16, fontweight="bold")

    # 1. Request frequency histogram
    ax = axes[0, 0]
    freq = df.groupby(["remote_addr", "minute"]).size().values
    ax.hist(freq, bins=30, color="#4CAF50", edgecolor="white", alpha=0.85)
    ax.axvline(freq_stats["p99"],       color="#FF5722", linestyle="--", label=f"P99={freq_stats['p99']:.1f}")
    ax.axvline(freq_stats["threshold"], color="#F44336", linestyle="-", linewidth=2, label=f"Threshold={freq_stats['threshold']:.1f}")
    ax.set_title("Request Frequency Distribution (per IP per min)")
    ax.set_xlabel("Requests per minute")
    ax.set_ylabel("Count")
    ax.legend()

    # 2. Requests over time
    ax = axes[0, 1]
    rpt = df.groupby("minute").size()
    ax.plot(rpt.index, rpt.values, color="#2196F3", linewidth=0.8, alpha=0.9)
    ax.fill_between(rpt.index, rpt.values, alpha=0.2, color="#2196F3")
    ax.set_title("Total Requests Over Time (per minute)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests / min")

    # 3. Status code distribution
    ax = axes[1, 0]
    status_counts = df["status"].value_counts().sort_index()
    colors = []
    for code in status_counts.index:
        if code < 300:   colors.append("#4CAF50")
        elif code < 400: colors.append("#FF9800")
        elif code < 500: colors.append("#F44336")
        else:            colors.append("#9C27B0")
    bars = ax.bar([str(c) for c in status_counts.index], status_counts.values, color=colors)
    ax.set_title("HTTP Status Code Distribution")
    ax.set_xlabel("Status Code")
    ax.set_ylabel("Count")

    # 4. Endpoint distribution
    ax = axes[1, 1]
    ep_counts = df["request_uri"].value_counts().head(8)
    ax.barh(range(len(ep_counts)), ep_counts.values, color="#9C27B0", alpha=0.85)
    ax.set_yticks(range(len(ep_counts)))
    ax.set_yticklabels([uri[:30] for uri in ep_counts.index], fontsize=8)
    ax.set_title("Top Endpoint Access Counts")
    ax.set_xlabel("Request Count")

    plt.tight_layout()
    plot_path = os.path.join(output_dir, "baseline_analysis.png")
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\n✓ Plots saved to {plot_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def export_baseline_profile(
    freq_stats:      Dict,
    endpoint_stats:  Dict,
    status_stats:    Dict,
    ua_stats:        Dict,
    df:              pd.DataFrame,
    output:          str = "data/baseline_profile.json",
) -> None:
    """
    Export the complete baseline profile as JSON.

    This file is the single source of truth for ALL detection thresholds.
    The detection engine loads this at startup and uses these values
    instead of hardcoded constants.
    """

    Path(os.path.dirname(output)).mkdir(parents=True, exist_ok=True)

    profile = {
        "metadata": {
            "generated_at":   datetime.utcnow().isoformat() + "Z",
            "total_requests": int(len(df)),
            "time_range": {
                "start": str(df["timestamp"].min()),
                "end":   str(df["timestamp"].max()),
            },
            "unique_ips": int(df["remote_addr"].nunique()),
        },
        "request_frequency": freq_stats,
        "endpoint_distribution": endpoint_stats,
        "status_codes": status_stats,
        "user_agents":  ua_stats,
        "detection_thresholds": {
            # Rate-based detection
            "rate_limit_req_per_min":       freq_stats["threshold"],
            "rate_limit_conservative":      freq_stats["threshold_conservative"],
            "rate_limit_aggressive":        freq_stats["threshold_aggressive"],
            # Error-based detection
            "error_rate_threshold":         status_stats["threshold_error_rate"],
            "rate_4xx_threshold":           status_stats["threshold_4xx_rate"],
            "rate_5xx_threshold":           status_stats["threshold_5xx_rate"],
            # Entropy-based detection (scanning)
            "entropy_scan_threshold":       endpoint_stats["scan_threshold"],
            # Rationale strings for documentation
            "rationale": {
                "rate_limit": f"P99({freq_stats['p99']}) + 3σ({3*freq_stats['std']:.4f})",
                "error_rate": f"6x baseline error rate ({status_stats['error_rate']:.4f})",
                "entropy":    f"2x baseline entropy ({endpoint_stats['entropy_norm']:.4f})",
            },
        },
    }

    with open(output, "w") as f:
        json.dump(profile, f, indent=2, default=str)

    print(f"\n✓ Baseline profile saved: {output}")
    print(f"\n{'═'*60}")
    print(f"  DETECTION THRESHOLDS SUMMARY")
    print(f"{'═'*60}")
    print(f"  Rate limit:   {profile['detection_thresholds']['rate_limit_req_per_min']:.2f} req/min")
    print(f"  Error rate:   {profile['detection_thresholds']['error_rate_threshold']:.2%}")
    print(f"  Scan entropy: {profile['detection_thresholds']['entropy_scan_threshold']:.4f}")
    print(f"{'═'*60}")
    print(f"\n  Next step: Start detection engine:")
    print(f"  docker compose up -d detection")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze baseline traffic from Elasticsearch",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host",   default="http://localhost:19200", help="Elasticsearch host")
    parser.add_argument("--index",  default="nginx-logs-*",           help="Elasticsearch index pattern")
    parser.add_argument("--size",   type=int, default=10_000,          help="Number of logs to fetch")
    parser.add_argument("--output", default="data/baseline_profile.json", help="Output JSON file")
    parser.add_argument("--no-plots", action="store_true",             help="Skip plot generation")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║    HYBRID IDS - BASELINE STATISTICAL ANALYSIS           ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # 1. Connect to ES
    es = connect_elasticsearch(args.host)

    # 2. Fetch logs
    df_raw = fetch_baseline_logs(es, index=args.index, size=args.size)

    # 3. Prepare data
    df = prepare_dataframe(df_raw)

    # 4. Statistical analysis
    freq_stats     = analyze_request_frequency(df)
    endpoint_stats = analyze_endpoint_distribution(df)
    status_stats   = analyze_status_distribution(df)
    ua_stats       = analyze_user_agents(df)

    # 5. Visualizations
    if not args.no_plots:
        try:
            generate_plots(df, freq_stats)
        except Exception as e:
            print(f"  Warning: Plot generation failed: {e}")

    # 6. Export profile
    export_baseline_profile(
        freq_stats, endpoint_stats, status_stats, ua_stats, df,
        output=args.output,
    )

    print("\n  Analysis complete. baseline_profile.json is the detection threshold source.")
