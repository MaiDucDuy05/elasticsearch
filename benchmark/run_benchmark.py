"""
SIEM Benchmark — Elasticsearch Query Performance
================================================
Chạy 6 loại query SIEM (bao gồm fuzzy search),

Usage:
    python benchmark/run_benchmark.py
    python benchmark/run_benchmark.py --runs 50 --concurrency 10
"""

import sys
import time
import json
import argparse
import statistics
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))
from config import ES_HOST, ZEEK_INDEX, SNORT_INDEX
from bulk_indexer import get_client

# ─── Định nghĩa 5 loại SIEM query ─────────────────────────────────────────────

QUERIES = {
    "1_time_range_search": {
        "description": "Time-range search: lấy 100 Zeek events trong 1 giờ đầu",
        "index": ZEEK_INDEX,
        "body": {
            "size": 100,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "2012-03-16T12:00:00",
                        "lte": "2012-03-16T13:00:00"
                    }
                }
            },
            "_source": ["@timestamp", "source.ip", "destination.ip", "network.transport"]
        }
    },
    "2_top_source_ip": {
        "description": "Top 10 Source IP (Top Talkers) — aggregation",
        "index": ZEEK_INDEX,
        "body": {
            "size": 0,
            "query": {"match_all": {}},
            "aggs": {
                "top_src_ips": {
                    "terms": {
                        "field": "source.ip.keyword",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
    },
    "3_snort_severity_distribution": {
        "description": "Snort Alert: phân phối theo severity — aggregation",
        "index": SNORT_INDEX,
        "body": {
            "size": 0,
            "query": {"match_all": {}},
            "aggs": {
                "severity_dist": {
                    "terms": {
                        "field": "event.severity",
                        "size": 5
                    }
                }
            }
        }
    },
    "4_suspicious_connections": {
        "description": "Suspicious Connections: Zeek state=S0 (SYN no response)",
        "index": ZEEK_INDEX,
        "body": {
            "size": 50,
            "query": {
                "term": {
                    "zeek.conn.state": "S0"
                }
            },
            "_source": ["@timestamp", "source.ip", "destination.ip", "destination.port"]
        }
    },
    "5_traffic_volume_timeseries": {
        "description": "Traffic volume theo giờ — date_histogram aggregation",
        "index": ZEEK_INDEX,
        "body": {
            "size": 0,
            "query": {"match_all": {}},
            "aggs": {
                "traffic_per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour",
                        "min_doc_count": 1
                    },
                    "aggs": {
                        "total_bytes": {
                            "sum": {"field": "network.bytes"}
                        }
                    }
                }
            }
        }
    },
    "6_fuzzy_search": {
        "description": "Fuzzy search source IP ~ '192.168.*' (fuzziness=2) — relevance scoring",
        "index": ZEEK_INDEX,
        "body": {
            "size": 20,
            "query": {
                "fuzzy": {
                    "source.ip": {
                        "value": "192.168",
                        "fuzziness": "2"
                    }
                }
            },
            "_source": ["@timestamp", "source.ip", "destination.ip", "zeek.http.hostname"]
        }
    }
}


# ─── Hàm chạy một query và đo thời gian ──────────────────────────────────────

def run_query(client, index: str, body: dict) -> float:
    """Chạy một query, trả về thời gian (ms)."""
    start = time.perf_counter()
    client.search(index=index, body=body)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return elapsed_ms


def run_query_parallel(args):
    """Wrapper cho concurrent execution."""
    client, index, body = args
    return run_query(client, index, body)


# ─── Hàm tính percentile ─────────────────────────────────────────────────────

def percentile(data: list[float], p: float) -> float:
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)


# ─── Chạy benchmark cho 1 loại query ─────────────────────────────────────────

def benchmark_query(client, name: str, config: dict, runs: int, concurrency: int) -> dict:
    index = config["index"]
    body = config["body"]
    latencies = []

    if concurrency <= 1:
        for _ in range(runs):
            latencies.append(run_query(client, index, body))
    else:
        args_list = [(client, index, body)] * runs
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = list(executor.map(run_query_parallel, args_list))
        latencies = results

    total_time_s = sum(latencies) / 1000
    qps = runs / total_time_s if total_time_s > 0 else 0

    return {
        "query": name,
        "description": config["description"],
        "runs": runs,
        "concurrency": concurrency,
        "p50_ms": round(percentile(latencies, 50), 2),
        "p95_ms": round(percentile(latencies, 95), 2),
        "p99_ms": round(percentile(latencies, 99), 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
        "mean_ms": round(statistics.mean(latencies), 2),
        "qps": round(qps, 2),
    }


# ─── In bảng kết quả ─────────────────────────────────────────────────────────

def print_results(results: list[dict]):
    print("\n" + "=" * 80)
    print("  SIEM BENCHMARK RESULTS")
    print("=" * 80)
    header = f"  {'Query':<35} {'p50':>8} {'p95':>8} {'p99':>8} {'QPS':>8}"
    print(header)
    print("-" * 80)
    for r in results:
        name = r["query"][:33]
        print(f"  {name:<35} {r['p50_ms']:>7.1f}ms {r['p95_ms']:>7.1f}ms {r['p99_ms']:>7.1f}ms {r['qps']:>7.1f}")
    print("=" * 80)
    print()


# ─── Lưu kết quả ra file JSON ────────────────────────────────────────────────

def save_results(results: list[dict], output_path: Path):
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elasticsearch_host": ES_HOST,
        "results": results
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f">> Report saved to: {output_path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SIEM Elasticsearch Benchmark")
    parser.add_argument("--runs", type=int, default=30,
                        help="Số lần chạy mỗi query (default: 30)")
    parser.add_argument("--concurrency", type=int, default=1,
                        help="Số luồng concurrent (default: 1, sequential)")
    parser.add_argument("--output", type=Path,
                        default=Path("benchmark/results/benchmark_result.json"),
                        help="File lưu kết quả JSON")
    args = parser.parse_args()

    print(f"\n>> Connecting to Elasticsearch: {ES_HOST}")
    client = get_client()

    try:
        info = client.info()
        print(f">> Connected: cluster={info['cluster_name']}, version={info['version']['number']}")
    except Exception as e:
        print(f"!! Cannot connect to Elasticsearch: {e}")
        sys.exit(1)

    print(f"\n>> Running benchmark — {args.runs} runs/query, concurrency={args.concurrency}")
    print(f">> Total queries: {len(QUERIES)}")

    results = []
    for name, config in QUERIES.items():
        print(f"\n   [{name}] {config['description']}")
        try:
            result = benchmark_query(client, name, config, args.runs, args.concurrency)
            results.append(result)
            print(f"   p50={result['p50_ms']}ms  p95={result['p95_ms']}ms  p99={result['p99_ms']}ms  QPS={result['qps']}")
        except Exception as e:
            print(f"   !! ERROR: {e}")

    print_results(results)
    save_results(results, args.output)


if __name__ == "__main__":
    main()
