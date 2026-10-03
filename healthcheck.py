#!/usr/bin/env python3
"""Service health checker: HTTP status, latency, and SSL expiry. Stdlib only.

Usage:
    python healthcheck.py                       # uses endpoints.json
    python healthcheck.py -c prod.json --json report.json
    SLACK_WEBHOOK_URL=https://hooks.slack.com/... python healthcheck.py --slack

Exit codes: 0 = all healthy, 1 = at least one check failed.
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

GREEN, RED, YELLOW, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def ssl_days_left(host, port=443, timeout=5):
    """Return days until the TLS certificate expires."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    return (expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def check(svc):
    """Run all checks for one service and return a result dict."""
    url = svc["url"]
    expected = svc.get("expected_status", 200)
    timeout = svc.get("timeout", 5)
    max_latency = svc.get("max_latency_ms", 2000)
    ssl_warn = svc.get("ssl_warn_days", 14)
    problems = []
    status, latency_ms, days_left = None, None, None

    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "devops-healthcheck/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:  # DNS failure, timeout, refused, TLS error...
        problems.append(f"unreachable: {type(e).__name__}: {e}")
    latency_ms = round((time.perf_counter() - start) * 1000)

    if status is not None:
        if status != expected:
            problems.append(f"status {status} (expected {expected})")
        if latency_ms > max_latency:
            problems.append(f"slow: {latency_ms}ms > {max_latency}ms")

    parsed = urlparse(url)
    if parsed.scheme == "https" and not problems:
        try:
            days_left = ssl_days_left(parsed.hostname, parsed.port or 443, timeout)
            if days_left < 0:
                problems.append("SSL certificate expired")
            elif days_left < ssl_warn:
                problems.append(f"SSL expires in {days_left} days")
        except Exception as e:
            problems.append(f"SSL check failed: {e}")

    return {
        "name": svc["name"], "url": url, "status": status,
        "latency_ms": latency_ms, "ssl_days_left": days_left,
        "healthy": not problems, "problems": problems,
    }


def print_table(results):
    print(f"\n{'SERVICE':<22}{'STATUS':<9}{'LATENCY':<10}{'SSL':<8}RESULT")
    print("-" * 70)
    for r in results:
        color = GREEN if r["healthy"] else RED
        ssl_txt = f"{r['ssl_days_left']}d" if r["ssl_days_left"] is not None else "-"
        verdict = "OK" if r["healthy"] else "; ".join(r["problems"])
        print(f"{r['name']:<22}{str(r['status'] or '-'):<9}{str(r['latency_ms']) + 'ms':<10}"
              f"{ssl_txt:<8}{color}{verdict}{RESET}")
    failed = sum(not r["healthy"] for r in results)
    summary = f"{len(results) - failed}/{len(results)} healthy"
    print(f"\n{(RED if failed else GREEN)}{summary}{RESET}\n")


def send_slack(webhook, results):
    bad = [r for r in results if not r["healthy"]]
    lines = [f":rotating_light: *{len(bad)} service(s) unhealthy*"]
    lines += [f"• *{r['name']}* ({r['url']}): {'; '.join(r['problems'])}" for r in bad]
    data = json.dumps({"text": "\n".join(lines)}).encode()
    req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", default="endpoints.json")
    p.add_argument("--json", metavar="FILE", help="write a JSON report to FILE")
    p.add_argument("--slack", action="store_true", help="post failures to SLACK_WEBHOOK_URL")
    p.add_argument("-w", "--workers", type=int, default=10)
    args = p.parse_args()

    with open(args.config) as f:
        services = json.load(f)["services"]

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(check, services))

    print_table(results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"checked_at": datetime.now(timezone.utc).isoformat(), "results": results}, f, indent=2)

    if args.slack and any(not r["healthy"] for r in results):
        webhook = os.environ.get("SLACK_WEBHOOK_URL")
        if webhook:
            send_slack(webhook, results)
        else:
            print(f"{YELLOW}--slack set but SLACK_WEBHOOK_URL is empty{RESET}", file=sys.stderr)

    sys.exit(1 if any(not r["healthy"] for r in results) else 0)


if __name__ == "__main__":
    main()
