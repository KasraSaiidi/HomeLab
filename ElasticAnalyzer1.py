"""
Elastic → Ollama Log Analyzer
Pulls logs directly from your Elasticsearch instance and analyzes with local LLM

Setup:
    Set environment variables before running:
        $env:ES_HOST = "your-elasticsearch-ip"
        $env:ES_USER = "elastic"
        $env:ES_PASS = "your-password"

Usage:
    python ElasticAnalyzer.py                      # Last 24 hours, all indexes
    python ElasticAnalyzer.py --hours 48           # Last 48 hours
    python ElasticAnalyzer.py --index winlogbeat-* # Specific index
    python ElasticAnalyzer.py --list               # List available indexes
"""

import os
import sys
import urllib3
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import ollama

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ES_HOST  = os.getenv("ES_HOST", "localhost")
ES_PORT  = int(os.getenv("ES_PORT", "9200"))
ES_USER  = os.getenv("ES_USER", "elastic")
ES_PASS  = os.getenv("ES_PASS", "")
ES_INDEX = os.getenv("ES_INDEX", "*")
MODEL      = os.getenv("OLLAMA_MODEL", "llama3.1")
CHUNK_SIZE = 3000    
MAX_LOGS   = 100     
OUTPUT_DIR = "reports"


SYSTEM_PROMPT = """You are an expert SOC analyst and threat hunter.
Analyze the provided log entries and identify:
1. Suspicious or malicious activity
2. Indicators of Compromise (IOCs) - IPs, domains, hashes, file paths
3. Attack techniques (map to MITRE ATT&CK if possible)
4. Severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO
5. Recommended immediate actions

Be concise and specific. Flag anything unusual even if uncertain."""


def connect_elastic() -> Elasticsearch:
    if not ES_PASS:
        print("ERROR: ES_PASS environment variable not set.")
        print("  Run: $env:ES_PASS = 'your-password'")
        sys.exit(1)

    print(f"  Connecting to Elasticsearch at {ES_HOST}:{ES_PORT}...")
    es = Elasticsearch(
        f"https://{ES_HOST}:{ES_PORT}",
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False
    )
    if not es.ping():
        print("ERROR: Cannot reach Elasticsearch. Check that:")
        print(f"  - Your SIEM is running")
        print(f"  - Elastic is up at {ES_HOST}:{ES_PORT}")
        print(f"  - You are on the same network or VPN")
        sys.exit(1)
    print("  Connected successfully")
    return es


def list_indexes(es: Elasticsearch):
    indexes = es.cat.indices(format="json")
    print("\nAvailable indexes:")
    for idx in indexes:
        print(f"  {idx['index']} ({idx['docs.count']} docs)")


def pull_logs(es: Elasticsearch, hours: int = 24, index: str = ES_INDEX) -> list[dict]:
    since = (datetime.now(tz=None) - timedelta(hours=hours)).isoformat()

    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": since,
                    "format": "strict_date_optional_time"
                }
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": MAX_LOGS
    }

    try:
        response = es.search(index=index, body=query)
        hits = response["hits"]["hits"]
        print(f"  Retrieved {len(hits)} log entries (last {hours}h)")
        return [hit["_source"] for hit in hits]
    except Exception:
        print(f"  Timestamp query failed, trying match_all...")
        query = {"query": {"match_all": {}}, "size": MAX_LOGS}
        response = es.search(index=index, body=query)
        hits = response["hits"]["hits"]
        print(f"  Retrieved {len(hits)} log entries")
        return [hit["_source"] for hit in hits]


def format_logs(logs: list[dict]) -> str:
    lines = []
    for log in logs:
        ts       = log.get("@timestamp", log.get("timestamp", "no-timestamp"))
        event_id = log.get("winlog", {}).get("event_id", "")
        message  = log.get("message", "")
        host     = log.get("host", {}).get("name", log.get("hostname", ""))
        user     = log.get("user", {}).get("name", "")
        process  = log.get("process", {}).get("name", "")
        src_ip   = log.get("source", {}).get("ip", "")
        dst_ip   = log.get("destination", {}).get("ip", "")

        parts = [f"[{ts}]"]
        if host:     parts.append(f"host={host}")
        if event_id: parts.append(f"event_id={event_id}")
        if user:     parts.append(f"user={user}")
        if process:  parts.append(f"process={process}")
        if src_ip:   parts.append(f"src={src_ip}")
        if dst_ip:   parts.append(f"dst={dst_ip}")
        if message:  parts.append(f"msg={message[:200]}")

        lines.append(" | ".join(parts))
    return "\n".join(lines)


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE) -> list[str]:
    chunks = []
    while len(text) > chunk_size:
        split_at = text.rfind("\n", 0, chunk_size)
        if split_at == -1:
            split_at = chunk_size
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    if text:
        chunks.append(text)
    return chunks


def analyze_chunk(chunk: str, chunk_num: int, total: int) -> str:
    print(f"  Analyzing chunk {chunk_num}/{total}...", end="", flush=True)

    prompt = f"""Analyze these log entries (chunk {chunk_num} of {total}):

---LOG START---
{chunk}
---LOG END---

SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
FINDINGS: [What you found]
IOCs: [IPs, domains, hashes, file paths]
MITRE: [ATT&CK technique if applicable]
ACTION: [Recommended response]"""

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        print(" done")
        return response["message"]["content"]
    except Exception as e:
        print(f" ERROR: {e}")
        return f"ERROR on chunk {chunk_num}: {e}"


def generate_summary(findings: list[str]) -> str:
    print("  Generating final report...")
    combined = "\n\n---CHUNK BREAK---\n\n".join(findings)

    prompt = f"""Consolidate these log analysis findings into a final incident report.
Do not use placeholder text like [Insert X] — either provide the value or omit the field.

{combined}

OVERALL SEVERITY:
INCIDENT SUMMARY:
KEY THREATS:
ALL IOCs:
MITRE ATT&CK:
PRIORITY ACTIONS:
TIMELINE:"""

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return response["message"]["content"]
    except Exception as e:
        return f"ERROR generating summary: {e}"


def save_report(findings: list[str], summary: str, hours: int, index: str) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_number = f"CASE-{timestamp}"
    report_path = os.path.join(OUTPUT_DIR, f"elastic_report_{timestamp}.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("ELASTIC SOC ANALYSIS REPORT\n")
        f.write(f"Case Number: {case_number}\n")
        f.write(f"Index: {index}\n")
        f.write(f"Time Range: Last {hours} hours\n")
        f.write(f"Model: {MODEL}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 70 + "\n")
        f.write(summary + "\n\n")

        f.write("=" * 70 + "\n")
        f.write("DETAILED CHUNK ANALYSIS\n")
        f.write("=" * 70 + "\n\n")

        for i, finding in enumerate(findings, 1):
            f.write(f"--- Chunk {i} ---\n{finding}\n\n")

    return report_path


def main():
    print(f"\n{'='*60}")
    print(f"ELASTIC → OLLAMA LOG ANALYZER")
    print(f"{'='*60}")

    hours = 24
    index = ES_INDEX

    if "--list" in sys.argv:
        es = connect_elastic()
        list_indexes(es)
        return

    if "--hours" in sys.argv:
        idx   = sys.argv.index("--hours")
        hours = int(sys.argv[idx + 1])

    if "--index" in sys.argv:
        idx   = sys.argv.index("--index")
        index = sys.argv[idx + 1]

    print(f"\nSettings:")
    print(f"  Elastic:  {ES_HOST}:{ES_PORT}")
    print(f"  Index:    {index}")
    print(f"  Range:    Last {hours} hours")
    print(f"  Model:    {MODEL}")
    print(f"  Max logs: {MAX_LOGS}")

    print(f"\n[1/4] Connecting to Elasticsearch:")
    es = connect_elastic()

    print(f"\n[2/4] Pulling logs:")
    logs = pull_logs(es, hours=hours, index=index)

    if not logs:
        print("No logs found in the specified time range.")
        print("Try: python ElasticAnalyzer.py --hours 168")
        return

    log_text = format_logs(logs)

    print(f"\n[3/4] Analyzing with {MODEL}:")
    chunks = chunk_text(log_text)
    print(f"  Split into {len(chunks)} chunk(s)")

    findings = []
    for i, chunk in enumerate(chunks, 1):
        result = analyze_chunk(chunk, i, len(chunks))
        findings.append(result)

    print(f"\n[4/4] Generating report:")
    summary = generate_summary(findings) if len(findings) > 1 else findings[0]

    report_path = save_report(findings, summary, hours, index)

    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(summary)
    print(f"\n[+] Report saved to: {report_path}")


if __name__ == "__main__":
    main()
