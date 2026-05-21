
import json
import os
import sys
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import ollama
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
ES_HOST = os.getenv('ELASTICSEARCH_HOST', "10.93.210.151")
ES_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
ES_INDEX = os.getenv('ELASTICSEARCH_INDEX', "*")
MODEL = os.getenv('LLM_MODEL', "qwen2.5:32b")
CHUNK_SIZE = int(os.getenv('LOG_CHUNK_SIZE', 8000))
MAX_LOGS = int(os.getenv('MAX_LOG_ENTRIES', 10))
OUTPUT_DIR = os.getenv('REPORT_OUTPUT_DIR', "reports")
ES_USER = "elastic"
ES_PASS = ""

# Logging Configuration
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Analyze these log entries:

---LOG START---
{log}
---LOG END---

SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
FINDINGS: [What you found]
IOCs: [IPs, domains, hashes, file paths]
MITRE: [ATT&CK technique if applicable]
ACTION: [Recommended response]"""

SUMMARY_PROMPT = """Consolidate these log analysis findings into a final incident report:

{findings}

OVERALL SEVERITY:
INCIDENT SUMMARY:
KEY THREATS:
ALL IOCs:
MITRE ATT&CK:
PRIORITY ACTIONS:
TIMELINE:"""


def connect_elastic():
    try:
        es = Elasticsearch(
            f"https://{ES_HOST}:{ES_PORT}",
            basic_auth=(ES_USER, ES_PASS),
            verify_certs=False
        )
        logger.info(f"Connected to Elasticsearch at {ES_HOST}:{ES_PORT}")
        return es
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        sys.exit(1)


def list_indexes(es):
    try:
        indices = es.indices.get_alias("*")
        for index in indices.keys():
            print(index)
    except Exception as e:
        logger.error(f"Error listing indexes: {e}")


def pull_logs(es, hours=24, index="*"):
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    query_body = {
        "size": MAX_LOGS,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lt": end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                }
            }
        }
    }

    try:
        response = es.search(index=index, body=query_body)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        logger.error(f"Failed to pull logs: {e}")
        sys.exit(1)


def format_logs(logs):
    lines = []
    for log in logs:
        parts = [
            f"{k}={v}" if isinstance(v, str) else f"{k}={json.dumps(v)}"
            for k, v in log.items()
        ]
        line = " | ".join(parts)
        lines.append(line)
    return "\n".join(lines)


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE) -> list:
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
    logger.info(f"Analyzing chunk {chunk_num}/{total}...")
    prompt = SYSTEM_PROMPT.format(log=chunk)

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": prompt}
            ],
        )
        logger.info(f"Chunk {chunk_num} analyzed successfully.")
        return response["message"]["content"]
    except Exception as e:
        logger.error(f"Error analyzing chunk {chunk_num}: {e}")
        return f"ERROR on chunk {chunk_num}: {e}"


def generate_summary(findings: list) -> str:
    combined = "\n\n---CHUNK BREAK---\n\n".join(findings)
    prompt = SUMMARY_PROMPT.format(findings=combined)

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": prompt}
            ],
        )
        return response["message"]["content"]
    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        return f"ERROR generating summary: {e}"


def save_report(findings: list, summary: str, hours: int, index: str) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(OUTPUT_DIR, f"elastic_report_{timestamp}.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("ELASTIC SOC ANALYSIS REPORT\n")
        f.write(f"Host: {ES_HOST}:{ES_PORT}\n")
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
    print("ELASTIC → Ollama LOG ANALYZER")
    print(f"{'='*60}")

    hours = 24
    index = ES_INDEX

    if "--list" in sys.argv:
        es = connect_elastic()
        list_indexes(es)
        return

    if "--hours" in sys.argv:
        idx = sys.argv.index("--hours")
        hours = int(sys.argv[idx + 1])

    if "--index" in sys.argv:
        idx = sys.argv.index("--index")
        index = sys.argv[idx + 1]

    logger.info(f"Elastic: {ES_HOST}:{ES_PORT}")
    logger.info(f"Index:   {index}")
    logger.info(f"Range:   Last {hours} hours")
    logger.info(f"Model:   {MODEL}")
    logger.info(f"Max logs: {MAX_LOGS}")

    logger.info("[1/4] Connecting to Elasticsearch...")
    es = connect_elastic()

    logger.info("[2/4] Pulling logs...")
    logs = pull_logs(es, hours=hours, index=index)

    if not logs:
        logger.warning("No logs found in the specified time range.")
        logger.warning("Try: python AnalyzerTest.py --hours 168")
        return

    log_text = format_logs(logs)

    logger.info(f"[3/4] Analyzing with {MODEL}...")
    chunks = chunk_text(log_text)
    logger.info(f"Split into {len(chunks)} chunk(s)")

    findings = []
    for i, chunk in enumerate(chunks, 1):
        result = analyze_chunk(chunk, i, len(chunks))
        findings.append(result)

    logger.info("[4/4] Generating report...")
    summary = generate_summary(findings) if len(findings) > 1 else findings[0]

    report_path = save_report(findings, summary, hours, index)

    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    logger.info(summary)
    logger.info(f"[+] Report saved to: {report_path}")


if __name__ == "__main__":
    print("\nUsage:")
    print("  python AnalyzerTest.py                        # Last 24 hours, all indexes")
    print("  python AnalyzerTest.py --hours 48             # Last 48 hours")
    print("  python AnalyzerTest.py --index winlogbeat-*   # Specific index")
    print("  python AnalyzerTest.py --list                 # List available indexes")
    print()
    main()
