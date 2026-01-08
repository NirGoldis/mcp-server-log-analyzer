"""
FastMCP log analysis server example with multiple tools and embedded demo data.
"""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# -------------------------------------------------
# Load raw log data from file
# -------------------------------------------------
def load_logs_from_file(filename: str = "raw_logs.txt") -> List[str]:
    """Load logs from a txt file in the same directory as the script."""
    script_dir = Path(__file__).parent
    log_file = script_dir / filename
    
    with open(log_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

RAW_LOGS = load_logs_from_file()

# -------------------------------------------------
# MCP Server
# -------------------------------------------------
mcp = FastMCP("LogAnalyzerMultiTool", json_response=True)


# -------------------------------------------------
# Internal helper
# -------------------------------------------------
def parse_logs(raw_logs: List[str]) -> List[Dict]:
    parsed = []
    for line in raw_logs:
        try:
            ts, level, service, *msg = line.split(" ")
            parsed.append({
                "timestamp": datetime.fromisoformat(ts.replace("Z", "")),
                "level": level,
                "service": service,
                "message": " ".join(msg),
            })
        except Exception:
            parsed.append({
                "raw": line,
                "error": "failed_to_parse"
            })
    return parsed


# -------------------------------------------------
# TOOL 1: Parse logs
# -------------------------------------------------
@mcp.tool()
def parse_demo_logs() -> Dict:
    """
    Parse raw demo logs into structured format.
    """
    parsed = parse_logs(RAW_LOGS)
    return {
        "total_logs": len(RAW_LOGS),
        "parsed_logs": parsed,
    }


# -------------------------------------------------
# TOOL 2: Log level statistics
# -------------------------------------------------
@mcp.tool()
def log_level_stats() -> Dict:
    """
    Calculate log level distribution and error rate.
    """
    parsed = parse_logs(RAW_LOGS)
    levels = [l["level"] for l in parsed if "level" in l]

    return {
        "levels_distribution": Counter(levels),
        "error_rate": round(levels.count("ERROR") / max(len(levels), 1), 2),
    }


# -------------------------------------------------
# TOOL 3: Service-level aggregation
# -------------------------------------------------
@mcp.tool()
def service_error_summary() -> Dict:
    """
    Aggregate errors per service.
    """
    parsed = parse_logs(RAW_LOGS)
    service_errors = defaultdict(int)

    for log in parsed:
        if log.get("level") == "ERROR":
            service_errors[log["service"]] += 1

    return dict(service_errors)


# -------------------------------------------------
# TOOL 4: Detect suspicious behavior
# -------------------------------------------------
@mcp.tool()
def detect_security_signals() -> Dict:
    """
    Detect basic security-related signals.
    """
    parsed = parse_logs(RAW_LOGS)
    findings = []

    for log in parsed:
        msg = log.get("message", "").lower()
        if "invalid token" in msg or "suspicious" in msg:
            findings.append({
                "timestamp": str(log.get("timestamp")),
                "service": log.get("service"),
                "message": log.get("message"),
            })

    return {
        "security_events": findings,
        "count": len(findings),
    }


# -------------------------------------------------
# RESOURCE
# -------------------------------------------------
@mcp.resource("logs://raw")
def get_raw_logs() -> List[str]:
    """Return raw demo logs"""
    return RAW_LOGS


# -------------------------------------------------
# PROMPT
# -------------------------------------------------
@mcp.prompt()
def log_analysis_prompt(
    level_stats: dict,
    service_errors: dict,
    security_findings: dict,
) -> str:
    """
    Generate a consolidated prompt for LLM-based analysis.
    """
    return f"""
You are a senior SRE and security analyst.

Log level stats:
{level_stats}

Errors per service:
{service_errors}

Security-related findings:
{security_findings}

Tasks:
1. Identify the most problematic service
2. Suggest root causes
3. Recommend concrete remediation steps
4. Highlight any security risks
"""


# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")
