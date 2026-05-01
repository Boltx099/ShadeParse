"""
ShadeParse SIEM Backend
=======================
Lightweight SIEM engine — log ingestion, parsing, detection, correlation,
and risk scoring.  Designed as a natural extension of ShadeParse's existing
pipeline architecture.

Run with:  python siem_backend.py
Endpoint:  POST /siem/analyze   — upload or paste logs
           GET  /siem/results   — latest analysis results
           GET  /siem/status    — health check
"""

from __future__ import annotations

import re
import io
import csv
import json
import time
import math
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# ── Flask ──────────────────────────────────────────────────────────────────────
try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    raise SystemExit(
        "Install deps first:  pip install flask flask-cors"
    )

app = Flask(__name__)
CORS(app)          # allow ShadeParse frontend to call the API

# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 1 — LOG INGESTION
#  Accept raw text, .log, .json, .csv — normalize to a list of raw strings.
# ─────────────────────────────────────────────────────────────────────────────

def ingest_logs(raw: str, fmt: str = "auto") -> list[str]:
    """
    Normalize any supported log format into a plain list of line strings
    that downstream parsers can work with uniformly.

    Supported formats (auto-detected when fmt='auto'):
      • plain text / .log  — one entry per line
      • JSON array          — each element serialized back to a string
      • JSONL               — one JSON object per line
      • CSV                 — rows joined as "key=value ..." strings
    """
    lines: list[str] = []

    stripped = raw.strip()
    if not stripped:
        return lines

    # ── JSON array or JSONL ──
    if fmt == "json" or (fmt == "auto" and stripped.startswith("[")):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                for entry in data:
                    lines.append(json.dumps(entry) if isinstance(entry, dict) else str(entry))
                return lines
        except json.JSONDecodeError:
            pass

    # ── JSONL (one object per line) ──
    if fmt in ("jsonl", "auto"):
        try:
            candidates = [json.loads(ln) for ln in stripped.splitlines() if ln.strip()]
            if all(isinstance(c, dict) for c in candidates):
                for obj in candidates:
                    lines.append(json.dumps(obj))
                return lines
        except (json.JSONDecodeError, ValueError):
            pass

    # ── CSV ──
    if fmt == "csv" or (fmt == "auto" and "," in stripped.splitlines()[0]):
        try:
            reader = csv.DictReader(io.StringIO(stripped))
            rows = list(reader)
            if rows:
                for row in rows:
                    lines.append(" ".join(f'{k}={v}' for k, v in row.items()))
                return lines
        except Exception:
            pass

    # ── Plain text / .log (default) ──
    lines = [ln for ln in stripped.splitlines() if ln.strip()]
    return lines


# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 2 — LOG PARSER
#  Extract structured fields from raw log lines.
# ─────────────────────────────────────────────────────────────────────────────

# Common log patterns
_RE_IP        = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_RE_TS_ISO    = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)')
_RE_TS_CLF    = re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]')
_RE_METHOD    = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+([^\s"]+)\s+HTTP/[\d.]+?"')
_RE_STATUS    = re.compile(r'"\s+(\d{3})\s+')
_RE_UA        = re.compile(r'"([^"]{10,})"$')
_RE_PAYLOAD   = re.compile(r'(?:payload|body|data|query)[:=\s]*([^\s&;,\]]+)', re.I)
_RE_KEY_VAL   = re.compile(r'([a-z_][a-z0-9_]*)[:=]"?([^"\s,}]+)"?', re.I)


def parse_line(raw: str) -> dict[str, Any]:
    """
    Parse a single log line and return a structured dict.
    Fields extracted: ip, timestamp, method, endpoint, status, user_agent,
                      payload, raw
    """
    entry: dict[str, Any] = {"raw": raw, "ip": None, "timestamp": None,
                              "method": None, "endpoint": None, "status": None,
                              "user_agent": None, "payload": None}

    # ── Try JSON log first ──
    if raw.strip().startswith("{"):
        try:
            obj = json.loads(raw)
            entry["ip"]         = obj.get("ip") or obj.get("remote_addr") or obj.get("client_ip")
            entry["timestamp"]  = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp")
            entry["method"]     = obj.get("method") or obj.get("http_method")
            entry["endpoint"]   = obj.get("endpoint") or obj.get("path") or obj.get("url") or obj.get("uri")
            entry["status"]     = str(obj.get("status") or obj.get("status_code") or "")
            entry["user_agent"] = obj.get("user_agent") or obj.get("ua")
            entry["payload"]    = obj.get("payload") or obj.get("body") or obj.get("query")
        except json.JSONDecodeError:
            pass

    # ── Fallback regex extraction ──
    if not entry["ip"]:
        m = _RE_IP.search(raw)
        entry["ip"] = m.group(1) if m else None

    if not entry["timestamp"]:
        m = _RE_TS_ISO.search(raw) or _RE_TS_CLF.search(raw)
        entry["timestamp"] = m.group(1) if m else None

    if not entry["method"]:
        m = _RE_METHOD.search(raw)
        if m:
            entry["method"]   = m.group(1)
            entry["endpoint"] = m.group(2)

    if not entry["status"]:
        m = _RE_STATUS.search(raw)
        entry["status"] = m.group(1) if m else None

    if not entry["user_agent"]:
        m = _RE_UA.search(raw)
        entry["user_agent"] = m.group(1) if m else None

    if not entry["payload"]:
        m = _RE_PAYLOAD.search(raw)
        entry["payload"] = m.group(1) if m else None

    # ── Fallback: key=value extraction for custom formats ──
    if not entry["ip"]:
        kv = dict(_RE_KEY_VAL.findall(raw))
        entry["ip"]        = kv.get("ip") or kv.get("src") or kv.get("client")
        entry["method"]    = entry["method"] or kv.get("method")
        entry["endpoint"]  = entry["endpoint"] or kv.get("path") or kv.get("url")
        entry["status"]    = entry["status"] or kv.get("status")

    return entry


def parse_logs(lines: list[str]) -> list[dict]:
    """Parse all ingested lines into structured log entries."""
    return [parse_line(ln) for ln in lines]


# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 3 — DETECTION ENGINE
#  Rule-based detection similar to Sigma logic.
# ─────────────────────────────────────────────────────────────────────────────

# ── SQL Injection patterns ──
_SQLI = [
    re.compile(r"'\s*OR\s+['\"0-9]", re.I),
    re.compile(r"UNION\s+SELECT", re.I),
    re.compile(r"DROP\s+TABLE", re.I),
    re.compile(r"--\s*$", re.M),
    re.compile(r";\s*SELECT\b", re.I),
    re.compile(r"xp_cmdshell", re.I),
    re.compile(r"SLEEP\s*\(\d+\)", re.I),
    re.compile(r"BENCHMARK\s*\(", re.I),
    re.compile(r"1\s*=\s*1", re.I),
    re.compile(r"CHAR\s*\(\d+\)", re.I),
    re.compile(r"(?:INSERT|UPDATE|DELETE)\s+INTO", re.I),
    re.compile(r"INFORMATION_SCHEMA", re.I),
]

# ── XSS patterns ──
_XSS = [
    re.compile(r"<script[\s>]", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"on(?:load|click|mouse|error|focus|blur)\s*=", re.I),
    re.compile(r"<img[^>]+src\s*=\s*['\"]?(?:javascript|data):", re.I),
    re.compile(r"&#x?\d+;", re.I),  # HTML entity encoding
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"document\s*\.\s*(?:write|cookie|location)", re.I),
    re.compile(r"<(?:iframe|object|embed|svg)[^>]*>", re.I),
    re.compile(r"expression\s*\(", re.I),
]

# ── Directory traversal / brute-force paths ──
_PATH_BRUTE = re.compile(
    r"/(?:admin|wp-admin|phpmyadmin|\.env|config|backup|\.git|"
    r"etc/passwd|\.htaccess|robots\.txt|sitemap\.xml|"
    r"\.ssh|id_rsa|private\.key|api/v\d+/admin)", re.I
)

# ── Suspicious user-agents (scanners / bots) ──
_BAD_UA = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|"
    r"wfuzz|burpsuite|metasploit|openvas|nessus|acunetix|w3af|havij|"
    r"python-requests/|curl/|wget/)", re.I
)

# ── Severity lookup ──
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def detect_sqli(entry: dict) -> list[dict]:
    """Detect SQL injection attempts in endpoint and payload."""
    alerts = []
    targets = [entry.get("endpoint") or "", entry.get("payload") or "",
               entry.get("raw") or ""]
    combined = " ".join(t for t in targets if t)

    hit_patterns = [p.pattern for p in _SQLI if p.search(combined)]
    if hit_patterns:
        alerts.append({
            "type":       "SQL Injection",
            "severity":   "HIGH",
            "ip":         entry.get("ip"),
            "timestamp":  entry.get("timestamp"),
            "endpoint":   entry.get("endpoint"),
            "evidence":   combined[:200],
            "patterns":   hit_patterns[:3],
            "risk_score": 75,
        })
    return alerts


def detect_xss(entry: dict) -> list[dict]:
    """Detect XSS attempts in endpoint and payload."""
    alerts = []
    targets = [entry.get("endpoint") or "", entry.get("payload") or "",
               entry.get("raw") or ""]
    combined = " ".join(t for t in targets if t)

    hit_patterns = [p.pattern for p in _XSS if p.search(combined)]
    if hit_patterns:
        alerts.append({
            "type":       "Cross-Site Scripting (XSS)",
            "severity":   "HIGH",
            "ip":         entry.get("ip"),
            "timestamp":  entry.get("timestamp"),
            "endpoint":   entry.get("endpoint"),
            "evidence":   combined[:200],
            "patterns":   hit_patterns[:3],
            "risk_score": 70,
        })
    return alerts


def detect_path_brute(entry: dict) -> list[dict]:
    """Detect directory brute-force / sensitive file access attempts."""
    alerts = []
    ep = entry.get("endpoint") or ""
    raw = entry.get("raw") or ""
    target = ep or raw

    if _PATH_BRUTE.search(target) and entry.get("status") in ("404", "403", "401"):
        alerts.append({
            "type":       "Directory Brute Force",
            "severity":   "MEDIUM",
            "ip":         entry.get("ip"),
            "timestamp":  entry.get("timestamp"),
            "endpoint":   ep,
            "evidence":   target[:200],
            "patterns":   [_PATH_BRUTE.pattern],
            "risk_score": 50,
        })
    return alerts


def detect_scanner_ua(entry: dict) -> list[dict]:
    """Detect known security scanner user-agents."""
    alerts = []
    ua = entry.get("user_agent") or entry.get("raw") or ""
    m = _BAD_UA.search(ua)
    if m:
        alerts.append({
            "type":       "Security Scanner Detected",
            "severity":   "MEDIUM",
            "ip":         entry.get("ip"),
            "timestamp":  entry.get("timestamp"),
            "endpoint":   entry.get("endpoint"),
            "evidence":   ua[:200],
            "patterns":   [m.group(0)],
            "risk_score": 55,
        })
    return alerts


# Run all detection rules on a single parsed entry
_DETECTORS = [detect_sqli, detect_xss, detect_path_brute, detect_scanner_ua]

def detect_single(entry: dict) -> list[dict]:
    results = []
    for detector in _DETECTORS:
        results.extend(detector(entry))
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 4 — BEHAVIORAL DETECTION (multi-entry analysis)
#  Brute-force login, high-frequency IP, 404 storm.
# ─────────────────────────────────────────────────────────────────────────────

# Thresholds (tune these per environment)
BRUTE_FORCE_THRESHOLD     = 5    # ≥N failed logins from same IP
DIR_BRUTE_THRESHOLD       = 8    # ≥N 404s from same IP
HIGH_FREQ_THRESHOLD       = 50   # ≥N total requests from same IP
HIGH_FREQ_WINDOW          = 60   # seconds (only used when timestamps parsed)


def detect_behavioral(entries: list[dict]) -> list[dict]:
    """
    Analyze the full log corpus for behavioral attack patterns.
    Returns additional alerts that span multiple log lines.
    """
    alerts: list[dict] = []

    ip_requests:     dict[str, list[dict]] = defaultdict(list)
    ip_failed_login: dict[str, int]        = defaultdict(int)
    ip_404:          dict[str, int]        = defaultdict(int)

    for entry in entries:
        ip = entry.get("ip") or "unknown"
        ip_requests[ip].append(entry)

        status  = str(entry.get("status") or "")
        ep      = (entry.get("endpoint") or "").lower()
        raw     = (entry.get("raw") or "").lower()

        # Failed auth heuristic: 401/403 on login-related endpoints
        if status in ("401", "403") and any(k in ep or k in raw
                                            for k in ("login", "auth", "signin", "password")):
            ip_failed_login[ip] += 1

        if status == "404":
            ip_404[ip] += 1

    # ── Brute-force login ──
    for ip, count in ip_failed_login.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            sample = ip_requests[ip][-1]
            alerts.append({
                "type":      "Brute Force Login",
                "severity":  "HIGH",
                "ip":        ip,
                "timestamp": sample.get("timestamp"),
                "endpoint":  sample.get("endpoint"),
                "evidence":  f"{count} failed authentication attempts",
                "patterns":  ["multiple 401/403 on auth endpoints"],
                "risk_score": 72,
            })

    # ── 404 storm / directory brute force ──
    for ip, count in ip_404.items():
        if count >= DIR_BRUTE_THRESHOLD:
            sample = ip_requests[ip][-1]
            alerts.append({
                "type":      "Directory Enumeration",
                "severity":  "MEDIUM",
                "ip":        ip,
                "timestamp": sample.get("timestamp"),
                "endpoint":  sample.get("endpoint"),
                "evidence":  f"{count} HTTP 404 responses from same IP",
                "patterns":  ["404 storm"],
                "risk_score": 55,
            })

    # ── High-frequency IP (general flood) ──
    for ip, reqs in ip_requests.items():
        if len(reqs) >= HIGH_FREQ_THRESHOLD:
            sample = reqs[-1]
            alerts.append({
                "type":      "High-Frequency Requests",
                "severity":  "MEDIUM",
                "ip":        ip,
                "timestamp": sample.get("timestamp"),
                "endpoint":  sample.get("endpoint"),
                "evidence":  f"{len(reqs)} requests from {ip}",
                "patterns":  ["request flood"],
                "risk_score": 48,
            })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 5 — CORRELATION ENGINE
#  Combine alerts from the same IP; escalate severity when multiple attack
#  types are detected together.
# ─────────────────────────────────────────────────────────────────────────────

def correlate(raw_alerts: list[dict]) -> list[dict]:
    """
    Group alerts by source IP.  If an IP triggers multiple distinct attack
    types the worst severity is escalated one level and a correlation note
    is added.  Returns a flat list of finalized alert dicts.
    """
    by_ip: dict[str, list[dict]] = defaultdict(list)
    no_ip: list[dict] = []

    for alert in raw_alerts:
        if alert.get("ip"):
            by_ip[alert["ip"]].append(alert)
        else:
            no_ip.append(alert)

    finalized: list[dict] = []

    for ip, group in by_ip.items():
        types = list({a["type"] for a in group})
        multi = len(types) > 1

        for alert in group:
            a = dict(alert)  # shallow copy
            if multi:
                # Escalate severity
                cur = SEVERITY_ORDER.get(a["severity"], 1)
                if cur < SEVERITY_ORDER["CRITICAL"]:
                    # bump one level
                    new_sev = [k for k, v in SEVERITY_ORDER.items() if v == cur + 1]
                    a["severity"] = new_sev[0] if new_sev else a["severity"]
                    a["risk_score"] = min(100, int(a["risk_score"] * 1.3))
                a["correlation_note"] = (
                    f"IP {ip} triggered {len(types)} attack types: "
                    + ", ".join(types)
                )
            finalized.append(a)

    finalized.extend(no_ip)
    return finalized


# ─────────────────────────────────────────────────────────────────────────────
#  STAGE 6 — RISK SCORER
#  Assign a final numeric risk score and deduplicate.
# ─────────────────────────────────────────────────────────────────────────────

def score_and_deduplicate(alerts: list[dict]) -> list[dict]:
    """
    Deduplicate identical alerts (same IP + type) and compute a final
    risk_score based on severity + occurrence count.
    """
    dedup: dict[str, dict] = {}

    for alert in alerts:
        key = hashlib.md5(
            f"{alert.get('ip')}:{alert.get('type')}:{alert.get('endpoint')}".encode()
        ).hexdigest()

        if key in dedup:
            dedup[key]["occurrences"] = dedup[key].get("occurrences", 1) + 1
            # Increase risk slightly with repeated hits
            dedup[key]["risk_score"] = min(
                100,
                dedup[key]["risk_score"] + 5
            )
        else:
            alert["occurrences"] = 1
            dedup[key] = alert

    result = list(dedup.values())

    # Sort: CRITICAL first, then by risk_score descending
    result.sort(key=lambda a: (
        -SEVERITY_ORDER.get(a.get("severity", "LOW"), 0),
        -a.get("risk_score", 0)
    ))

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  FULL PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def run_siem_pipeline(raw_logs: str, fmt: str = "auto") -> dict:
    """
    Execute the full 6-stage SIEM pipeline and return a structured result
    dict consumed by the frontend.
    """
    t_start = time.time()

    # Stage 1 — Ingest
    lines = ingest_logs(raw_logs, fmt)
    stage_counts = {"ingested": len(lines)}

    # Stage 2 — Parse
    entries = parse_logs(lines)
    stage_counts["parsed"] = len(entries)

    # Stage 3 — Per-entry Detection
    raw_alerts: list[dict] = []
    for entry in entries:
        raw_alerts.extend(detect_single(entry))
    stage_counts["rule_alerts"] = len(raw_alerts)

    # Stage 4 — Behavioral Detection
    behavioral = detect_behavioral(entries)
    raw_alerts.extend(behavioral)
    stage_counts["behavioral_alerts"] = len(behavioral)

    # Stage 5 — Correlation
    correlated = correlate(raw_alerts)
    stage_counts["correlated"] = len(correlated)

    # Stage 6 — Risk Scoring + dedup
    final_alerts = score_and_deduplicate(correlated)
    stage_counts["final_alerts"] = len(final_alerts)

    # ── Summary counters ──
    sev_counts = defaultdict(int)
    for a in final_alerts:
        sev_counts[a.get("severity", "INFO")] += 1

    # ── Timeline: unique IPs with event counts ──
    ip_timeline: dict[str, dict] = defaultdict(lambda: {"count": 0, "types": set()})
    for a in final_alerts:
        if a.get("ip"):
            ip_timeline[a["ip"]]["count"] += 1
            ip_timeline[a["ip"]]["types"].add(a.get("type", "Unknown"))
    timeline = [
        {"ip": ip, "events": v["count"], "types": list(v["types"])}
        for ip, v in ip_timeline.items()
    ]
    timeline.sort(key=lambda x: -x["events"])

    elapsed = round((time.time() - t_start) * 1000, 1)

    # Serialize alerts (convert sets/non-JSON types)
    def clean(obj):
        if isinstance(obj, set):
            return list(obj)
        return obj

    cleaned_alerts = []
    for a in final_alerts:
        cleaned_alerts.append({k: clean(v) for k, v in a.items()})

    return {
        "success":      True,
        "elapsed_ms":   elapsed,
        "stage_counts": stage_counts,
        "severity":     dict(sev_counts),
        "total_alerts": len(final_alerts),
        "alerts":       cleaned_alerts,
        "timeline":     timeline,
        "log_count":    len(lines),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  FLASK ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

# In-memory store of last analysis (no persistence needed for lightweight tool)
_last_result: dict = {}


@app.route("/siem/analyze", methods=["POST"])
def analyze():
    """
    POST /siem/analyze
    Accept multipart file upload OR JSON body with { logs, format }.
    Returns structured SIEM result.
    """
    fmt = "auto"
    raw = ""

    if "file" in request.files:
        f = request.files["file"]
        raw = f.read().decode("utf-8", errors="replace")
        name = f.filename or ""
        if name.endswith(".json"):
            fmt = "json"
        elif name.endswith(".csv"):
            fmt = "csv"
        elif name.endswith(".jsonl"):
            fmt = "jsonl"
    else:
        body = request.get_json(silent=True) or {}
        raw  = body.get("logs", "")
        fmt  = body.get("format", "auto")

    if not raw.strip():
        return jsonify({"success": False, "error": "No log data provided"}), 400

    try:
        result = run_siem_pipeline(raw, fmt)
        global _last_result
        _last_result = result
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/siem/results", methods=["GET"])
def results():
    """GET /siem/results — return the most recent analysis."""
    if not _last_result:
        return jsonify({"success": False, "error": "No analysis run yet"}), 404
    return jsonify(_last_result)


@app.route("/siem/status", methods=["GET"])
def status():
    return jsonify({"status": "ok", "service": "ShadeParse SIEM"})


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE LOG MONITORING
#  POST /siem/live/ingest  — push new log line(s) for real-time analysis
#  GET  /siem/live/stream  — SSE stream of live alerts
#  POST /siem/live/reset   — clear live session state
#  GET  /siem/live/stats   — current session summary
# ─────────────────────────────────────────────────────────────────────────────

import queue
import threading

# Per-session live state
_live_lock      = threading.Lock()
_live_entries:  list[dict] = []          # all parsed entries this session
_live_alerts:   list[dict] = []          # all deduped alerts this session
_live_ip_stats: dict       = defaultdict(lambda: {"count": 0, "types": set()})
_live_queues:   list[queue.Queue] = []   # one queue per SSE subscriber


def _live_broadcast(event_type: str, data: dict) -> None:
    """Push an SSE event to every connected subscriber."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead = []
    for q in _live_queues:
        try:
            q.put_nowait(msg)
        except queue.Full:
            dead.append(q)
    for q in dead:
        _live_queues.remove(q)


def _live_process_line(raw_line: str) -> list[dict]:
    """
    Parse + detect a single new log line.
    Update global live state and return any new alerts produced.
    """
    entry = parse_line(raw_line)

    with _live_lock:
        _live_entries.append(entry)
        ip = entry.get("ip") or "unknown"
        _live_ip_stats[ip]["count"] += 1

    # Per-entry detection rules
    new_alerts = detect_single(entry)

    # Lightweight behavioral: check if this IP has now crossed thresholds
    with _live_lock:
        ip_count = _live_ip_stats[ip]["count"]
        status   = str(entry.get("status") or "")
        ep       = (entry.get("endpoint") or "").lower()

        if status in ("401", "403") and any(
            k in ep for k in ("login", "auth", "signin", "password")
        ):
            _live_ip_stats[ip].setdefault("failed_auth", 0)
            _live_ip_stats[ip]["failed_auth"] += 1
            if _live_ip_stats[ip]["failed_auth"] == BRUTE_FORCE_THRESHOLD:
                new_alerts.append({
                    "type":       "Brute Force Login",
                    "severity":   "HIGH",
                    "ip":         ip,
                    "timestamp":  entry.get("timestamp"),
                    "endpoint":   entry.get("endpoint"),
                    "evidence":   f"{BRUTE_FORCE_THRESHOLD} failed auth attempts detected live",
                    "patterns":   ["repeated 401/403 on auth endpoint"],
                    "risk_score": 72,
                    "live":       True,
                })

        if status == "404":
            _live_ip_stats[ip].setdefault("not_found", 0)
            _live_ip_stats[ip]["not_found"] += 1
            if _live_ip_stats[ip]["not_found"] == DIR_BRUTE_THRESHOLD:
                new_alerts.append({
                    "type":       "Directory Enumeration",
                    "severity":   "MEDIUM",
                    "ip":         ip,
                    "timestamp":  entry.get("timestamp"),
                    "endpoint":   entry.get("endpoint"),
                    "evidence":   f"{DIR_BRUTE_THRESHOLD} 404s from {ip} detected live",
                    "patterns":   ["404 storm"],
                    "risk_score": 55,
                    "live":       True,
                })

        if ip_count == HIGH_FREQ_THRESHOLD:
            new_alerts.append({
                "type":       "High-Frequency Requests",
                "severity":   "MEDIUM",
                "ip":         ip,
                "timestamp":  entry.get("timestamp"),
                "endpoint":   entry.get("endpoint"),
                "evidence":   f"{HIGH_FREQ_THRESHOLD} requests from {ip} detected live",
                "patterns":   ["request flood"],
                "risk_score": 48,
                "live":       True,
            })

        # Track types for correlation note
        for a in new_alerts:
            _live_ip_stats[ip]["types"].add(a.get("type", ""))

        # Correlation: note if this IP has multiple attack types now
        known_types = list(_live_ip_stats[ip]["types"])
        if len(known_types) > 1:
            for a in new_alerts:
                a["correlation_note"] = (
                    f"IP {ip} now has {len(known_types)} attack types: "
                    + ", ".join(known_types)
                )
                # Escalate severity
                cur = SEVERITY_ORDER.get(a["severity"], 1)
                if cur < SEVERITY_ORDER["CRITICAL"]:
                    new_sev = [k for k, v in SEVERITY_ORDER.items() if v == cur + 1]
                    if new_sev:
                        a["severity"]   = new_sev[0]
                        a["risk_score"] = min(100, int(a["risk_score"] * 1.2))

        _live_alerts.extend(new_alerts)

    return new_alerts


@app.route("/siem/live/ingest", methods=["POST"])
def live_ingest():
    """
    POST /siem/live/ingest
    Body: { "lines": ["log line 1", "log line 2", ...], "format": "auto" }
    OR:   { "line": "single log line" }

    Processes each line through the detection pipeline and broadcasts
    any new alerts over the SSE stream.
    """
    body = request.get_json(silent=True) or {}

    if "line" in body:
        raw_lines = [body["line"]]
    elif "lines" in body:
        raw_lines = body["lines"]
    else:
        return jsonify({"success": False, "error": "No line(s) provided"}), 400

    fmt = body.get("format", "auto")

    all_new_alerts = []
    for raw in raw_lines:
        if not raw.strip():
            continue
        # Normalize through ingest if format hint given
        if fmt != "auto" and fmt != "log":
            normalized = ingest_logs(raw, fmt)
            for ln in normalized:
                alerts = _live_process_line(ln)
                all_new_alerts.extend(alerts)
        else:
            alerts = _live_process_line(raw)
            all_new_alerts.extend(alerts)

    # Broadcast each new alert
    for alert in all_new_alerts:
        _live_broadcast("alert", {k: (list(v) if isinstance(v, set) else v)
                                   for k, v in alert.items()})

    # Always broadcast a stats heartbeat
    with _live_lock:
        total_lines = len(_live_entries)
        total_alerts = len(_live_alerts)

    _live_broadcast("stats", {
        "lines":  total_lines,
        "alerts": total_alerts,
        "ts":     datetime.now(timezone.utc).isoformat(),
    })

    return jsonify({
        "success":    True,
        "new_alerts": len(all_new_alerts),
        "total_lines": total_lines,
    })


@app.route("/siem/live/stream", methods=["GET"])
def live_stream():
    """
    GET /siem/live/stream
    Server-Sent Events stream. Each subscriber gets a dedicated queue.
    Heartbeat every 15 s to keep connection alive through proxies.
    """
    q: queue.Queue = queue.Queue(maxsize=200)
    _live_queues.append(q)

    def generate():
        # Send current stats immediately on connect
        with _live_lock:
            total = len(_live_entries)
            alerts = len(_live_alerts)
        yield f"event: connected\ndata: {json.dumps({'lines': total, 'alerts': alerts})}\n\n"

        while True:
            try:
                msg = q.get(timeout=15)
                yield msg
            except queue.Empty:
                # Heartbeat comment to keep the connection alive
                yield ": heartbeat\n\n"
            except GeneratorExit:
                break

        # Cleanup on disconnect
        try:
            _live_queues.remove(q)
        except ValueError:
            pass

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":      "keep-alive",
        },
    )


@app.route("/siem/live/reset", methods=["POST"])
def live_reset():
    """POST /siem/live/reset — clear all live session data."""
    global _live_entries, _live_alerts, _live_ip_stats
    with _live_lock:
        _live_entries  = []
        _live_alerts   = []
        _live_ip_stats = defaultdict(lambda: {"count": 0, "types": set()})
    _live_broadcast("reset", {"ts": datetime.now(timezone.utc).isoformat()})
    return jsonify({"success": True})


@app.route("/siem/live/stats", methods=["GET"])
def live_stats():
    """GET /siem/live/stats — current session summary."""
    with _live_lock:
        sev = defaultdict(int)
        for a in _live_alerts:
            sev[a.get("severity", "INFO")] += 1
        return jsonify({
            "success":      True,
            "lines":        len(_live_entries),
            "total_alerts": len(_live_alerts),
            "severity":     dict(sev),
            "active_ips":   len(_live_ip_stats),
            "ts":           datetime.now(timezone.utc).isoformat(),
        })


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════╗")
    print("║   ShadeParse SIEM Backend v1.0       ║")
    print("║   http://127.0.0.1:5050              ║")
    print("╚══════════════════════════════════════╝")
    app.run(host="127.0.0.1", port=5050, debug=False)
