"""Investigation tools available to the Smart Log Investigation AI Agent."""
import re
from typing import List, Dict, Any, Optional
from src.models.log_model import LogEntry

class InvestigationTools:
    """Tool execution suite allowing the Agent to interrogate logs dynamically."""

    def __init__(self, logs: List[LogEntry]):
        self.logs = sorted(logs, key=lambda x: x.timestamp)

    def search_logs(self, query: str = "", service: Optional[str] = None, level: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Search logs by query string, target service, or log level."""
        results = []
        q_lower = query.lower() if query else ""

        for entry in self.logs:
            if service and service.lower() != entry.service.lower():
                continue
            if level and level.upper() != entry.level.upper():
                continue
            if q_lower and q_lower not in entry.message.lower() and q_lower not in (entry.stack_trace or "").lower():
                continue

            results.append({
                "timestamp": entry.raw_timestamp or str(entry.timestamp),
                "service": entry.service,
                "level": entry.level,
                "message": entry.message,
                "trace_id": entry.trace_id,
                "client_ip": entry.client_ip
            })
            if len(results) >= limit:
                break
        return results

    def get_service_health(self) -> Dict[str, Any]:
        """Calculates error statistics, failure rates, and status per service."""
        stats = {}
        for entry in self.logs:
            srv = entry.service
            if srv not in stats:
                stats[srv] = {"total_events": 0, "errors": 0, "first_seen": str(entry.timestamp), "levels": {}}
            stats[srv]["total_events"] += 1
            stats[srv]["levels"][entry.level] = stats[srv]["levels"].get(entry.level, 0) + 1
            if entry.level in ("ERROR", "FATAL", "CRITICAL"):
                stats[srv]["errors"] += 1

        for srv, val in stats.items():
            val["error_rate_pct"] = round((val["errors"] / val["total_events"]) * 100, 2) if val["total_events"] > 0 else 0
        return stats

    def get_stack_traces(self) -> List[Dict[str, Any]]:
        """Retrieves all stack traces and runtime exceptions found in logs."""
        traces = []
        for entry in self.logs:
            if entry.stack_trace:
                traces.append({
                    "timestamp": entry.raw_timestamp or str(entry.timestamp),
                    "service": entry.service,
                    "level": entry.level,
                    "message": entry.message,
                    "stack_trace": entry.stack_trace
                })
        return traces

    def get_security_events(self) -> List[Dict[str, Any]]:
        """Scans for suspicious security events: brute force, SQLi, unauthorized access."""
        events = []
        sqli_words = ["UNION SELECT", "OR 1=1", "ELEVATE_PRIVILEGES", "DROP TABLE", "--"]

        for entry in self.logs:
            is_sec = False
            reason = ""
            if "status=401" in entry.message or "failed authentication" in entry.message.lower():
                is_sec = True
                reason = "Authentication Failure / Brute Force"
            elif any(w in entry.message.upper() for w in sqli_words):
                is_sec = True
                reason = "SQL Injection or Privilege Escalation Signature"
            elif "unauthorized" in entry.message.lower():
                is_sec = True
                reason = "Unauthorized Access Attempt"

            if is_sec:
                events.append({
                    "timestamp": entry.raw_timestamp or str(entry.timestamp),
                    "service": entry.service,
                    "client_ip": entry.client_ip,
                    "reason": reason,
                    "message": entry.message
                })
        return events

    def get_causality_timeline(self) -> List[Dict[str, Any]]:
        """Returns the first anomalous event of each service to establish chronological causality."""
        first_events = {}
        for entry in self.logs:
            if entry.level in ("WARN", "ERROR", "FATAL", "CRITICAL"):
                if entry.service not in first_events:
                    first_events[entry.service] = {
                        "timestamp": entry.raw_timestamp or str(entry.timestamp),
                        "service": entry.service,
                        "level": entry.level,
                        "message": entry.message
                    }

        # Return sorted list
        return list(first_events.values())

    def inspect_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Trace a specific request lifecycle across all microservices using trace_id."""
        trace_logs = []
        for entry in self.logs:
            if entry.trace_id == trace_id or (trace_id and trace_id in entry.message):
                trace_logs.append({
                    "timestamp": entry.raw_timestamp or str(entry.timestamp),
                    "service": entry.service,
                    "level": entry.level,
                    "message": entry.message
                })
        return trace_logs
