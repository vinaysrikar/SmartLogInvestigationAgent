"""Cross-service log correlation and blast radius calculation."""
from collections import defaultdict
from typing import List, Dict, Any, Tuple
from src.models.log_model import LogEntry

class LogCorrelator:
    """Correlates logs across multiple microservices to establish causal order and blast radius."""

    def __init__(self, logs: List[LogEntry]):
        # Sort logs chronologically
        self.logs = sorted(logs, key=lambda x: x.timestamp)

    def get_service_error_summary(self) -> Dict[str, Dict[str, Any]]:
        """Summarizes error counts, first seen error timestamp, and log levels by service."""
        summary = {}
        for entry in self.logs:
            srv = entry.service
            if srv not in summary:
                summary[srv] = {
                    "total_logs": 0,
                    "error_count": 0,
                    "first_error_time": None,
                    "has_fatal": False,
                    "sample_errors": []
                }
            summary[srv]["total_logs"] += 1
            if entry.level in ("ERROR", "FATAL", "CRITICAL"):
                summary[srv]["error_count"] += 1
                if summary[srv]["first_error_time"] is None:
                    summary[srv]["first_error_time"] = entry.timestamp
                if entry.level == "FATAL":
                    summary[srv]["has_fatal"] = True
                if len(summary[srv]["sample_errors"]) < 3:
                    summary[srv]["sample_errors"].append(entry.message)
        return summary

    def determine_probable_root_cause_service(self) -> Tuple[str, List[str]]:
        """
        Identifies the earliest origin service of failure and downstream blast radius.
        """
        summary = self.get_service_error_summary()
        failing_services = [
            (srv, data["first_error_time"])
            for srv, data in summary.items()
            if data["error_count"] > 0 and data["first_error_time"] is not None
        ]

        if not failing_services:
            return "None detected", []

        # Sort by earliest failure timestamp
        failing_services.sort(key=lambda x: x[1])
        primary_culprit = failing_services[0][0]
        blast_radius = [s[0] for s in failing_services if s[0] != primary_culprit]

        return primary_culprit, blast_radius

    def get_chronological_incident_timeline(self, limit: int = 15) -> List[Dict[str, str]]:
        """Constructs a clean step-by-step incident timeline of significant warnings and errors."""
        timeline = []
        for entry in self.logs:
            if entry.level in ("WARN", "ERROR", "FATAL", "CRITICAL"):
                timeline.append({
                    "time": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else entry.raw_timestamp,
                    "service": entry.service,
                    "level": entry.level,
                    "message": entry.message[:160] + ("..." if len(entry.message) > 160 else "")
                })
                if len(timeline) >= limit:
                    break
        return timeline
