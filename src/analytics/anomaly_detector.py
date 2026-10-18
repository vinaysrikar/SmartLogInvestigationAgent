"""Anomaly detection engine for logs."""
from collections import defaultdict
from typing import List, Dict, Any
from src.models.log_model import LogEntry, Anomaly

class AnomalyDetector:
    """Detects statistical spikes, security patterns, and system failures across logs."""

    def __init__(self, z_threshold: float = 2.0):
        self.z_threshold = z_threshold

    def detect_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        if not logs:
            return []

        anomalies: List[Anomaly] = []
        
        # 1. Error rate & Fatal exceptions
        anomalies.extend(self._detect_error_and_fatal_anomalies(logs))

        # 2. Security threats (Brute force & Injection)
        anomalies.extend(self._detect_security_anomalies(logs))

        # 3. Resource exhaustion (OOM, Connection Pool)
        anomalies.extend(self._detect_resource_exhaustion(logs))

        return anomalies

    def _detect_error_and_fatal_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        anomalies = []
        service_error_map = defaultdict(list)

        for entry in logs:
            if entry.level in ("ERROR", "FATAL", "CRITICAL"):
                service_error_map[entry.service].append(entry)

        for service, error_entries in service_error_map.items():
            count = len(error_entries)
            first_err = error_entries[0]
            severity = "CRITICAL" if any(e.level == "FATAL" for e in error_entries) or count > 5 else "HIGH"
            
            anomalies.append(
                Anomaly(
                    anomaly_type="ERROR_BURST",
                    timestamp=first_err.timestamp,
                    service=service,
                    description=f"High error burst on service '{service}' with {count} failure events.",
                    severity=severity,
                    related_logs_count=count,
                    sample_messages=[e.message for e in error_entries[:3]]
                )
            )
        return anomalies

    def _detect_security_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        anomalies = []
        ip_auth_failures = defaultdict(list)
        sqli_patterns = ["UNION SELECT", "OR 1=1", "--", "information_schema"]

        for entry in logs:
            # Detect 401 or auth brute force
            if "status=401" in entry.message or "failed authentication" in entry.message.lower():
                ip = entry.client_ip or "unknown_ip"
                ip_auth_failures[ip].append(entry)

            # Detect SQLi pattern
            upper_msg = entry.message.upper()
            if any(p in upper_msg for p in sqli_patterns) or "syntax error detected during SQL" in entry.message:
                anomalies.append(
                    Anomaly(
                        anomaly_type="SECURITY_SPIKE",
                        timestamp=entry.timestamp,
                        service=entry.service,
                        description=f"Potential SQL Injection attempt detected from client IP {entry.client_ip or 'unknown'}",
                        severity="CRITICAL",
                        related_logs_count=1,
                        sample_messages=[entry.message]
                    )
                )

        # Check for brute force threshold
        for ip, entries in ip_auth_failures.items():
            if len(entries) >= 3:
                anomalies.append(
                    Anomaly(
                        anomaly_type="SECURITY_SPIKE",
                        timestamp=entries[0].timestamp,
                        service=entries[0].service,
                        description=f"Brute-force authentication attacks detected from client IP {ip} ({len(entries)} failed attempts)",
                        severity="HIGH",
                        related_logs_count=len(entries),
                        sample_messages=[e.message for e in entries[:3]]
                    )
                )

        return anomalies

    def _detect_resource_exhaustion(self, logs: List[LogEntry]) -> List[Anomaly]:
        anomalies = []
        oom_keywords = ["OutOfMemoryError", "OOMKilled", "memory usage", "connection slots are reserved", "HikariPool", "connection pool"]

        for entry in logs:
            combined = (entry.message + " " + (entry.stack_trace or "")).lower()
            for kw in oom_keywords:
                if kw.lower() in combined:
                    anomalies.append(
                        Anomaly(
                            anomaly_type="RESOURCE_EXHAUSTION",
                            timestamp=entry.timestamp,
                            service=entry.service,
                            description=f"Resource exhaustion indicator: '{kw}' in service {entry.service}",
                            severity="CRITICAL",
                            related_logs_count=1,
                            sample_messages=[entry.message]
                        )
                    )
                    break
        return anomalies
