"""Tests for anomaly detection."""
from src.parsers.log_parser import UniversalLogParser
from src.analytics.anomaly_detector import AnomalyDetector

def test_detect_security_sqli_anomaly():
    text = "2026-10-17 02:14:10.050 [WARN] [web-gateway] [client_ip=198.51.100.42] GET /catalog?search=' UNION SELECT username FROM users-- status=500"
    parser = UniversalLogParser()
    logs = parser.parse_text(text)
    
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(logs)
    
    assert len(anomalies) > 0
    assert any(a.anomaly_type == "SECURITY_SPIKE" for a in anomalies)
    assert any("SQL Injection" in a.description for a in anomalies)

def test_detect_resource_exhaustion_oom():
    text = "2026-10-17 08:30:54.120 [FATAL] [kubelet] Killing container billing-worker: OOMKilled (Exit Code 137)"
    parser = UniversalLogParser()
    logs = parser.parse_text(text)
    
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(logs)
    
    assert len(anomalies) > 0
    assert any(a.anomaly_type == "RESOURCE_EXHAUSTION" for a in anomalies)
