"""Tests for the autonomous investigator agent and tools."""
from src.parsers.log_parser import UniversalLogParser
from src.analytics.anomaly_detector import AnomalyDetector
from src.agent.tools import InvestigationTools
from src.agent.investigator_agent import SmartLogInvestigatorAgent
from src.config import Config

def test_investigation_tools():
    log_file = Config.SAMPLE_LOGS_DIR / "microservices_cascading_failure.log"
    parser = UniversalLogParser()
    logs = parser.parse_file(str(log_file))
    
    tools = InvestigationTools(logs)
    
    health = tools.get_service_health()
    assert "postgres-primary" in health
    assert health["postgres-primary"]["errors"] > 0
    
    traces = tools.get_stack_traces()
    assert len(traces) > 0
    assert any("PSQLException" in t["message"] or "PSQLException" in (t.get("stack_trace") or "") for t in traces)

def test_agent_end_to_end_investigation():
    log_file = Config.SAMPLE_LOGS_DIR / "microservices_cascading_failure.log"
    parser = UniversalLogParser()
    logs = parser.parse_file(str(log_file))
    
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(logs)
    
    agent = SmartLogInvestigatorAgent(logs=logs, anomalies=anomalies, llm_provider="offline")
    report = agent.run_investigation()
    
    assert report is not None
    assert "postgres-primary" in report.root_cause_service or "postgres" in report.root_cause_service
    assert len(report.blast_radius) > 0
    assert len(report.remediation_steps) > 0
    assert len(report.runbook_commands) > 0
    assert len(report.agent_thought_trace) >= 4
