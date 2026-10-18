"""Pydantic data models for logs, anomalies, agent traces, and incident reports."""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class LogEntry(BaseModel):
    """Structured representation of a single log line or multi-line event."""
    id: int = 0
    timestamp: datetime
    raw_timestamp: str = ""
    level: str = "INFO"  # DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN
    service: str = "unknown"
    message: str = ""
    trace_id: Optional[str] = None
    client_ip: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_text: str = ""

class Anomaly(BaseModel):
    """Represents a statistical or semantic anomaly identified in logs."""
    anomaly_type: str  # ERROR_BURST, HIGH_LATENCY, SECURITY_SPIKE, FATAL_EXCEPTION, UNKNOWN_PATTERN
    timestamp: datetime
    service: str
    description: str
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    related_logs_count: int = 1
    sample_messages: List[str] = Field(default_factory=list)

class AgentAction(BaseModel):
    """Single step in an Agent's ReAct cycle: Thought -> Action -> Observation."""
    step: int
    thought: str
    tool_name: str
    tool_input: Dict[str, Any] = Field(default_factory=dict)
    tool_output: str = ""

class IncidentReport(BaseModel):
    """Comprehensive Root Cause Analysis (RCA) and Incident Report."""
    incident_title: str
    severity: str = "P1 - Critical"
    summary: str
    root_cause: str
    root_cause_service: str
    blast_radius: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    security_findings: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    runbook_commands: List[str] = Field(default_factory=list)
    agent_thought_trace: List[AgentAction] = Field(default_factory=list)
