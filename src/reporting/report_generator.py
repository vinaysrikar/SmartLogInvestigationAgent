"""Report generator formatting IncidentReports into Markdown, JSON, and Rich Terminal output."""
import json
from src.models.log_model import IncidentReport

class ReportGenerator:
    """Generates structured executive and engineering reports."""

    @staticmethod
    def to_markdown(report: IncidentReport) -> str:
        """Renders an IncidentReport into a comprehensive Markdown document."""
        md = []
        md.append(f"# {report.incident_title}\n")
        md.append(f"**Severity**: `{report.severity}` | **Root Origin**: `{report.root_cause_service}`\n")
        md.append("## Executive Summary")
        md.append(f"{report.summary}\n")
        
        md.append("## Root Cause Analysis")
        md.append(f"{report.root_cause}\n")

        md.append("## Blast Radius & Impacted Services")
        if report.blast_radius:
            for srv in report.blast_radius:
                md.append(f"- **{srv}**")
        else:
            md.append("No downstream service cascade detected.")
        md.append("")

        md.append("## Chronological Timeline of Key Events")
        if report.timeline:
            md.append("| Timestamp | Service | Level | Summary |")
            md.append("|---|---|---|---|")
            for t in report.timeline:
                clean_msg = t.get('message', '').replace('|', '\\|')
                md.append(f"| {t.get('time')} | `{t.get('service')}` | **{t.get('level')}** | {clean_msg} |")
        md.append("")

        if report.security_findings:
            md.append("## Security & Threat Intelligence Findings")
            for sec in report.security_findings:
                md.append(f"- {sec}")
            md.append("")

        md.append("## Recommended Mitigation Steps")
        for step in report.remediation_steps:
            md.append(f"1. {step}")
        md.append("")

        if report.runbook_commands:
            md.append("## Immediate Remediation Runbook")
            for cmd in report.runbook_commands:
                md.append(f"```bash\n{cmd}\n```\n")

        if report.agent_thought_trace:
            md.append("## Agent Investigative Reasoning Trace")
            for trace in report.agent_thought_trace:
                md.append(f"### Step {trace.step}: `{trace.tool_name}`")
                md.append(f"**Thought**: *{trace.thought}*\n")

        return "\n".join(md)

    @staticmethod
    def to_json(report: IncidentReport) -> str:
        """Serializes report to JSON."""
        return report.model_dump_json(indent=2)
