"""Command-line interface for the Smart Log Investigation AI Agent."""
import argparse
import sys
from pathlib import Path

# Fix Windows console encoding for UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.parsers.log_parser import UniversalLogParser
from src.analytics.anomaly_detector import AnomalyDetector
from src.agent.investigator_agent import SmartLogInvestigatorAgent
from src.reporting.report_generator import ReportGenerator

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    has_rich = True
    console = Console(legacy_windows=False) if sys.platform == "win32" else Console()
except ImportError:
    has_rich = False
    console = None

def main():
    parser = argparse.ArgumentParser(description="Autonomous Smart Log Investigation AI Agent CLI")
    parser.add_argument("--file", "-f", required=True, help="Path to raw log file to investigate")
    parser.add_argument("--provider", "-p", default="offline", help="LLM Provider: gemini, openai, ollama, or offline")
    parser.add_argument("--export", "-e", help="Output path to export markdown report")
    parser.add_argument("--json", "-j", help="Output path to export JSON report")
    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    if has_rich:
        console.print(Panel(f"[bold cyan]Smart Log Investigation AI Agent[/bold cyan]\nTarget: [yellow]{log_path.name}[/yellow]", title="Initializing Agent"))
    else:
        print(f"=== Smart Log Investigation AI Agent: {log_path.name} ===")

    # 1. Ingest & Parse
    parser_engine = UniversalLogParser()
    logs = parser_engine.parse_file(str(log_path))
    if has_rich:
        console.print(f"[green][+] Ingested and parsed {len(logs)} log records.[/green]")
    else:
        print(f"[+] Parsed {len(logs)} log records.")

    # 2. Detect Anomalies
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(logs)
    if has_rich:
        console.print(f"[green][+] Detected {len(anomalies)} telemetry anomalies.[/green]")
    else:
        print(f"[+] Detected {len(anomalies)} telemetry anomalies.")

    # 3. Agent Investigation
    def on_step(action):
        if has_rich:
            console.print(f"  [bold yellow]Agent Step {action.step}:[/bold yellow] {action.thought}")
            console.print(f"    [dim]Invoked tool: {action.tool_name}[/dim]")
        else:
            print(f"  [Step {action.step}] {action.thought}")

    agent = SmartLogInvestigatorAgent(logs=logs, anomalies=anomalies, llm_provider=args.provider)
    if has_rich:
        console.print("\n[bold magenta]Starting Autonomous ReAct Investigation Loop...[/bold magenta]")
    else:
        print("\nStarting Autonomous ReAct Investigation Loop...")

    report = agent.run_investigation(status_callback=on_step)

    # 4. Display Summary
    if has_rich:
        console.print("\n" + "="*70)
        console.print(Panel(
            f"[bold red]{report.incident_title}[/bold red]\n"
            f"[bold]Severity:[/bold] {report.severity}\n"
            f"[bold]Root Origin:[/bold] {report.root_cause_service}\n"
            f"[bold]Blast Radius:[/bold] {', '.join(report.blast_radius)}\n\n"
            f"[bold]Root Cause:[/bold]\n{report.root_cause}",
            title="Investigation Complete"
        ))
    else:
        print("\n=== Investigation Complete ===")
        print(f"Title: {report.incident_title}")
        print(f"Severity: {report.severity}")
        print(f"Root Origin: {report.root_cause_service}")
        print(f"Blast Radius: {', '.join(report.blast_radius)}")
        print(f"Root Cause: {report.root_cause}")

    # 5. Export
    if args.export:
        md_content = ReportGenerator.to_markdown(report)
        with open(args.export, "w", encoding="utf-8") as f:
            f.write(md_content)
        if has_rich:
            console.print(f"[cyan]Report exported to markdown: {args.export}[/cyan]")
        else:
            print(f"Report exported to: {args.export}")

    if args.json:
        json_content = ReportGenerator.to_json(report)
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(json_content)
        if has_rich:
            console.print(f"[cyan]Report exported to JSON: {args.json}[/cyan]")
        else:
            print(f"Report exported to: {args.json}")

if __name__ == "__main__":
    main()
