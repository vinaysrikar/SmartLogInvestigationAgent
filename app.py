"""Streamlit Interactive Web Application for Smart Log Investigation AI Agent."""
import time
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

from src.parsers.log_parser import UniversalLogParser
from src.analytics.anomaly_detector import AnomalyDetector
from src.agent.investigator_agent import SmartLogInvestigatorAgent
from src.reporting.report_generator import ReportGenerator
from src.config import Config

st.set_page_config(
    page_title="Smart Log Investigation AI Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #3b82f6;
    }
    .agent-step {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 10px;
    }
    .badge-p1 {
        background-color: #ef4444;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- Sidebar -----------------
st.sidebar.title("🔍 Smart Log Agent")
st.sidebar.caption("Autonomous Log Investigation & RCA")

# Log Source Selection
log_source_mode = st.sidebar.radio(
    "Select Incident Source:",
    ["Pre-packaged Incident Scenarios", "Upload Custom Log File"]
)

sample_files = {
    "💥 Microservices Outage (DB Connection Pool Exhaustion)": "microservices_cascading_failure.log",
    "🛡️ Security Incident (Brute Force + SQL Injection)": "security_incident_bruteforce_sqli.log",
    "☸️ Kubernetes OOM (JVM Heap Memory Exhaustion)": "k8s_resource_oom_crashloop.log"
}

log_text = ""
selected_scenario_name = ""

if log_source_mode == "Pre-packaged Incident Scenarios":
    selected_scenario_name = st.sidebar.selectbox("Choose Sample Scenario:", list(sample_files.keys()))
    file_name = sample_files[selected_scenario_name]
    file_path = Config.SAMPLE_LOGS_DIR / file_name
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            log_text = f.read()
else:
    uploaded_file = st.sidebar.file_uploader("Upload log file (.log, .txt, .json):", type=["log", "txt", "json", "csv"])
    if uploaded_file is not None:
        log_text = uploaded_file.getvalue().decode("utf-8", errors="replace")
        selected_scenario_name = uploaded_file.name

st.sidebar.markdown("---")
st.sidebar.subheader("AI Engine Configuration")
provider = st.sidebar.selectbox(
    "Provider:",
    ["offline (Built-in Heuristic AI)", "gemini", "openai", "ollama"],
    index=0
)

api_key = ""
if "gemini" in provider:
    api_key = st.sidebar.text_input("Gemini API Key:", type="password", value=Config.GEMINI_API_KEY)
    if api_key:
        Config.GEMINI_API_KEY = api_key
elif "openai" in provider:
    api_key = st.sidebar.text_input("OpenAI API Key:", type="password", value=Config.OPENAI_API_KEY)
    if api_key:
        Config.OPENAI_API_KEY = api_key

investigate_btn = st.sidebar.button("🚀 Run Autonomous Investigation", type="primary", use_container_width=True)

# ----------------- Main View -----------------
st.title("🛡️ Smart Log Investigation AI Agent")
st.markdown("Autonomous triage, temporal cross-service causality correlation, and automated remediation runbooks.")

if not log_text:
    st.info("👈 Please select a pre-packaged scenario or upload a log file from the sidebar to begin.")
    st.stop()

# Parse Logs
parser = UniversalLogParser()
logs = parser.parse_text(log_text)

# Detect Anomalies
detector = AnomalyDetector()
anomalies = detector.detect_anomalies(logs)

# Quick Metrics Row
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Log Records", len(logs))
col2.metric("Detected Anomalies", len(anomalies))
services_set = set(e.service for e in logs)
col3.metric("Monitored Services", len(services_set))
critical_count = sum(1 for e in logs if e.level in ("FATAL", "CRITICAL", "ERROR"))
col4.metric("Errors & Criticals", critical_count)

# Store investigation state
if "report" not in st.session_state or investigate_btn:
    if investigate_btn or "report" not in st.session_state:
        agent_provider = "offline" if "offline" in provider else provider.split()[0]
        agent = SmartLogInvestigatorAgent(logs=logs, anomalies=anomalies, llm_provider=agent_provider)
        
        progress_bar = st.progress(0, text="Agent initializing...")
        step_box = st.empty()
        steps_log = []

        def on_step(action):
            pct = min(action.step * 20, 100)
            progress_bar.progress(pct, text=f"Agent Step {action.step}: {action.tool_name}")
            steps_log.append(action)

        with st.spinner("🤖 Autonomous Agent is analyzing logs, tracing causality, and synthesizing findings..."):
            report = agent.run_investigation(status_callback=on_step)
            time.sleep(0.3)
            progress_bar.empty()
            st.session_state["report"] = report
            st.session_state["steps"] = steps_log

report = st.session_state.get("report")

# Tabs
tab1, tab2, tab3 = st.tabs(["🤖 Agent Investigation & RCA", "📊 Telemetry & Visual Analytics", "🔍 Interactive Log Explorer"])

with tab1:
    if report:
        # Incident Banner
        st.error(f"🚨 **{report.incident_title}** | Severity: **{report.severity}** | Origin: `{report.root_cause_service}`")
        
        rcol1, rcol2 = st.columns([2, 1])
        with rcol1:
            st.subheader("📋 Executive Summary")
            st.write(report.summary)
            
            st.subheader("🎯 Root Cause Analysis")
            st.info(report.root_cause)

            st.subheader("💥 Blast Radius")
            if report.blast_radius:
                badges = " ".join([f"`{srv}`" for srv in report.blast_radius])
                st.markdown(f"Impacted Downstream Systems: {badges}")
            else:
                st.write("No cascading downstream victims identified.")

        with rcol2:
            st.subheader("🛡️ Security Assessment")
            if report.security_findings:
                for sec in report.security_findings:
                    st.warning(f"⚠️ {sec}")
            else:
                st.success("✅ No malicious security signatures identified.")

            st.subheader("📥 Export Investigation")
            md_report = ReportGenerator.to_markdown(report)
            json_report = ReportGenerator.to_json(report)
            st.download_button("📄 Download Markdown Report", md_report, file_name="incident_investigation.md", mime="text/markdown", use_container_width=True)
            st.download_button("📦 Download JSON Report", json_report, file_name="incident_investigation.json", mime="application/json", use_container_width=True)

        st.markdown("---")
        # Remediation & Runbook
        st.subheader("🔧 Recommended Mitigation & Executable Runbook")
        for i, step in enumerate(report.remediation_steps, 1):
            st.markdown(f"**{i}.** {step}")

        if report.runbook_commands:
            st.markdown("#### ⚡ Emergency Runbook Commands")
            for cmd in report.runbook_commands:
                st.code(cmd, language="bash")

        st.markdown("---")
        # Agent ReAct Trace
        with st.expander("🧠 View Agent Step-by-Step ReAct Reasoning Trace", expanded=False):
            for action in report.agent_thought_trace:
                st.markdown(f"**Step {action.step}: `{action.tool_name}`**")
                st.caption(f"💭 **Thought:** {action.thought}")
                with st.expander(f"Tool Output ({action.tool_name})", expanded=False):
                    st.code(action.tool_output, language="json")

with tab2:
    st.subheader("📈 Log Distribution & Anomaly Analytics")
    
    # Prepare Dataframe
    df_data = []
    for entry in logs:
        df_data.append({
            "timestamp": entry.timestamp,
            "level": entry.level,
            "service": entry.service,
            "message": entry.message
        })
    df = pd.DataFrame(df_data)

    if not df.empty:
        c1, c2 = st.columns(2)
        with c1:
            # Service Error Distribution
            err_df = df[df["level"].isin(["ERROR", "FATAL", "CRITICAL", "WARN"])]
            if not err_df.empty:
                svc_counts = err_df["service"].value_counts().reset_index()
                svc_counts.columns = ["Service", "Errors/Warnings"]
                fig_bar = px.bar(svc_counts, x="Service", y="Errors/Warnings", color="Errors/Warnings", title="Issues by Service", color_continuous_scale="Reds")
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.write("No errors to display.")

        with c2:
            # Level Breakdown Pie
            fig_pie = px.pie(df, names="level", title="Log Severity Distribution", color="level",
                             color_discrete_map={"INFO": "#3b82f6", "WARN": "#f59e0b", "ERROR": "#ef4444", "FATAL": "#7f1d1d"})
            st.plotly_chart(fig_pie, use_container_width=True)

        # Timeline plot
        st.subheader("⏱️ Temporal Event Timeline")
        fig_time = px.scatter(df, x="timestamp", y="service", color="level", hover_data=["message"],
                              title="Chronological Event Stream across Microservices",
                              color_discrete_map={"INFO": "blue", "WARN": "orange", "ERROR": "red", "FATAL": "darkred"})
        st.plotly_chart(fig_time, use_container_width=True)

    if anomalies:
        st.subheader("🚨 Detected Anomaly Signatures")
        anom_data = [{
            "Type": a.anomaly_type,
            "Service": a.service,
            "Severity": a.severity,
            "Description": a.description
        } for a in anomalies]
        st.dataframe(pd.DataFrame(anom_data), use_container_width=True)

with tab3:
    st.subheader("🔍 Log Records Explorer")
    search_term = st.text_input("Filter logs by keyword, trace_id, or IP:")
    selected_service = st.selectbox("Filter by Service:", ["All"] + list(services_set))
    selected_level = st.selectbox("Filter by Level:", ["All", "INFO", "WARN", "ERROR", "FATAL"])

    filtered_logs = logs
    if selected_service != "All":
        filtered_logs = [e for e in filtered_logs if e.service == selected_service]
    if selected_level != "All":
        filtered_logs = [e for e in filtered_logs if e.level == selected_level]
    if search_term:
        filtered_logs = [e for e in filtered_logs if search_term.lower() in e.message.lower() or (e.stack_trace and search_term.lower() in e.stack_trace.lower())]

    st.write(f"Showing **{len(filtered_logs)}** matching records:")
    table_data = []
    for e in filtered_logs:
        table_data.append({
            "Timestamp": e.raw_timestamp or str(e.timestamp),
            "Level": e.level,
            "Service": e.service,
            "Trace ID": e.trace_id or "-",
            "Message": e.message[:120] + ("..." if len(e.message) > 120 else ""),
            "Has Stack Trace": "Yes" if e.stack_trace else "No"
        })
    st.dataframe(pd.DataFrame(table_data), use_container_width=True)
