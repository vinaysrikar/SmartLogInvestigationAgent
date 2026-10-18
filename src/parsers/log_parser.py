"""Universal Log Parser supporting multi-line stack traces, JSON, Syslog, and custom formats."""
import json
import re
from datetime import datetime
from typing import List, Optional, Tuple
from src.models.log_model import LogEntry

# Regexes for timestamp detection
ISO_TIMESTAMP_REGEX = re.compile(
    r'^(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
SYSLOG_TIMESTAMP_REGEX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)

# Common level detection
LOG_LEVELS = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"]
LEVEL_REGEX = re.compile(r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b', re.IGNORECASE)

# Metadata extraction regexes
TRACE_ID_REGEX = re.compile(r'trace_id=([a-zA-Z0-9_-]+)')
CLIENT_IP_REGEX = re.compile(r'client_ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)')

# Common stack trace line starts
STACK_TRACE_PREFIXES = (
    "\tat ", "   at ", "Caused by: ", "Exception in thread ",
    "Traceback (most recent call last):", '  File "', "    at "
)

class UniversalLogParser:
    """Intelligent multi-format log parser with multi-line stack trace stitching."""

    def __init__(self):
        self.year = datetime.now().year

    def parse_file(self, file_path: str) -> List[LogEntry]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self.parse_text(content)

    def parse_text(self, text: str) -> List[LogEntry]:
        lines = text.splitlines()
        entries: List[LogEntry] = []
        current_raw_lines: List[str] = []
        entry_id = 1

        for line in lines:
            if not line.strip():
                continue
            
            # Check if this line starts a brand new log record or is a stack trace continuation
            is_new = self._is_new_record(line)
            
            if is_new and current_raw_lines:
                entry = self._build_entry(current_raw_lines, entry_id)
                if entry:
                    entries.append(entry)
                    entry_id += 1
                current_raw_lines = [line]
            else:
                current_raw_lines.append(line)

        # Flush final record
        if current_raw_lines:
            entry = self._build_entry(current_raw_lines, entry_id)
            if entry:
                entries.append(entry)

        return entries

    def _is_new_record(self, line: str) -> bool:
        """Determines if a line is the beginning of a new log entry vs continuation."""
        stripped = line.strip()
        
        # Check if line looks like continuation of stack trace
        for prefix in STACK_TRACE_PREFIXES:
            if stripped.startswith(prefix) or line.startswith("\t") or line.startswith("   "):
                return False

        # Check for JSON line
        if stripped.startswith("{") and stripped.endswith("}"):
            return True

        # Check for ISO or Syslog timestamps
        if ISO_TIMESTAMP_REGEX.match(stripped) or SYSLOG_TIMESTAMP_REGEX.match(stripped):
            return True

        return False

    def _parse_timestamp(self, ts_str: str) -> Tuple[datetime, str]:
        """Tries various date formats or returns fallback."""
        ts_str = ts_str.strip()
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %H:%M:%S"
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if "%Y" not in fmt:
                    dt = dt.replace(year=self.year)
                return dt, ts_str
            except ValueError:
                continue
        return datetime.now(), ts_str

    def _build_entry(self, lines: List[str], entry_id: int) -> Optional[LogEntry]:
        first_line = lines[0].strip()
        stack_trace_lines = lines[1:] if len(lines) > 1 else []
        stack_trace_str = "\n".join(stack_trace_lines) if stack_trace_lines else None
        
        # Try JSON parsing
        if first_line.startswith("{") and first_line.endswith("}"):
            try:
                data = json.loads(first_line)
                ts_val = data.get("timestamp") or data.get("time") or data.get("@timestamp") or ""
                dt, raw_ts = self._parse_timestamp(str(ts_val))
                return LogEntry(
                    id=entry_id,
                    timestamp=dt,
                    raw_timestamp=raw_ts,
                    level=str(data.get("level", "INFO")).upper(),
                    service=str(data.get("service") or data.get("app") or data.get("logger") or "application"),
                    message=str(data.get("message") or data.get("msg") or first_line),
                    trace_id=str(data.get("trace_id") or data.get("traceId") or "") or None,
                    client_ip=str(data.get("client_ip") or data.get("ip") or "") or None,
                    stack_trace=data.get("stack_trace") or stack_trace_str,
                    metadata=data,
                    raw_text="\n".join(lines)
                )
            except Exception:
                pass

        # Parse text formatted logs
        # Check ISO timestamp
        iso_match = ISO_TIMESTAMP_REGEX.match(first_line)
        timestamp_dt = datetime.now()
        raw_ts = ""
        remainder = first_line

        if iso_match:
            raw_ts = iso_match.group(1)
            timestamp_dt, _ = self._parse_timestamp(raw_ts)
            remainder = first_line[len(raw_ts):].strip()
        else:
            syslog_match = SYSLOG_TIMESTAMP_REGEX.match(first_line)
            if syslog_match:
                raw_ts = syslog_match.group(1)
                timestamp_dt, _ = self._parse_timestamp(raw_ts)
                remainder = first_line[len(raw_ts):].strip()

        # Find log level
        level = "INFO"
        level_match = LEVEL_REGEX.search(remainder)
        if level_match:
            detected_level = level_match.group(1).upper()
            if detected_level == "WARNING":
                detected_level = "WARN"
            level = detected_level

        # Extract service name (often in brackets like [service-name] or before a colon)
        bracket_matches = re.findall(r'\[(.*?)\]', remainder)
        service = "system"
        metadata = {}

        if bracket_matches:
            # First bracket might be level or service
            for b in bracket_matches:
                b_stripped = b.strip()
                if b_stripped.upper() in LOG_LEVELS:
                    continue
                elif b_stripped.startswith("trace_id="):
                    metadata["trace_id"] = b_stripped.split("=")[1]
                elif b_stripped.startswith("client_ip="):
                    metadata["client_ip"] = b_stripped.split("=")[1]
                elif "=" in b_stripped:
                    k, v = b_stripped.split("=", 1)
                    metadata[k.strip()] = v.strip()
                elif service == "system":
                    service = b_stripped

        # Check regex matches for trace_id and client_ip
        trace_match = TRACE_ID_REGEX.search(remainder)
        trace_id = trace_match.group(1) if trace_match else metadata.get("trace_id")

        ip_match = CLIENT_IP_REGEX.search(remainder)
        client_ip = ip_match.group(1) if ip_match else metadata.get("client_ip")

        # Extract message content
        # Clean remainder from leading bracket markers
        clean_msg = remainder
        for b in bracket_matches:
            clean_msg = clean_msg.replace(f"[{b}]", "")
        clean_msg = clean_msg.strip()
        if clean_msg.startswith(":"):
            clean_msg = clean_msg[1:].strip()

        return LogEntry(
            id=entry_id,
            timestamp=timestamp_dt,
            raw_timestamp=raw_ts,
            level=level,
            service=service,
            message=clean_msg or first_line,
            trace_id=trace_id,
            client_ip=client_ip,
            stack_trace=stack_trace_str,
            metadata=metadata,
            raw_text="\n".join(lines)
        )
