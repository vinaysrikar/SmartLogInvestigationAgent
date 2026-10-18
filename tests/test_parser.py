"""Tests for the Universal Log Parser and Pattern Extractor."""
import pytest
from src.parsers.log_parser import UniversalLogParser
from src.parsers.pattern_extractor import extract_template

def test_parse_standard_log_line():
    sample = "2026-10-17 14:00:01.120 [INFO] [api-gateway] [trace_id=a100-01] Received GET /health status=200"
    parser = UniversalLogParser()
    entries = parser.parse_text(sample)
    
    assert len(entries) == 1
    entry = entries[0]
    assert entry.level == "INFO"
    assert entry.service == "api-gateway"
    assert entry.trace_id == "a100-01"
    assert "Received GET /health" in entry.message

def test_parse_multiline_stack_trace():
    sample = """2026-10-17 14:01:31.420 [ERROR] [auth-service] Database error while validating session
org.postgresql.util.PSQLException: Connection checkout timed out after 30000ms.
\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:217)
\tat com.zaxxer.hikari.HikariDataSource.getConnection(HikariDataSource.java:100)"""
    
    parser = UniversalLogParser()
    entries = parser.parse_text(sample)
    
    assert len(entries) == 1
    entry = entries[0]
    assert entry.level == "ERROR"
    assert entry.service == "auth-service"
    assert entry.stack_trace is not None
    assert "HikariPool" in entry.stack_trace

def test_extract_template_masking():
    msg = "User 198.51.100.42 failed to authenticate with id 89231 and token 12345678-1234-1234-1234-123456789abc"
    tpl = extract_template(msg)
    assert "<IP>" in tpl
    assert "<NUM>" in tpl
    assert "<UUID>" in tpl
