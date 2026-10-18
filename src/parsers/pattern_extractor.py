"""Pattern extraction and template abstraction for log messages."""
import re

# Regex patterns for dynamic tokens
UUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
IPV4_REGEX = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
HEX_REGEX = re.compile(r'\b0x[0-9a-fA-F]+\b')
NUM_REGEX = re.compile(r'\b\d+\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

def extract_template(message: str) -> str:
    """
    Abstract dynamic parameters from a log message to identify its template signature.
    Example:
        'Connection checkout timed out after 30000ms' -> 'Connection checkout timed out after <NUM>ms'
    """
    if not message:
        return ""
    
    # Take first line if multi-line
    first_line = message.strip().split("\n")[0]
    
    masked = UUID_REGEX.sub("<UUID>", first_line)
    masked = IPV4_REGEX.sub("<IP>", masked)
    masked = EMAIL_REGEX.sub("<EMAIL>", masked)
    masked = HEX_REGEX.sub("<HEX>", masked)
    masked = NUM_REGEX.sub("<NUM>", masked)
    
    return masked.strip()
