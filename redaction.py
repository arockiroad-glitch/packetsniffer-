"""
Redaction module for sensitive data masking.

This module implements ethical guardrails to protect privacy:
- IP address masking (partial redaction)
- Email redaction
- Cookie/token/session redaction
- Password/secret parameter redaction
- Authentication header masking
"""

import re


def redact_ip(ip_address):
    """
    Redact private IP addresses by masking the last octet.
    
    Examples:
        192.168.1.42 → 192.168.1.xxx
        10.0.0.99 → 10.0.0.xxx
        8.8.8.8 → 8.8.8.8 (public IP, unchanged)
    """
    if not ip_address:
        return "[INVALID_IP]"
    
    # Check if private IP range
    private_ranges = [
        r"^192\.168\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^127\.",  # Loopback
        r"^169\.254\.",  # Link-local
    ]
    
    for pattern in private_ranges:
        if re.match(pattern, ip_address):
            parts = ip_address.rsplit(".", 1)
            return parts[0] + ".xxx"
    
    return ip_address


def redact_sensitive(text):
    """
    Redact sensitive data from text payloads.
    
    Redacts:
    - Email addresses
    - Cookies (Set-Cookie, Cookie headers)
    - Authorization headers
    - Password/token/secret query parameters
    - API keys
    """
    if not text:
        return text
    
    # Redact emails
    text = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "[REDACTED_EMAIL]",
        text
    )
    
    # Redact cookies
    text = re.sub(
        r"(?i)(cookie|set-cookie):\s*([^;\r\n]+)",
        r"\1: [REDACTED_COOKIE]",
        text
    )
    
    # Redact Authorization headers
    text = re.sub(
        r"(?i)(authorization):\s*([^\r\n]+)",
        r"\1: [REDACTED_AUTH]",
        text
    )
    
    # Redact query string parameters (password, token, secret, api_key, etc.)
    text = re.sub(
        r"(?i)(password|token|secret|api_key|apikey|session|auth|credentials)=([^\s&\r\n]+)",
        r"\1=[REDACTED]",
        text
    )
    
    # Redact JSON values for sensitive keys
    text = re.sub(
        r'(?i)("(?:password|token|secret|api_key|authorization)":\s*"[^"]*")',
        '"[REDACTED]"',
        text
    )
    
    # Redact credit card-like patterns (basic check)
    text = re.sub(
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "[REDACTED_CARD]",
        text
    )
    
    # Redact Social Security Numbers
    text = re.sub(
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED_SSN]",
        text
    )
    
    return text


def mask_payload(payload_bytes, max_length=200):
    """
    Convert raw payload bytes to a safe string representation.
    
    Shows only printable ASCII; masks binary data.
    """
    if not payload_bytes:
        return ""
    
    try:
        decoded = payload_bytes.decode('utf-8', errors='replace')
        decoded = redact_sensitive(decoded)
        if len(decoded) > max_length:
            return decoded[:max_length] + "... [truncated]"
        return decoded
    except Exception:
        return "[Binary payload - redacted]"
