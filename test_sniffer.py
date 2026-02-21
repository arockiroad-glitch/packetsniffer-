"""
Unit tests for redaction module.

Tests verify that sensitive data is properly masked.
"""

import unittest
from redaction import redact_ip, redact_sensitive, mask_payload


class TestRedactionModule(unittest.TestCase):
    """Test cases for redaction functions."""
    
    def test_redact_private_ips(self):
        """Test redaction of private IP addresses."""
        self.assertEqual(redact_ip("192.168.1.42"), "192.168.1.xxx")
        self.assertEqual(redact_ip("10.0.0.99"), "10.0.0.xxx")
        self.assertEqual(redact_ip("127.0.0.1"), "127.0.0.xxx")
        self.assertEqual(redact_ip("172.16.0.5"), "172.16.0.xxx")
        self.assertEqual(redact_ip("169.254.1.1"), "169.254.1.xxx")
    
    def test_keep_public_ips(self):
        """Test that public IPs are not redacted."""
        self.assertEqual(redact_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(redact_ip("1.1.1.1"), "1.1.1.1")
    
    def test_redact_emails(self):
        """Test email redaction."""
        text = "Contact: admin@example.com for support"
        redacted = redact_sensitive(text)
        self.assertIn("[REDACTED_EMAIL]", redacted)
        self.assertNotIn("admin@example.com", redacted)
    
    def test_redact_cookies(self):
        """Test cookie redaction."""
        text = "Cookie: session_id=abc123def456ghi789"
        redacted = redact_sensitive(text)
        self.assertIn("[REDACTED_COOKIE]", redacted)
        self.assertNotIn("abc123", redacted)
    
    def test_redact_authorization(self):
        """Test Authorization header redaction."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted = redact_sensitive(text)
        self.assertIn("[REDACTED_AUTH]", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
    
    def test_redact_passwords_in_query(self):
        """Test password/token query parameter redaction."""
        text = "GET /login?username=alice&password=secret123&token=xyz789"
        redacted = redact_sensitive(text)
        self.assertIn("password=[REDACTED]", redacted)
        self.assertIn("token=[REDACTED]", redacted)
        self.assertNotIn("secret123", redacted)
        self.assertNotIn("xyz789", redacted)
    
    def test_redact_json_secrets(self):
        """Test JSON secret field redaction."""
        text = '{"username": "alice", "password": "secret123", "api_key": "key_123"}'
        redacted = redact_sensitive(text)
        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("secret123", redacted)
    
    def test_redact_credit_cards(self):
        """Test credit card number redaction."""
        text = "Card: 4532-1234-5678-9010"
        redacted = redact_sensitive(text)
        self.assertIn("[REDACTED_CARD]", redacted)
    
    def test_mask_payload_bytes(self):
        """Test payload masking."""
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
        result = mask_payload(payload)
        self.assertIn("GET", result)
        self.assertIn("example.com", result)
    
    def test_mask_payload_with_redaction(self):
        """Test that payload masking also redacts sensitive data."""
        payload = b"password=secret123&token=abc"
        result = mask_payload(payload)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("secret123", result)


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple redaction functions."""
    
    def test_full_http_request_redaction(self):
        """Test a complete HTTP request with multiple sensitive fields."""
        http_request = (
            "GET /api/user?password=mypass123&token=tk_xyz123 HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Authorization: Bearer auth_token_secret\r\n"
            "Cookie: session_id=sess_abc123def\r\n"
            "User-Agent: Mozilla/5.0"
        )
        redacted = redact_sensitive(http_request)
        
        # Verify sensitive data is redacted
        self.assertNotIn("mypass123", redacted)
        self.assertNotIn("tk_xyz123", redacted)
        self.assertNotIn("auth_token_secret", redacted)
        self.assertNotIn("sess_abc123def", redacted)
        
        # Verify structure remains readable
        self.assertIn("GET /api/user", redacted)
        self.assertIn("api.example.com", redacted)


if __name__ == "__main__":
    unittest.main()
