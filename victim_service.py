"""
Victim Service: Generates safe lab traffic for packet sniffing.

This service creates:
1. A local HTTP server with cookies and headers
2. DNS queries to common domains
3. Intentional "sensitive" data for testing redaction

Students run this alongside the sniffer to observe packet capture in action.
"""

import http.server
import socketserver
import threading
import time
import socket
from urllib.request import urlopen
from urllib.error import URLError


class CustomHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler that sends various responses."""
    
    def do_GET(self):
        """Handle GET requests with various headers and cookies."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123def456; Path=/")
        self.send_header("Set-Cookie", "auth_token=tk_xyz789; Path=/")
        self.send_header("X-Custom-Header", "test-value")
        self.end_headers()
        
        html_content = """
        <html>
            <head><title>Lab Victim Server</title></head>
            <body>
                <h1>Welcome to the Lab Victim Server</h1>
                <p>This server generates traffic for packet sniffing practice.</p>
                <p>Try these requests:</p>
                <ul>
                    <li><a href="/public">Public Page</a></li>
                    <li><a href="/api?user=alice&password=secret123">API with Credentials</a></li>
                    <li><a href="/login?email=admin@example.com&token=abc123">Login Page</a></li>
                </ul>
            </body>
        </html>
        """.encode('utf-8')
        
        self.wfile.write(html_content)
        print(f"[HTTP] Served GET {self.path} to {self.client_address[0]}")
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        
        response = b'{"status": "ok", "message": "Data received"}'
        self.wfile.write(response)
        print(f"[HTTP] Served POST {self.path}")
    
    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass


def start_http_server(host='127.0.0.1', port=8080):
    """Start the local HTTP victim server."""
    server = socketserver.TCPServer((host, port), CustomHTTPHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] HTTP Victim Server started at http://{host}:{port}")
    print(f"[*] Server is running in background. Press Ctrl+C to stop.\n")
    return server


def generate_dns_queries():
    """Generate DNS queries to simulate normal traffic."""
    domains = [
        "example.com",
        "google.com",
        "github.com",
        "stackoverflow.com"
    ]
    
    print("[*] Generating DNS queries...")
    for domain in domains:
        try:
            print(f"[DNS] Resolving {domain}...")
            socket.gethostbyname(domain)
            time.sleep(0.5)
        except socket.gaierror as e:
            print(f"[DNS] Failed to resolve {domain}: {e}")
    print("[*] DNS queries complete.\n")


def generate_http_requests(base_url='http://127.0.0.1:8080'):
    """Generate HTTP requests to the victim server."""
    paths = [
        "/",
        "/public",
        "/api?user=alice&password=secret123",
        "/login?email=admin@example.com&token=abc123"
    ]
    
    print("[*] Generating HTTP requests...")
    for path in paths:
        try:
            url = base_url + path
            print(f"[HTTP] Requesting {url}...")
            response = urlopen(url, timeout=2)
            response.read()
            response.close()
            time.sleep(0.5)
        except URLError as e:
            print(f"[HTTP] Failed to reach {url}: {e}")
    print("[*] HTTP requests complete.\n")


def main():
    """Main entry point."""
    print("=" * 60)
    print("Victim Service: Lab Traffic Generator")
    print("=" * 60)
    print()
    
    # Start HTTP server
    server = start_http_server()
    
    # Give user time to start sniffer
    print("[!] Make sure the packet sniffer is running in another terminal!")
    print("[!] Use: python sniffer.py --iface lo --count 100\n")
    
    try:
        # Generate traffic automatically
        input("Press Enter to generate DNS queries and HTTP requests...\n")
        
        # Generate DNS queries first
        generate_dns_queries()
        
        # Generate HTTP requests
        generate_http_requests()
        
        print("\n[*] Traffic generation complete!")
        print("[*] Keep server running for manual requests.")
        print("[*] Visit http://127.0.0.1:8080 in your browser to generate more traffic.")
        print("[*] Press Ctrl+C to exit.\n")
        
        # Keep server running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n[*] Victim service stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
