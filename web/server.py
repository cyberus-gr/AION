#!/usr/bin/env python3
"""
Simple local HTTP server for the AION web UI.

Usage:
    python web/server.py          # serves on http://localhost:8080
    python web/server.py 3000     # custom port

The Web Crypto API (used for AES-256-GCM encryption) requires a secure context.
A localhost origin qualifies, so this plain HTTP server is sufficient locally.
"""

import http.server
import os
import sys
import threading
import webbrowser

PORT = 8080
if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        print(f"Error: port must be a number, got '{sys.argv[1]}'")
        sys.exit(1)

ROOT = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        pass  # suppress request noise

if __name__ == "__main__":
    # Bind to 127.0.0.1 only — keeps the server off the local network
    with http.server.HTTPServer(("127.0.0.1", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print(f"\n  AION  →  {url}\n")
        print("  Press Ctrl+C to stop.\n")
        # Delay browser open slightly so server is ready before the request arrives
        threading.Timer(0.4, webbrowser.open, args=[url]).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
