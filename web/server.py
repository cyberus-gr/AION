#!/usr/bin/env python3
"""
Simple local HTTP server for the PASSVAULT web UI.

Usage:
    python web/server.py          # serves on http://localhost:8080
    python web/server.py 3000     # custom port

The Web Crypto API (used for AES-256-GCM encryption) requires a secure context.
A localhost origin qualifies, so this plain HTTP server is sufficient locally.
"""

import http.server
import os
import sys
import webbrowser

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
ROOT = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        pass  # suppress request noise

if __name__ == "__main__":
    with http.server.HTTPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print(f"\n  PASSVAULT  →  {url}\n")
        print("  Press Ctrl+C to stop.\n")
        try:
            webbrowser.open(url)
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
