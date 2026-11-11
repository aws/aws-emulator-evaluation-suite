"""The service the image asset carries: a stdlib HTTP server, no dependencies.

Two response paths on purpose:
  * ``/healthz`` answers 200 and prints NOTHING. The load balancer polls it every few seconds, so a
    health check that printed the counted token would keep the custom metric permanently above the
    alarm threshold and the alarm's crossing would prove nothing about request traffic.
  * anything else answers with the greeting and marker the task definition passed in, and prints one
    structured line carrying the counted token — which is what the Logs metric filter turns into the
    datapoint the alarm evaluates.

The startup line uses a DIFFERENT token so the log stream has content before any request arrives
without moving the metric.
"""

import http.server
import json
import os
import socketserver

GREETING = os.environ.get("GREETING", "hello")
MARKER = os.environ.get("SITE_MARKER", "sim2real")
PORT = int(os.environ.get("PORT", "8080"))

REQUEST_TOKEN = "SIM2REAL_REQUEST"
BOOT_TOKEN = "SIM2REAL_BOOT"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's contract
        if self.path.startswith("/healthz"):
            self._respond({"ok": True})
            return
        print(
            json.dumps(
                {"token": REQUEST_TOKEN, "path": self.path, "greeting": GREETING, "marker": MARKER}
            ),
            flush=True,
        )
        self._respond({"greeting": GREETING, "marker": MARKER, "path": self.path})

    def _respond(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        """Silence the default access log: stdout is the metric filter's input, so only the
        structured lines above may appear on it."""


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(json.dumps({"token": BOOT_TOKEN, "greeting": GREETING, "marker": MARKER}), flush=True)
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
