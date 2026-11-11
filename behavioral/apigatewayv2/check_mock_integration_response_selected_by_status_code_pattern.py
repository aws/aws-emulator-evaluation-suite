"""mock-integration-response-selected-by-status-code-pattern."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse

from behavioral_harness import tags

CHECK = "mock-integration-response-selected-by-status-code-pattern"
GROUP = "websocket-dataplane"
SERVICES = ["apigatewayv2"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_STAGE = "s"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WebSocket MOCK integration picks among /2\\d\\d/, /4\\d{2}/ and $default responses by the
    templated statusCode; the chosen response's template renders the body the client receives.
    """
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="MOCK",
        RequestTemplates={"\\$default": "{\"statusCode\": $input.json('$.code')}"},
        TemplateSelectionExpression="\\$default",
    )["IntegrationId"]

    for key, body in (
        ("/2\\d\\d/", {"result": "ok"}),
        ("/4\\d{2}/", {"result": "client-error"}),
        ("$default", {"result": "unmatched"}),
    ):
        agw.create_integration_response(
            ApiId=api_id,
            IntegrationId=integ_id,
            IntegrationResponseKey=key,
            TemplateSelectionExpression="\\$default",
            ResponseTemplates={"\\$default": json.dumps(body)},
        )

    route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="$default",
        Target=f"integrations/{integ_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    agw.create_route_response(ApiId=api_id, RouteId=route_id, RouteResponseKey="$default")
    agw.create_stage(ApiId=api_id, StageName=_STAGE, Tags=_TAGS)
    dep = agw.create_deployment(ApiId=api_id, StageName=_STAGE)
    _poll_until(
        lambda: agw.get_deployment(ApiId=api_id, DeploymentId=dep["DeploymentId"]),
        lambda d: d.get("DeploymentStatus") != "PENDING",
        timeout_s=60.0, description="the WebSocket deployment to leave PENDING",
    )
    assert agw.get_deployment(ApiId=api_id, DeploymentId=dep["DeploymentId"]).get(
        "DeploymentStatus") == "DEPLOYED", "the WebSocket deployment must reach DEPLOYED"

    url = ctx.stage_url(api["ApiEndpoint"], _STAGE)
    conn = _poll_until(
        lambda: _ws_connect(url, ctx.http_verify),
        lambda r: r["status"] == 101,
        timeout_s=120.0, interval_s=3.0, description=f"a 101 WebSocket upgrade at {url}",
    )
    sock = conn["sock"]
    ctx.on_cleanup(lambda: _quiet_close(sock))
    buf = [conn["rest"]]

    cases = ((200, {"result": "ok"}), (404, {"result": "client-error"}), (301, {"result": "unmatched"}))
    for code, expected in cases:
        _ws_send(sock, json.dumps({"action": "anything", "code": code}))
        op, payload = _ws_recv(sock, buf)
        assert op == 1, f"code={code}: expected a text frame, got opcode {op}: {payload!r}"
        got = json.loads(payload)
        assert got == expected, f"code={code}: expected the client to receive {expected!r}, got {got!r}"

    _ws_send(sock, struct.pack(">H", 1000), opcode=8)
    op, _ = _ws_recv(sock, buf)
    assert op == 8, f"the server must answer a close frame with a close frame, got opcode {op}"
    _quiet_close(sock)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _quiet_close(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ws_connect(url: str, verify=True) -> dict:
    """Open a WebSocket (RFC 6455 handshake; TLS per ``ctx.http_verify``). Returns {status, sock,
    rest}; a non-101 closes the socket and is returned as a result so the caller can poll while the
    stage settles.
    """
    u = urllib.parse.urlparse(url)
    tls = u.scheme == "wss"
    port = u.port or (443 if tls else 80)
    try:
        raw = socket.create_connection((u.hostname, port), timeout=15)
    except OSError as exc:
        return {"status": None, "error": str(exc)}
    try:
        sock = _ssl_context(verify).wrap_socket(raw, server_hostname=u.hostname) if tls else raw
    except OSError as exc:
        _quiet_close(raw)
        return {"status": None, "error": f"TLS handshake failed: {exc}"}
    key = base64.b64encode(os.urandom(16)).decode()
    host = u.netloc
    sock.sendall(
        (f"GET {u.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
         f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
    )
    data = b""
    sock.settimeout(15)
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        return {"status": None, "error": str(exc)}
    head, _, rest = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    if status != 101:
        _quiet_close(sock)
        return {"status": status, "head": head[:300]}
    sock.settimeout(20)
    return {"status": 101, "sock": sock, "rest": rest}


def _ws_send(sock, data, opcode: int = 1) -> None:
    """Send one FIN frame, client-masked as RFC 6455 requires."""
    payload = data.encode() if isinstance(data, str) else data
    mask = os.urandom(4)
    n = len(payload)
    header = bytes([0x80 | opcode])
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _ws_read(sock, buf, n: int) -> bytes:
    while len(buf[0]) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError("the WebSocket closed while a frame was being read")
        buf[0] += chunk
    out, buf[0] = buf[0][:n], buf[0][n:]
    return out


def _ws_recv(sock, buf):
    """Read the next complete message, aggregating continuation frames until FIN, or a close
    frame: (opcode, payload). Pings are answered and skipped."""
    parts = []
    first_opcode = None
    while True:
        b1, b2 = _ws_read(sock, buf, 2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", _ws_read(sock, buf, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", _ws_read(sock, buf, 8))[0]
        mask = _ws_read(sock, buf, 4) if b2 & 0x80 else None
        payload = _ws_read(sock, buf, n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        if opcode == 9:  # ping -> pong
            _ws_send(sock, payload, opcode=10)
            continue
        if opcode == 10:
            continue
        if opcode == 8:
            return 8, payload
        if first_opcode is None:
            first_opcode = opcode
        parts.append(payload)
        if fin:
            return first_opcode, b"".join(parts)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
