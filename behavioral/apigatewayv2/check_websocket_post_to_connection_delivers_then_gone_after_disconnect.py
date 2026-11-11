"""websocket-post-to-connection-delivers-then-gone-after-disconnect."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-post-to-connection-delivers-then-gone-after-disconnect"
GROUP = "invoke"
SERVICES = ["apigatewayv2"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_STAGE = "s"
_PUSHED = b"sim2real-server-push"


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A live WebSocket is routed by action, gets an @connections push, and after it closes
    Post/Get/DeleteConnection answer GoneException (410); the deleted API is then NotFound by id,
    absent from GetApis, and refuses CreateRoute."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(_tolerant(lambda: agw.delete_api(ApiId=api_id), "NotFoundException"))
    endpoint = api.get("ApiEndpoint") or ""
    assert endpoint.startswith(("wss://", "ws://")), f"a WEBSOCKET ApiEndpoint must be ws(s)://, got {endpoint!r}"

    integ = agw.create_integration(
        ApiId=api_id,
        IntegrationType="MOCK",
        RequestTemplates={"$default": '{"statusCode": 200}'},
        TemplateSelectionExpression="\\$default",
    )["IntegrationId"]
    agw.create_integration_response(
        ApiId=api_id,
        IntegrationId=integ,
        IntegrationResponseKey="$default",
        ResponseTemplates={
            "$default": '{"connectionId": "$context.connectionId", "routeKey": "$context.routeKey"}'
        },
        TemplateSelectionExpression="\\$default",
    )
    route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="whoami",
        Target=f"integrations/{integ}",
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

    # The published ApiEndpoint is reached only through the target's stage URL.
    url = ctx.stage_url(api["ApiEndpoint"], _STAGE)
    attempts = []

    def _connect():
        r = _ws_connect(url, ctx.http_verify)
        attempts.append(r)
        return r

    try:
        ws = _poll_until(
            _connect,
            lambda r: r["status"] == 101,
            timeout_s=120.0, interval_s=3.0, description=f"a 101 WebSocket upgrade at {url}",
        )
    except AssertionError as exc:
        if all(r.get("error") for r in attempts):
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: no WebSocket listener accepted a connection at {url} "
                f"within 120s, so the route and @connections data plane could not be reached: "
                f"{attempts[-1].get('error') if attempts else exc}"
            ) from exc
        raise
    sock = ws["sock"]
    ctx.on_cleanup(lambda: _quiet_close(sock))
    buf = [ws["rest"]]

    # Route selection on $request.body.action, answered as a frame on the same socket.
    _ws_send(sock, json.dumps({"action": "whoami"}))
    op, payload = _ws_recv(sock, buf)
    assert op == 1, f"the route reply must be a text frame (opcode 1), got opcode {op}: {payload!r}"
    reply = json.loads(payload)
    assert reply.get("routeKey") == "whoami", f"the reply must come from route 'whoami', got {reply!r}"
    cid = reply.get("connectionId")
    assert isinstance(cid, str) and cid, f"the reply must carry the caller's connectionId, got {reply!r}"

    # An action no route matches (and there is no $default route): refused on the socket.
    _ws_send(sock, json.dumps({"action": "no-such-route"}))
    op, payload = _ws_recv(sock, buf)
    refused = json.loads(payload)
    assert refused.get("message") == "Forbidden", (
        f"an unmatched action must be answered Forbidden, got {payload!r}"
    )
    assert refused.get("connectionId") == cid, (
        f"the refusal must be addressed to the same connection {cid!r}, got {refused!r}"
    )

    mgmt = ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api["ApiEndpoint"], _STAGE, management=True),
    )
    conn = mgmt.get_connection(ConnectionId=cid)
    assert conn.get("ConnectedAt") is not None, f"GetConnection must report ConnectedAt, got {conn!r}"

    # Server-initiated push through @connections, delivered to the live socket.
    mgmt.post_to_connection(ConnectionId=cid, Data=_PUSHED)
    op, payload = _ws_recv(sock, buf)
    assert (op, payload) == (1, _PUSHED), (
        f"PostToConnection must deliver exactly the posted bytes as a text frame, got "
        f"opcode {op} payload {payload!r}"
    )

    # Client-initiated close; the server echoes the close, then the connection is gone.
    _ws_send(sock, struct.pack(">H", 1000), opcode=8)
    op, _ = _ws_recv(sock, buf)
    assert op == 8, f"the server must answer a close frame with a close frame, got opcode {op}"
    _quiet_close(sock)

    def _post_after_close():
        try:
            mgmt.post_to_connection(ConnectionId=cid, Data=b"after-close")
        except ClientError as exc:
            return _as_error(exc)
        return {"accepted": True}

    # Polled: removal of the connection after the close is asynchronous.
    gone = _poll_until(_post_after_close, lambda r: "accepted" not in r, timeout_s=60.0,
                       description="PostToConnection to stop accepting a closed connection")
    _assert_gone(gone, "PostToConnection after close", expected_message="")
    # The by-id read is refused the same way.
    _assert_gone(_gone_error(lambda: mgmt.get_connection(ConnectionId=cid)), "GetConnection after close", expected_message="")
    # Deleting the dead connection is refused the same way.
    _assert_gone(_gone_error(lambda: mgmt.delete_connection(ConnectionId=cid)), "DeleteConnection after close", expected_message="")

    # The API: deleted, then gone by id, gone from the listing, and refusing a mutation.
    agw.delete_api(ApiId=api_id)
    read = _poll_until(
        lambda: _error_or_none(lambda: agw.get_api(ApiId=api_id)),
        lambda r: r is not None,
        timeout_s=60.0, description=f"GetApi {api_id} to stop answering after DeleteApi",
    )
    _assert_not_found(read, f"GetApi {api_id} after DeleteApi", expected_message=f"Invalid API identifier specified {ctx.account}:{api_id}")
    listed = {a["ApiId"] for a in _paged_apis(agw)}
    assert api_id not in listed, f"GetApis still lists the deleted API {api_id}"
    _assert_not_found(
        _gone_error(lambda: agw.create_route(ApiId=api_id, RouteKey="gone")),
        f"CreateRoute on the deleted API {api_id}",
        expected_message=f"Invalid API identifier specified {ctx.account}:{api_id}",
    )


def _gone_error(fn) -> dict:
    """The ClientError fn() raised: {Code, Message, HTTPStatusCode}. RAISES if fn() succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        return _as_error(exc)
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


def _error_or_none(fn):
    """The ClientError fn() raised as {Code, Message, HTTPStatusCode}, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return _as_error(exc)
    return None


def _assert_not_found(err: dict, what: str, expected_message) -> None:
    """NotFoundException with HTTP 404 and the exact message."""
    assert (err["Code"], err["HTTPStatusCode"]) == ("NotFoundException", 404), (
        f"{what}: expected NotFoundException/404, got {err['Code']!r}/{err['HTTPStatusCode']!r}"
    )
    assert err["Message"] == expected_message, f'expected the message {expected_message!r}, got {err["Message"]!r}'


def _paged_apis(agw) -> list:
    """Every API GetApis returns, following NextToken."""
    out, kwargs = [], {}
    while True:
        page = agw.get_apis(**kwargs)
        out.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes:
                raise

    return run


def _as_error(exc) -> dict:
    """A ClientError as {Code, Message, HTTPStatusCode}."""
    err = exc.response.get("Error", {})
    return {
        "Code": err.get("Code", "<no code>"),
        "Message": err.get("Message"),
        "HTTPStatusCode": exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
    }


def _assert_gone(err: dict, what: str, expected_message) -> None:
    """GoneException with HTTP 410 and the exact message."""
    assert err["Code"] == "GoneException", f"{what}: expected GoneException, got {err['Code']!r}"
    assert err["HTTPStatusCode"] == 410, f"{what}: expected HTTP 410, got {err['HTTPStatusCode']!r}"
    assert err["Message"] == expected_message, f'expected the message {expected_message!r}, got {err["Message"]!r}'


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
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
    rest}; a non-101 closes the socket and is returned as a RESULT so the caller can poll while the
    stage settles."""
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
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
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
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("the WebSocket closed while a frame was being read")
        buf[0] += chunk
    out, buf[0] = buf[0][:n], buf[0][n:]
    return out


def _ws_recv(sock, buf):
    """Read the next data or close frame: (opcode, payload). Pings are answered and skipped."""
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
        opcode = b1 & 0x0F
        if opcode == 9:  # ping -> pong
            _ws_send(sock, payload, opcode=10)
            continue
        if opcode == 10:
            continue
        return opcode, payload


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
