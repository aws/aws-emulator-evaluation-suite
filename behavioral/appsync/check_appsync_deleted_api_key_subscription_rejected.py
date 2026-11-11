"""appsync-deleted-api-key-subscription-rejected."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags

CHECK = "appsync-deleted-api-key-subscription-rejected"
GROUP = 'api-key'
SERVICES = ['appsync']

SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Post {
    id: ID!
    body: String
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    addPost(id: ID!, body: String): Post
}
type Subscription {
    onAddPost: Post @aws_subscribe(mutations: ["addPost"])
}
"""

JS_ECHO_ARGS = """export function request(ctx) {
  return { payload: ctx.args };
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT, not an
    exception: the negative legs assert on the status and body of the error response."""
    data = json.dumps(payload).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


class _WS:
    """A minimal RFC 6455 text-frame client over TLS, stdlib only, so the check needs no
    third-party WebSocket package.
    """

    def __init__(self, url, route_headers=None, *, subprotocol="graphql-ws", timeout_s=25.0):
        parts = urllib.parse.urlsplit(url)
        self.host = parts.hostname
        target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        self.eof = False
        self._buf = b""
        secure = parts.scheme in ("wss", "https")
        raw = socket.create_connection((self.host, parts.port or (443 if secure else 80)), timeout=timeout_s)
        self._sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if secure else raw
        nonce = base64.b64encode(os.urandom(16)).decode()
        self._sock.sendall(
            (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {(route_headers or {}).get('Host') or self.host}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {nonce}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Protocol: {subprotocol}\r\n"
                "\r\n"
            ).encode()
        )
        head = b""
        self._sock.settimeout(timeout_s)
        while b"\r\n\r\n" not in head:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            head += chunk
        raw_head, _, rest = head.partition(b"\r\n\r\n")
        self._buf = rest
        line = raw_head.split(b"\r\n", 1)[0].decode("latin-1")
        bits = line.split(" ")
        self.status = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 0
        self.headers = raw_head.decode("latin-1")

    # -- framing ------------------------------------------------------------
    def _fill(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._sock.settimeout(min(remaining, 5.0))
        try:
            chunk = self._sock.recv(8192)
        except (socket.timeout, TimeoutError):
            return time.monotonic() < deadline
        except OSError:
            self.eof = True
            return False
        if not chunk:
            self.eof = True
            return False
        self._buf += chunk
        return True

    def _need(self, n, deadline):
        while len(self._buf) < n:
            if not self._fill(deadline):
                return False
        return True

    def _send_frame(self, opcode, payload):
        n = len(payload)
        frame = bytearray([0x80 | opcode])
        if n < 126:
            frame.append(0x80 | n)
        elif n < 65536:
            frame.append(0x80 | 126)
            frame += struct.pack("!H", n)
        else:
            frame.append(0x80 | 127)
            frame += struct.pack("!Q", n)
        mask = os.urandom(4)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(bytes(frame))

    def send_json(self, obj):
        self._send_frame(0x1, json.dumps(obj).encode())

    def _recv_frame(self, deadline):
        if not self._need(2, deadline):
            return None
        b0, b1 = self._buf[0], self._buf[1]
        ln, off = b1 & 0x7F, 2
        if ln == 126:
            if not self._need(4, deadline):
                return None
            ln, off = struct.unpack("!H", bytes(self._buf[2:4]))[0], 4
        elif ln == 127:
            if not self._need(10, deadline):
                return None
            ln, off = struct.unpack("!Q", bytes(self._buf[2:10]))[0], 10
        if not self._need(off + ln, deadline):
            return None
        payload = bytes(self._buf[off:off + ln])
        self._buf = self._buf[off + ln:]
        return (b0 & 0x0F, payload, bool(b0 & 0x80))

    def recv_json(self, deadline):
        """Next application message as a dict, or None once ``deadline`` passes.

        Control frames are handled here rather than surfaced: a ping MUST be ponged or the
        server drops the connection mid-check, and a close frame is reported as a synthetic
        ``__closed__`` message so a refusal is observable instead of looking like a timeout.
        """
        parts = []
        while True:
            frame = self._recv_frame(deadline)
            if frame is None:
                return None
            opcode, payload, fin = frame
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                self.eof = True
                return {"type": "__closed__", "code": code,
                        "reason": payload[2:].decode("utf-8", "replace")}
            parts.append(payload)
            if not fin:
                continue
            text = b"".join(parts).decode("utf-8", "replace")
            parts = []
            try:
                return json.loads(text)
            except ValueError:
                return {"type": "__unparsed__", "raw": text}

    def read_body(self, timeout_s=10.0):
        """Drain the body of a NON-101 HTTP response.

        A refusal on the realtime endpoint may be an HTTP status with a GraphQL errors
        document rather than a WebSocket frame, so the body has to be readable off the same
        socket the handshake used. Content-Length bounds the read; without it, the deadline
        does.
        """
        want = None
        for line in self.headers.split("\r\n")[1:]:
            key, _, value = line.partition(":")
            if key.strip().lower() == "content-length":
                try:
                    want = int(value.strip())
                except ValueError:
                    want = None
        deadline = time.monotonic() + timeout_s
        while not self.eof and (want is None or len(self._buf) < want):
            if not self._fill(deadline):
                break
        return self._buf.decode("utf-8", "replace")

    def close(self):
        try:
            self._send_frame(0x8, b"\x03\xe8")
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _realtime_url(realtime_uri, auth_header):
    hdr = base64.b64encode(json.dumps(auth_header).encode()).decode()
    payload = base64.b64encode(b"{}").decode()
    return (
        f"{realtime_uri}?header={urllib.parse.quote(hdr, safe='')}"
        f"&payload={urllib.parse.quote(payload, safe='')}"
    )


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, uris)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=120.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: status={status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL") and uris.get("REALTIME"), (
        f"the API did not expose both endpoint URIs: {uris!r}"
    )
    return api_id, uris


# ===== end helpers =====

def _tolerate_notfound(fn, **kwargs):
    """Run a teardown call, tolerating the target already being gone.

    ``delete_api_key`` on K1 is the ACT of this check, so its registered cleanup is expected
    to find the key missing on the happy path -- and must still be registered, because a
    wrongly-rejected delete leaves a real key behind.
    """
    try:
        fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 - teardown, and NotFound is the expected case
        if "NotFound" not in type(exc).__name__ and "NotFound" not in str(exc):
            raise


def _error_types(document):
    """Every ``errorType`` in a GraphQL errors document, in order."""
    if not isinstance(document, dict):
        return []
    return [e.get("errorType") for e in (document.get("errors") or []) if isinstance(e, dict)]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A deleted API key is refused on the REALTIME handshake (a `connection_error` frame), while a
    second live key on the same API, schema and subscription still subscribes and receives a
    published mutation: key revocation reaches the WebSocket endpoint.
    """
    svc = ctx.client("appsync")
    api_id, uris = _graphql_api(ctx, svc, SDL)
    graphql_uri, realtime_uri = uris["GRAPHQL"], uris["REALTIME"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))

    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="addPost",
        kind="UNIT", dataSourceName=ds["name"], runtime=APPSYNC_JS, code=JS_ECHO_ARGS,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="addPost")
    )

    k1 = svc.create_api_key(apiId=api_id, description="sim2real-behav appsync doomed key")
    k1_id = k1["apiKey"]["id"]
    # Registered even though deleting it IS the act: if the delete below is wrongly rejected
    # the key still exists, and a failing assert must not leak it.
    ctx.on_cleanup(lambda: _tolerate_notfound(svc.delete_api_key, apiId=api_id, id=k1_id))
    k2_id = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync surviving key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: _tolerate_notfound(svc.delete_api_key, apiId=api_id, id=k2_id))

    svc.delete_api_key(apiId=api_id, id=k1_id)

    key_ids = set()
    paginator_token = None
    while True:
        kwargs = {"apiId": api_id, "maxResults": 25}
        if paginator_token:
            kwargs["nextToken"] = paginator_token
        page = svc.list_api_keys(**kwargs)
        key_ids.update(k["id"] for k in page.get("apiKeys", []))
        paginator_token = page.get("nextToken")
        if not paginator_token:
            break
    assert k1_id not in key_ids, f"the deleted API key is still listed: {sorted(key_ids)!r}"
    assert k2_id in key_ids, f"the surviving API key is missing from the listing: {sorted(key_ids)!r}"

    gql_host = urllib.parse.urlsplit(graphql_uri).hostname
    dead_auth = {"host": gql_host, "x-api-key": k1_id}
    dead_ws = _WS(*ctx.endpoint_route(_realtime_url(realtime_uri, dead_auth), websocket=True))
    ctx.on_cleanup(dead_ws.close)

    # AppSync ACCEPTS the WebSocket upgrade for a deleted key -- HTTP 101,
    # Sec-WebSocket-Protocol: graphql-ws -- and refuses inside a `connection_error` frame in reply
    # to connection_init, so a 401 on the upgrade itself is a different behavior.
    assert dead_ws.status == 101, (
        f"real AWS accepts the realtime UPGRADE for a revoked key and refuses in a frame; "
        f"this endpoint refused at the upgrade with HTTP {dead_ws.status!r} "
        f"headers={dead_ws.headers[:400]!r}"
    )
    refusal_deadline = time.monotonic() + 45.0
    dead_ws.send_json({"type": "connection_init"})
    refusal = None
    while time.monotonic() < refusal_deadline:
        msg = dead_ws.recv_json(refusal_deadline)
        if msg is None:
            break
        if msg.get("type") in ("connection_error", "error", "__closed__"):
            refusal = msg
            break
        assert msg.get("type") != "connection_ack", (
            f"the realtime endpoint ACKNOWLEDGED a connection authenticated with a DELETED "
            f"API key: {msg!r}"
        )
    assert isinstance(refusal, dict), (
        "the deleted API key neither completed nor failed the realtime handshake within 45s"
    )
    assert refusal["type"] == "connection_error", (
        f"expected the revocation to surface as a connection_error frame, got {refusal!r}"
    )
    observed = _error_types(refusal.get("payload") or {})
    assert len(observed) == 1, (
        f"expected exactly one errorType on the connection_error frame, got {observed!r} "
        f"in {refusal!r}"
    )
    assert observed[0] == "UnauthorizedException", (
        f"the deleted API key was not refused with UnauthorizedException on the realtime "
        f"handshake; got {observed[0]!r} in {refusal!r}"
    )

    # ----- positive control: K2, same API, same subscription, real delivery -----
    live_auth = {"host": gql_host, "x-api-key": k2_id}
    ws = _WS(*ctx.endpoint_route(_realtime_url(realtime_uri, live_auth), websocket=True))
    ctx.on_cleanup(ws.close)
    assert ws.status == 101, (
        f"the control key was refused the WebSocket upgrade: HTTP {ws.status!r} "
        f"headers={ws.headers[:400]!r}"
    )

    deadline = time.monotonic() + 60.0
    ws.send_json({"type": "connection_init"})
    ack = ws.recv_json(deadline)
    assert isinstance(ack, dict) and ack.get("type") == "connection_ack", (
        f"the surviving key did not complete the realtime handshake: {ack!r}"
    )

    sub_id = ctx.unique_name("sub-")
    ws.send_json({
        "id": sub_id,
        "type": "start",
        "payload": {
            "data": json.dumps({"query": "subscription OnAdd { onAddPost { id body } }",
                                "variables": {}}),
            "extensions": {"authorization": live_auth},
        },
    })
    start_ack = None
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            break
        if msg.get("type") in ("start_ack", "error", "connection_error", "__closed__"):
            start_ack = msg
            break
    assert isinstance(start_ack, dict) and start_ack.get("type") == "start_ack", (
        f"the control subscription was not accepted: {start_ack!r}"
    )

    marker = ctx.unique_name("post-")
    status, published = _post_json(
        ctx, graphql_uri, {"x-api-key": k2_id},
        {"query": ("mutation Add($id: ID!, $body: String) "
                   "{ addPost(id: $id, body: $body) { id body } }"),
         "variables": {"id": marker, "body": marker}},
    )
    assert status == 200 and not published.get("errors"), (
        f"the control mutation failed: {status!r} {published!r}"
    )

    frame_deadline = time.monotonic() + 60.0
    delivered = None
    while time.monotonic() < frame_deadline:
        msg = ws.recv_json(frame_deadline)
        if msg is None:
            break
        if msg.get("type") == "data":
            delivered = msg
            break
    assert isinstance(delivered, dict), (
        f"the surviving key held a subscription that never received the mutation: "
        f"start_ack={start_ack!r} published={published!r}"
    )
    assert delivered["payload"]["data"]["onAddPost"]["id"] == marker, (
        f"the control subscription received the wrong post: {delivered['payload']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
