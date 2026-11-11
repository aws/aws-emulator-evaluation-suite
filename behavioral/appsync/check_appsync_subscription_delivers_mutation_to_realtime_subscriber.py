"""appsync-subscription-delivers-mutation-to-realtime-subscriber."""
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

CHECK = "appsync-subscription-delivers-mutation-to-realtime-subscriber"
GROUP = 'data-plane'
SERVICES = ['appsync']

SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Post {
    id: ID!
    body: String
    secret: String
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    addPost(id: ID!, body: String, secret: String): Post
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


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A live realtime subscriber receives an HTTPS mutation's result, narrowed to its selection set.

    The push arrives as a server-initiated WebSocket ``data`` frame that no client request
    answers, and AppSync projects the mutation result onto the subscription's fields.
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

    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync realtime subscriber key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    auth = {"host": urllib.parse.urlsplit(graphql_uri).hostname, "x-api-key": api_key}
    ws = _WS(*ctx.endpoint_route(_realtime_url(realtime_uri, auth), websocket=True))
    ctx.on_cleanup(ws.close)
    assert ws.status == 101, (
        f"the realtime endpoint refused the WebSocket upgrade: HTTP {ws.status!r} "
        f"headers={ws.headers[:400]!r}"
    )

    deadline = time.monotonic() + 60.0
    ws.send_json({"type": "connection_init"})
    ack = ws.recv_json(deadline)
    assert isinstance(ack, dict) and ack.get("type") == "connection_ack", (
        f"realtime handshake failed: expected connection_ack, got {ack!r}"
    )

    sub_id = ctx.unique_name("sub-")
    sub_doc = "subscription OnAdd { onAddPost { id body } }"
    ws.send_json({
        "id": sub_id,
        "type": "start",
        "payload": {
            "data": json.dumps({"query": sub_doc, "variables": {}}),
            "extensions": {"authorization": auth},
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
        f"the subscription was not accepted on the live socket: {start_ack!r}"
    )

    marker = ctx.unique_name("post-")
    body_marker = ctx.unique_name("body-")
    secret_marker = ctx.unique_name("secret-")
    mutation = (
        "mutation Add($id: ID!, $body: String, $secret: String) "
        "{ addPost(id: $id, body: $body, secret: $secret) { id body secret } }"
    )
    status, published = _post_json(
        ctx, graphql_uri, {"x-api-key": api_key},
        {"query": mutation,
         "variables": {"id": marker, "body": body_marker, "secret": secret_marker}},
    )
    assert status == 200, f"the mutation POST did not return 200: {status!r} body={published!r}"
    assert not published.get("errors"), (
        f"the mutation itself failed, so nothing could be published: {published!r}"
    )
    assert published["data"]["addPost"]["secret"] == secret_marker, (
        f"the mutation did not store the secret field, so the selection-set assertion below "
        f"would be vacuous: {published!r}"
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
        assert msg.get("type") not in ("error", "connection_error", "__closed__"), (
            f"the socket failed instead of delivering the mutation: {msg!r}"
        )
    assert isinstance(delivered, dict), (
        f"no data frame arrived within 60s of the mutation; the subscription is registered "
        f"(start_ack was {start_ack!r}) and the mutation succeeded ({published!r})"
    )

    assert delivered.get("id") == sub_id, (
        f"the data frame was not addressed to this subscription: {delivered!r}"
    )
    post = delivered["payload"]["data"]["onAddPost"]
    assert post["id"] == marker, f"the subscriber got the wrong post: {delivered['payload']!r}"
    assert post["body"] == body_marker, (
        f"the published payload lost the mutation's body: {delivered['payload']!r}"
    )
    assert "secret" not in post, (
        f"a field outside the SUBSCRIPTION's selection set was delivered: "
        f"{sorted(post)!r} -- AppSync must project the mutation result onto the "
        f"subscription document, not forward the mutation's own selection set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
