"""deep-appsync-3-appsync-rt-invalidation-completes-only-matching-subscriber."""
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

CHECK = "deep-appsync-3-appsync-rt-invalidation-completes-only-matching-subscriber"
GROUP = "data-plane"
SERVICES = ["appsync"]

# Subscription arguments are ALSO delivery filters in AppSync: onMsg(group: "A") only receives
# publish results whose `group` field is "A" (measured: a publish with group "Z" reached neither
# subscriber). So each subscriber's own publications are the ones it is owed.
SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Msg {
    group: String
    body: String
}
type Query {
    ping: String
}
type Mutation {
    publish(group: String!, body: String!): Msg
    revoke(group: String!): Msg
}
type Subscription {
    onMsg(group: String!): Msg @aws_subscribe(mutations: ["publish"])
}
"""

JS_ECHO_ARGS = """export function request(ctx) {
  return { payload: ctx.args };
}

export function response(ctx) {
  return ctx.result;
}
"""

# The invalidation is raised from the mutation's RESPONSE handler, with a payload the service
# matches against every live subscription's invalidation filter.
JS_REVOKE = """import { extensions } from '@aws-appsync/utils';

export function request(ctx) {
  return { payload: { group: ctx.args.group, body: 'revoked' } };
}

export function response(ctx) {
  extensions.invalidateSubscriptions({
    subscriptionField: 'onMsg',
    payload: { group: ctx.args.group },
  });
  return ctx.result;
}
"""

# Installed at SUBSCRIBE time: this subscription is invalidated only by a payload whose group
# equals the group it subscribed with.
JS_SUBSCRIBE = """import { extensions } from '@aws-appsync/utils';

export function request(ctx) {
  extensions.setSubscriptionInvalidationFilter({
    filterGroup: [
      { filters: [ { fieldName: 'group', operator: 'eq', value: ctx.args.group } ] }
    ]
  });
  return { payload: null };
}

export function response(ctx) {
  return null;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

SUB_DOC = "subscription S($g: String!) { onMsg(group: $g) { group body } }"
PUBLISH = (
    "mutation P($g: String!, $b: String!) { publish(group: $g, body: $b) { group body } }"
)
REVOKE = "mutation R($g: String!) { revoke(group: $g) { group body } }"


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
    """A minimal RFC6455 text-frame client over TLS, stdlib only, so the check needs no
    third-party WebSocket package and no event loop."""

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


def _subscribe(ctx, realtime_uri, auth, group):
    """Open one socket, init it, start one onMsg(group) subscription -> (ws, sub_id)."""
    ws = _WS(*ctx.endpoint_route(_realtime_url(realtime_uri, auth), websocket=True))
    ctx.on_cleanup(ws.close)
    assert ws.status == 101, (
        f"the realtime endpoint refused the WebSocket upgrade for group {group!r}: "
        f"HTTP {ws.status!r} headers={ws.headers[:400]!r}"
    )
    deadline = time.monotonic() + 60.0
    ws.send_json({"type": "connection_init"})
    ack = ws.recv_json(deadline)
    assert isinstance(ack, dict) and ack.get("type") == "connection_ack", (
        f"realtime handshake for group {group!r} failed: expected connection_ack, got {ack!r}"
    )
    sub_id = ctx.unique_name(f"sub{group.lower()}-")
    ws.send_json({
        "id": sub_id,
        "type": "start",
        "payload": {
            "data": json.dumps({"query": SUB_DOC, "variables": {"g": group}}),
            "extensions": {"authorization": auth},
        },
    })
    start_ack = _next_event(ws, deadline)
    assert isinstance(start_ack, dict) and start_ack.get("type") == "start_ack" \
        and start_ack.get("id") == sub_id, (
            f"subscription for group {group!r} was not accepted: expected start_ack for "
            f"{sub_id!r}, got {start_ack!r}"
        )
    return ws, sub_id


def _next_event(ws, deadline):
    """Next non-keepalive message, or None at the deadline."""
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            return None
        if msg.get("type") != "ka":
            return msg
    return None


def _drain(ws, seconds):
    """Every non-keepalive message arriving within ``seconds``. Only ever called AFTER an
    observable barrier has been crossed, never in place of one."""
    deadline = time.monotonic() + seconds
    seen = []
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            break
        if msg.get("type") != "ka":
            seen.append(msg)
    return seen


@tags("axis:negative-delivery", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """invalidateSubscriptions ends only the subscription whose invalidation filter matches: it gets a
    "complete" frame on a still-open socket and no later data, while the twin subscriber keeps
    receiving its own group's publications."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-rtinv-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
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
    graphql_uri, realtime_uri = uris["GRAPHQL"], uris["REALTIME"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    for type_name, field, code in (
        ("Mutation", "publish", JS_ECHO_ARGS),
        ("Mutation", "revoke", JS_REVOKE),
        ("Subscription", "onMsg", JS_SUBSCRIBE),
    ):
        svc.create_resolver(
            apiId=api_id, typeName=type_name, fieldName=field, kind="UNIT",
            dataSourceName=ds["name"], runtime=APPSYNC_JS, code=code,
        )
        ctx.on_cleanup(
            lambda _t=type_name, _f=field: svc.delete_resolver(
                apiId=api_id, typeName=_t, fieldName=_f)
        )

    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync invalidation key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    auth = {"host": urllib.parse.urlsplit(graphql_uri).hostname, "x-api-key": api_key}
    ws_a, sub_a = _subscribe(ctx, realtime_uri, auth, "A")
    ws_b, sub_b = _subscribe(ctx, realtime_uri, auth, "B")

    def _gql(query, variables):
        status, body = _post_json(ctx, graphql_uri, {"x-api-key": api_key},
                                  {"query": query, "variables": variables})
        assert status == 200 and not body.get("errors"), (
            f"GraphQL call failed: {status!r} {body!r} for {variables!r}"
        )
        return body["data"]

    def _expect_data(ws, sub_id, group, marker, what):
        msg = _next_event(ws, time.monotonic() + 60.0)
        assert isinstance(msg, dict) and msg.get("type") == "data" and msg.get("id") == sub_id, (
            f"{what}: expected a data frame for {sub_id!r}, got {msg!r}"
        )
        got = msg["payload"]["data"]["onMsg"]
        assert got == {"group": group, "body": marker}, (
            f"{what}: delivered the wrong payload: expected group={group!r} body={marker!r}, "
            f"got {got!r}"
        )

    # ---- positive control: both subscriptions are live before any invalidation ----------
    pre_a, pre_b = ctx.unique_name("pre-a-"), ctx.unique_name("pre-b-")
    _gql(PUBLISH, {"g": "A", "b": pre_a})
    _gql(PUBLISH, {"g": "B", "b": pre_b})
    _expect_data(ws_a, sub_a, "A", pre_a, "pre-invalidation delivery to subscriber A")
    _expect_data(ws_b, sub_b, "B", pre_b, "pre-invalidation delivery to subscriber B")

    # ---- invalidate group A only ---------------------------------------------------------
    revoked = _gql(REVOKE, {"g": "A"})["revoke"]
    assert revoked == {"group": "A", "body": "revoked"}, (
        f"the revoke mutation did not resolve through its handler: {revoked!r}"
    )
    ended = _next_event(ws_a, time.monotonic() + 60.0)
    assert isinstance(ended, dict) and ended.get("type") == "complete", (
        f"invalidateSubscriptions({{group: A}}) must end subscriber A's subscription with a "
        f"'complete' frame; got {ended!r}"
    )
    assert ended.get("id") == sub_a, (
        f"the 'complete' frame must name subscriber A's subscription id {sub_a!r}; got "
        f"{ended.get('id')!r}"
    )

    # ---- twin control: B still receives; A, now ended, does not ---------------------------
    post_a, post_b = ctx.unique_name("post-a-"), ctx.unique_name("post-b-")
    _gql(PUBLISH, {"g": "A", "b": post_a})
    _gql(PUBLISH, {"g": "B", "b": post_b})
    # Barrier: B's next event must be its own post-revoke publication -- NOT a 'complete'.
    _expect_data(ws_b, sub_b, "B", post_b,
                 "the non-matching twin after revoke(A) (it must neither be ended nor starved)")

    leaked = _drain(ws_a, 8.0)
    assert not [m for m in leaked if m.get("type") == "data"], (
        f"subscriber A was invalidated yet still received data after the twin's barrier: "
        f"{leaked!r}"
    )
    assert post_a not in json.dumps(leaked), (
        f"the post-revoke group-A publication reached the ended subscription: {leaked!r}"
    )
    assert not ws_a.eof, (
        "invalidation must end the SUBSCRIPTION, not the connection: measured on real AWS the "
        "socket stays open after 'complete', but this server closed it"
    )
    extra_b = _drain(ws_b, 2.0)
    assert not [m for m in extra_b if m.get("type") in ("complete", "error")], (
        f"the non-matching twin was ended or errored after the barrier: {extra_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
