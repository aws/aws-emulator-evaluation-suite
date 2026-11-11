"""obs-appsync-2-realtime-connect-rejected-counts-client-error."""
from __future__ import annotations

# What this check pins:
#
#   N1  A GraphQL realtime connect carrying an API key the API never issued is NOT refused at
#       the HTTP upgrade: the server answers 101, and refuses at connection_init with a
#       connection_error frame whose single error is errorType "UnauthorizedException",
#       errorCode 401.
#   N2  That refusal is counted: one rejected + one accepted connect on the same API read
#       ConnectRequests Sum 2, ConnectSuccess Sum 1 (SampleCount 2 -- the refusal is a 0 sample),
#       ConnectClientError Sum 1, all under exactly [GraphQLAPIId].

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
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-appsync-2-realtime-connect-rejected-counts-client-error"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
API_DIM = "GraphQLAPIId"
POLL_TIMEOUT_S = 600.0
POLL_INTERVAL_S = 20.0
COUNTERS = ("ConnectRequests", "ConnectSuccess", "ConnectClientError")

SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Post {
    id: ID!
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    addPost(id: ID!): Post
}
type Subscription {
    onAddPost: Post @aws_subscribe(mutations: ["addPost"])
}
"""


# ===== shared helpers (self-contained) =====


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
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
    """A minimal RFC6455 text-frame client, over TLS for wss://, stdlib only."""

    def __init__(self, url, *, subprotocol="graphql-ws", timeout_s=25.0, ctx=None):
        parts = urllib.parse.urlsplit(url)
        self.host = parts.hostname
        target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        self.eof = False
        self._buf = b""
        _t = urllib.parse.urlsplit(ctx.endpoint_url(url))
        secure = _t.scheme in ("wss", "https")
        raw = socket.create_connection((_t.hostname, _t.port or (443 if secure else 80)), timeout=timeout_s)
        self._sock = _ssl_context(ctx.http_verify).wrap_socket(raw, server_hostname=self.host) if secure else raw
        nonce = base64.b64encode(os.urandom(16)).decode()
        self._sock.sendall(
            (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
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
        """Next application message as a dict, or None once ``deadline`` passes. Pings are
        ponged here; a close frame surfaces as a synthetic ``__closed__`` message."""
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


def _service_socket(ws, seconds, sink):
    """Read the socket for ``seconds`` -- answering pings, collecting every non-keepalive
    message into ``sink`` -- instead of sleeping. This IS the poll interval: a held-open
    realtime connection must be serviced or the server drops it."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not ws.eof:
        msg = ws.recv_json(deadline)
        if msg is None:
            break
        if msg.get("type") != "ka":
            sink.append(msg)


def _series(cw, name, dims, since):
    """[(timestamp, Sum, Maximum)] for one metric at Period 60, oldest first."""
    resp = cw.get_metric_statistics(
        Namespace=NAMESPACE, MetricName=name,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=since, EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60, Statistics=["Sum", "Maximum"],
    )
    return sorted(
        ((p["Timestamp"], p["Sum"], p["Maximum"]) for p in resp.get("Datapoints") or []),
        key=lambda t: t[0],
    )


def _catalogue(cw, dims):
    """{metric name: [sorted dimension-name tuple, ...]} for every AWS/AppSync metric carrying
    ``dims`` -- ListMetrics' filter matches supersets, so the exact sets are kept for the caller."""
    out = {}
    pages = cw.get_paginator("list_metrics").paginate(
        Namespace=NAMESPACE, Dimensions=[{"Name": k, "Value": v} for k, v in dims],
    )
    for page in pages:
        for m in page.get("Metrics", []):
            out.setdefault(m["MetricName"], []).append(
                tuple(sorted(d["Name"] for d in m.get("Dimensions", [])))
            )
    return out


def _poll_metrics(ws, cw, dims, since, names, predicate, description, sink=None):
    """Poll ListMetrics + GetMetricStatistics every POLL_INTERVAL_S for up to POLL_TIMEOUT_S.

    Returns the snapshot that satisfied ``predicate``. On timeout it FAILS with the LAST
    ListMetrics catalogue and every series attached -- a check never skips, and a metric that
    never arrives is a fidelity failure the dump must make readable."""
    deadline = time.monotonic() + POLL_TIMEOUT_S
    snap = None
    while True:
        snap = {
            "catalogue": _catalogue(cw, dims),
            "series": {n: _series(cw, n, dims, since) for n in names},
        }
        if predicate(snap):
            return snap
        if time.monotonic() >= deadline:
            break
        if ws is not None and not ws.eof:
            _service_socket(ws, POLL_INTERVAL_S, sink if sink is not None else [])
        else:
            time.sleep(POLL_INTERVAL_S)
    raise AssertionError(
        f"{description} not met within {POLL_TIMEOUT_S:.0f}s. Last ListMetrics catalogue for "
        f"{dims!r}: {snap['catalogue']!r}. Last GetMetricStatistics series: {snap['series']!r}"
    )


def _total(series):
    return sum(s for _t, s, _m in series)


def _minute_floor(dt):
    return dt.replace(second=0, microsecond=0)


# ===== end shared helpers =====


def _first_reply(ws, timeout_s=30.0):
    """The first non-keepalive message after connection_init, or None on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None or msg.get("type") != "ka":
            return msg
    return None


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html
@tags(
    "axis:rejection",
    "concern:metrics",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A realtime connect with an unknown API key is rejected and counted as ConnectClientError,
    never ConnectSuccess.
    """
    svc = ctx.client("appsync")
    cw = ctx.client("cloudwatch")
    since = datetime.now(timezone.utc) - timedelta(minutes=2)

    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-obs-appsync-2-neg-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    dims = [(API_DIM, api_id)]
    svc.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
    schema_deadline = time.monotonic() + 120.0
    schema = svc.get_schema_creation_status(apiId=api_id)
    while schema["status"] not in ("SUCCESS", "ACTIVE", "FAILED") and time.monotonic() < schema_deadline:
        time.sleep(2.0)
        schema = svc.get_schema_creation_status(apiId=api_id)
    assert schema["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: status={schema['status']!r} "
        f"details={schema.get('details')!r}"
    )
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL") and uris.get("REALTIME"), f"missing endpoint URIs: {uris!r}"
    host = urllib.parse.urlsplit(uris["GRAPHQL"]).hostname
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real obs-appsync-2 negative-connect key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    # ---- positive control: the real key is acked ------------------------------------------
    control_refusals = 0
    ack = None
    control_deadline = time.monotonic() + 90.0
    while time.monotonic() < control_deadline:
        ok = _WS(_realtime_url(uris["REALTIME"], {"host": host, "x-api-key": api_key}), ctx=ctx)
        ctx.on_cleanup(ok.close)
        assert ok.status == 101, f"the real key's upgrade was refused: HTTP {ok.status!r}"
        ok.send_json({"type": "connection_init"})
        ack = _first_reply(ok)
        ok.close()
        if isinstance(ack, dict) and ack.get("type") == "connection_ack":
            break
        control_refusals += 1
        time.sleep(3.0)
    assert isinstance(ack, dict) and ack.get("type") == "connection_ack", (
        f"the positive control never connected with the API's own key: {ack!r}"
    )

    # ---- the rejected connect --------------------------------------------------------------
    unknown_key = "da2-" + os.urandom(13).hex()
    bad = _WS(_realtime_url(uris["REALTIME"], {"host": host, "x-api-key": unknown_key}), ctx=ctx)
    ctx.on_cleanup(bad.close)
    assert bad.status == 101, (
        f"real AWS upgrades first and refuses at connection_init; got HTTP {bad.status!r} "
        f"headers={bad.headers[:300]!r}"
    )
    bad.send_json({"type": "connection_init"})
    refusal = _first_reply(bad)
    bad.close()
    assert isinstance(refusal, dict) and refusal.get("type") == "connection_error", (
        f"an API key the API never issued must be refused with connection_error; got {refusal!r}"
    )
    errors = (refusal.get("payload") or {}).get("errors") or []
    assert len(errors) == 1, f"expected exactly one error in the refusal, got {refusal!r}"
    assert errors[0].get("errorType") == "UnauthorizedException", (
        f"the refusal must be UnauthorizedException, got {errors[0]!r}"
    )
    assert errors[0].get("errorCode") == 401, (
        f"the refusal must carry errorCode 401, got {errors[0]!r}"
    )

    # ---- the counters: the refusal is a client error, never a success ----------------------
    expected_requests = 2 + control_refusals
    expected_client_errors = 1 + control_refusals
    snap = _poll_metrics(
        None, cw, dims, since, list(COUNTERS),
        lambda s: all((API_DIM,) in s["catalogue"].get(n, []) for n in COUNTERS)
        and _total(s["series"]["ConnectRequests"]) >= expected_requests
        and _total(s["series"]["ConnectClientError"]) >= expected_client_errors
        and _total(s["series"]["ConnectSuccess"]) >= 1,
        f"ConnectRequests >= {expected_requests}, ConnectClientError >= {expected_client_errors} "
        f"and ConnectSuccess >= 1, with all of {list(COUNTERS)} under exactly [{API_DIM}]",
    )
    ser = snap["series"]
    assert _total(ser["ConnectRequests"]) == expected_requests, (
        f"{expected_requests} connects were attempted; ConnectRequests read "
        f"{ser['ConnectRequests']!r}"
    )
    assert _total(ser["ConnectClientError"]) == expected_client_errors, (
        f"the rejected connect must be counted as a client error ({expected_client_errors} "
        f"expected); ConnectClientError read {ser['ConnectClientError']!r}"
    )
    assert _total(ser["ConnectSuccess"]) == 1, (
        f"only the positive control connected, so ConnectSuccess Sum must be 1 -- a 2 means the "
        f"rejected connect was booked as a success; got {ser['ConnectSuccess']!r}"
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
