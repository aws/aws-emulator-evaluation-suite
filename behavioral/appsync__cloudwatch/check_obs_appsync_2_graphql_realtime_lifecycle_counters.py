"""obs-appsync-2-graphql-realtime-lifecycle-counters."""
from __future__ import annotations

# The realtime counters publish under [GraphQLAPIId] only. ActiveSubscriptions and
# ActiveConnections are per-minute gauges sampled while the socket is open, so the zero reading
# is observable only with the connection held open; datapoints appear within about a minute.

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

CHECK = "obs-appsync-2-graphql-realtime-lifecycle-counters"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
API_DIM = "GraphQLAPIId"
POLL_TIMEOUT_S = 600.0
POLL_INTERVAL_S = 20.0
MATCHING = 3
REQUIRED = (
    "ConnectSuccess", "SubscribeSuccess", "PublishDataMessageSuccess", "UnsubscribeSuccess",
    "DisconnectSuccess", "ActiveSubscriptions", "ActiveConnections",
)

SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Post {
    id: ID!
    channel: String
    body: String
}
type Query {
    getPost(id: ID!): Post
}
type Mutation {
    addPost(id: ID!, channel: String!, body: String): Post
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

# Installed at SUBSCRIBE time; AppSync evaluates it against every later mutation result.
JS_CHANNEL_FILTER = """import { extensions } from '@aws-appsync/utils';

export function request(ctx) {
  extensions.setSubscriptionFilter({
    filterGroup: [
      { filters: [ { fieldName: 'channel', operator: 'eq', value: 'alpha' } ] }
    ]
  });
  return { payload: null };
}

export function response(ctx) {
  return null;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
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
    """A minimal RFC6455 text-frame client over TLS, stdlib only."""

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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html
@tags(
    "axis:happy-path",
    "concern:metrics",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """One realtime subscriber's connect, subscribe, filtered delivery, unsubscribe and disconnect
    land in AWS/AppSync as exact counters: PublishDataMessageSuccess counts only delivered frames,
    and ActiveSubscriptions falls to 0 while the connection stays open."""
    svc = ctx.client("appsync")
    cw = ctx.client("cloudwatch")
    since = datetime.now(timezone.utc) - timedelta(minutes=2)

    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-obs-appsync-2-gql-"),
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
    graphql_uri, realtime_uri = uris["GRAPHQL"], uris["REALTIME"]

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Mutation", fieldName="addPost", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO_ARGS,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Mutation", fieldName="addPost")
    )
    svc.create_resolver(
        apiId=api_id, typeName="Subscription", fieldName="onAddPost", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_CHANNEL_FILTER,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Subscription", fieldName="onAddPost")
    )
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real obs-appsync-2 realtime metrics key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    # ---- connect + subscribe (with the filter) ---------------------------------------------
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
    ws.send_json({
        "id": sub_id, "type": "start",
        "payload": {
            "data": json.dumps({
                "query": "subscription OnAdd { onAddPost { id channel body } }",
                "variables": {},
            }),
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
        f"the filtered subscription was not accepted on the live socket: {start_ack!r}"
    )

    # ---- the gauge must SEE the live subscription before anything is unsubscribed -----------
    stray = []
    _poll_metrics(
        ws, cw, dims, since, ["ActiveSubscriptions"],
        lambda s: any(mx >= 1 for _t, _s, mx in s["series"]["ActiveSubscriptions"]),
        "ActiveSubscriptions to sample the live subscription (Maximum >= 1)", sink=stray,
    )
    assert not [m for m in stray if m.get("type") == "data"], (
        f"a data frame arrived before any mutation was published: {stray!r}"
    )

    # ---- 3 matching mutations + 1 the filter must exclude -----------------------------------
    mutation = (
        "mutation Add($id: ID!, $channel: String!, $body: String) "
        "{ addPost(id: $id, channel: $channel, body: $body) { id channel body } }"
    )
    alpha_ids = [ctx.unique_name(f"alpha{i}-") for i in range(MATCHING)]
    beta_id = ctx.unique_name("beta-")
    for post_id, channel in [(alpha_ids[0], "alpha"), (beta_id, "beta"),
                             (alpha_ids[1], "alpha"), (alpha_ids[2], "alpha")]:
        status, body = _post_json(
            ctx, graphql_uri, {"x-api-key": api_key},
            {"query": mutation,
             "variables": {"id": post_id, "channel": channel, "body": post_id}},
        )
        assert status == 200 and not body.get("errors"), (
            f"mutation {channel!r} failed, so nothing was published: {status!r} {body!r}"
        )
        assert body["data"]["addPost"]["channel"] == channel, (
            f"mutation resolved with the wrong channel: {body!r}"
        )

    delivered = []
    frame_deadline = time.monotonic() + 60.0
    while time.monotonic() < frame_deadline and len(delivered) < MATCHING:
        msg = ws.recv_json(frame_deadline)
        if msg is None:
            break
        if msg.get("type") == "data":
            delivered.append(msg["payload"]["data"]["onAddPost"]["id"])
            continue
        assert msg.get("type") not in ("error", "connection_error", "__closed__"), (
            f"the socket failed instead of delivering: {msg!r}"
        )
    # The 3rd alpha arrival is the barrier: beta was published BEFORE alphas 2 and 3, so an
    # unfiltered service would already have delivered it. Drain briefly past the barrier.
    late = []
    _service_socket(ws, 10.0, late)
    delivered += [m["payload"]["data"]["onAddPost"]["id"] for m in late if m.get("type") == "data"]
    assert sorted(delivered) == sorted(alpha_ids), (
        f"the subscriber must receive exactly the {MATCHING} matching mutations "
        f"{sorted(alpha_ids)!r} and not the excluded {beta_id!r}; got {delivered!r}"
    )

    # ---- unsubscribe, keep the connection, watch the gauge fall to 0 ------------------------
    ws.send_json({"id": sub_id, "type": "stop"})
    stop_deadline = time.monotonic() + 30.0
    complete = None
    while time.monotonic() < stop_deadline:
        msg = ws.recv_json(stop_deadline)
        if msg is None or msg.get("type") in ("complete", "error", "__closed__"):
            complete = msg
            break
    assert isinstance(complete, dict) and complete.get("type") == "complete", (
        f"stop was not acknowledged with 'complete': {complete!r}"
    )
    after_unsub = _minute_floor(datetime.now(timezone.utc)) + timedelta(minutes=1)

    def _zero_with_live_connection(snap):
        subs = {t: mx for t, _s, mx in snap["series"]["ActiveSubscriptions"] if t >= after_unsub}
        conns = {t: mx for t, _s, mx in snap["series"]["ActiveConnections"] if t >= after_unsub}
        return any(subs[t] == 0 and conns.get(t, 0) >= 1 for t in subs)

    held = []
    gauges = _poll_metrics(
        ws, cw, dims, since, ["ActiveSubscriptions", "ActiveConnections"],
        _zero_with_live_connection,
        (f"a minute at/after {after_unsub.isoformat()} reading ActiveSubscriptions == 0 while "
         f"ActiveConnections >= 1 (connection held open after unsubscribe)"),
        sink=held,
    )
    assert not ws.eof, f"the server dropped the held connection: {held!r}"
    assert not [m for m in held if m.get("type") == "data"], (
        f"data arrived after the subscription was stopped: {held!r}"
    )
    conns = {t: mx for t, _s, mx in gauges["series"]["ActiveConnections"]}
    first_zero = min(
        t for t, _s, mx in gauges["series"]["ActiveSubscriptions"]
        if t >= after_unsub and mx == 0 and conns.get(t, 0) >= 1
    )
    relapsed = [(t, mx) for t, _s, mx in gauges["series"]["ActiveSubscriptions"]
                if t > first_zero and mx != 0]
    assert not relapsed, (
        f"once ActiveSubscriptions returned to 0 at {first_zero.isoformat()} it must stay 0 "
        f"while no subscription exists; later minutes read {relapsed!r}"
    )

    # ---- close, then the lifecycle counters --------------------------------------------------
    ws.close()

    def _all_counted(snap):
        cat, ser = snap["catalogue"], snap["series"]
        return (
            all((API_DIM,) in cat.get(n, []) for n in REQUIRED)
            and _total(ser["DisconnectSuccess"]) >= 1
            and _total(ser["PublishDataMessageSuccess"]) >= MATCHING
        )

    final = _poll_metrics(
        None, cw, dims, since, list(REQUIRED), _all_counted,
        "every realtime metric name under exactly [GraphQLAPIId] plus DisconnectSuccess >= 1 "
        "and PublishDataMessageSuccess >= 3",
    )
    cat, ser = final["catalogue"], final["series"]
    for name in REQUIRED:
        assert (API_DIM,) in cat[name], (
            f"{name} must be published under exactly [{API_DIM}]; ListMetrics shows "
            f"{cat.get(name)!r}"
        )
    assert _total(ser["ConnectSuccess"]) == 1, (
        f"one connection was opened: ConnectSuccess Sum must be 1, got {ser['ConnectSuccess']!r}"
    )
    assert _total(ser["SubscribeSuccess"]) == 1, (
        f"one subscription was started: SubscribeSuccess Sum must be 1, got "
        f"{ser['SubscribeSuccess']!r}"
    )
    assert _total(ser["UnsubscribeSuccess"]) == 1, (
        f"one subscription was stopped: UnsubscribeSuccess Sum must be 1, got "
        f"{ser['UnsubscribeSuccess']!r}"
    )
    assert _total(ser["DisconnectSuccess"]) == 1, (
        f"one connection was closed: DisconnectSuccess Sum must be 1, got "
        f"{ser['DisconnectSuccess']!r}"
    )
    # DisconnectSuccess lands in a LATER minute than the publishes, so its presence is the
    # barrier after which the publish minute is settled and the count can be pinned.
    published = _total(ser["PublishDataMessageSuccess"])
    assert published == MATCHING, (
        f"PublishDataMessageSuccess must count exactly the {MATCHING} DELIVERED frames -- the "
        f"filter-excluded mutation must not be counted (a 4 means it was); got Sum {published!r} "
        f"from {ser['PublishDataMessageSuccess']!r}"
    )
    assert max(mx for _t, _s, mx in ser["ActiveSubscriptions"]) >= 1, (
        f"ActiveSubscriptions never reported the live subscription: {ser['ActiveSubscriptions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
