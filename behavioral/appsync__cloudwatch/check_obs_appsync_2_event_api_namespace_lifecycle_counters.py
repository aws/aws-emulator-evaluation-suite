"""obs-appsync-2-event-api-namespace-lifecycle-counters."""
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
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-appsync-2-event-api-namespace-lifecycle-counters"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
POLL_TIMEOUT_S = 600.0
POLL_INTERVAL_S = 20.0
# BroadcastEventSuccess / OutboundMessages report fractional, rate-shaped Sums, so they are not
# pinned. Connection-scoped metrics carry only [EventAPIId]: a connection belongs to no namespace.
NS_REQUIRED = (
    "SubscribeSuccess", "UnsubscribeSuccess", "PublishHandlerInvocations", "SuccessfulEvents",
    "DroppedEvents", "FailedEvents",
)
CONNECTION_SCOPED = ("ConnectSuccess", "DisconnectSuccess", "ActiveSubscriptions",
                     "ActiveConnections")
KEEP = [True, False, True, True]  # the 2nd event is dropped by the onPublish handler

JS_ON_PUBLISH_FILTER = """export function onPublish(ctx) {
  return ctx.events.filter((e) => e.payload.keep === true);
}
"""


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _post_json(url, headers, payload, timeout_s=30, *, verify):
    """POST JSON and return (status, parsed_body); a 4xx/5xx is returned, not raised."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(verify)) as resp:
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

    def __init__(self, url, *, subprotocol="graphql-ws", timeout_s=25.0, route_headers, verify):
        parts = urllib.parse.urlsplit(url)
        self.host = parts.hostname
        target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        self.eof = False
        self._buf = b""
        secure = parts.scheme == "wss"
        raw = socket.create_connection((self.host, parts.port or (443 if secure else 80)), timeout=timeout_s)
        self._sock = _ssl_context(verify).wrap_socket(raw, server_hostname=self.host) if secure else raw
        nonce = base64.b64encode(os.urandom(16)).decode()
        self._sock.sendall(
            (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {route_headers.get('Host', self.host)}\r\n"
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
    """Service the socket for ``seconds`` (answer pings, collect messages into ``sink``) instead of
    sleeping: a held-open realtime connection must be serviced or the server drops it."""
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
    """Poll ListMetrics + GetMetricStatistics until ``predicate`` holds and return that snapshot.
    On timeout fail with the last catalogue and every series attached."""
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




def _b64url(obj):
    raw = base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
    return raw.replace("+", "-").replace("/", "_").rstrip("=")


def _event_hosts(dns):
    http_host = (dns or {}).get("HTTP")
    realtime_host = (dns or {}).get("REALTIME")
    assert http_host and realtime_host, f"the Event API exposed no HTTP/REALTIME dns: {dns!r}"
    return http_host, realtime_host


def _connect_event_ws(ctx, http_host, realtime_host, api_key, timeout_s=90.0):
    """Open the Event API realtime socket and wait for connection_ack, reconnecting on a refusal:
    a just-created api/key is refused ('Unable to find the Api.') for a few seconds."""
    auth = {"host": http_host, "x-api-key": api_key}
    protocol = f"aws-appsync-event-ws, header-{_b64url(auth)}"
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ws_url, ws_route_headers = ctx.endpoint_route(realtime_host, websocket=True)
        ws = _WS(
            f"{ws_url}/event/realtime", subprotocol=protocol,
            route_headers=ws_route_headers, verify=ctx.http_verify,
        )
        ctx.on_cleanup(ws.close)
        if ws.status == 101:
            ws.send_json({"type": "connection_init"})
            msg_deadline = time.monotonic() + 15.0
            while time.monotonic() < msg_deadline:
                msg = ws.recv_json(msg_deadline)
                if msg is None or msg.get("type") != "ka":
                    break
            if isinstance(msg, dict) and msg.get("type") == "connection_ack":
                return ws, auth
            last = msg
        else:
            last = {"http_status": ws.status, "headers": ws.headers[:300]}
        ws.close()
        time.sleep(3.0)
    raise AssertionError(f"the Event API realtime socket never acked within {timeout_s}s: {last!r}")


def _publish(ctx, http_host, api_key, channel, event, timeout_s=60.0):
    """POST one event to the HTTP data plane, retrying only while the namespace is still
    propagating. Returns (status, body) of the final attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        http_url, route_headers = ctx.endpoint_route(http_host)
        status, body = _post_json(
            f"{http_url}/event", {"x-api-key": api_key, **route_headers},
            {"channel": channel, "events": [json.dumps(event)]},
            verify=ctx.http_verify,
        )
        if status == 200 or time.monotonic() >= deadline:
            return status, body
        time.sleep(3.0)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appsync/latest/eventapi/monitoring.html
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
    """An Event API subscriber's lifecycle lands in CloudWatch: subscribe/publish counters under
    exactly [EventAPIId, ChannelNamespaceName], connection ones under [EventAPIId] only, and an
    event the onPublish handler drops counts as DroppedEvents, not FailedEvents.
    """
    svc = ctx.client("appsync")
    cw = ctx.client("cloudwatch")
    since = datetime.now(timezone.utc) - timedelta(minutes=2)
    tag_set = {"sim2real": CHECK, "sim2real:managed": "true"}

    api = svc.create_api(
        name=ctx.unique_name("sim2real-obs-appsync-2-ev-"),
        eventConfig={
            "authProviders": [{"authType": "API_KEY"}],
            "connectionAuthModes": [{"authType": "API_KEY"}],
            "defaultPublishAuthModes": [{"authType": "API_KEY"}],
            "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
        },
        tags=tag_set,
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_api(apiId=api_id))
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real obs-appsync-2 event metrics key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))
    ns_name = "ns" + ctx.unique_name("").replace("-", "")[-12:]
    svc.create_channel_namespace(
        apiId=api_id, name=ns_name, codeHandlers=JS_ON_PUBLISH_FILTER, tags=tag_set,
    )
    ctx.on_cleanup(lambda: svc.delete_channel_namespace(apiId=api_id, name=ns_name))
    api_dims = [("EventAPIId", api_id)]
    ns_dims = [("EventAPIId", api_id), ("ChannelNamespaceName", ns_name)]
    http_host, realtime_host = _event_hosts(api.get("dns"))
    channel = f"{ns_name}/room1"

    ws, auth = _connect_event_ws(ctx, http_host, realtime_host, api_key)
    sub_id, sub_reply = None, None
    sub_deadline = time.monotonic() + 60.0
    while time.monotonic() < sub_deadline:
        attempt = ctx.unique_name("sub-")
        ws.send_json({"type": "subscribe", "id": attempt, "channel": channel,
                      "authorization": auth})
        reply_deadline = time.monotonic() + 15.0
        while time.monotonic() < reply_deadline:
            msg = ws.recv_json(reply_deadline)
            if msg is None or (msg.get("id") == attempt
                               and msg.get("type") in ("subscribe_success", "subscribe_error")):
                sub_reply = msg
                break
            assert msg.get("type") != "__closed__", f"socket closed while subscribing: {msg!r}"
        if isinstance(sub_reply, dict) and sub_reply.get("type") == "subscribe_success":
            sub_id = attempt
            break
        time.sleep(3.0)
    assert sub_id, f"the channel subscription was never accepted: last reply {sub_reply!r}"

    stray = []
    _poll_metrics(
        ws, cw, api_dims, since, ["ActiveSubscriptions"],
        lambda s: any(mx >= 1 for _t, _s, mx in s["series"]["ActiveSubscriptions"]),
        "ActiveSubscriptions under [EventAPIId] to sample the live subscription", sink=stray,
    )
    assert not [m for m in stray if m.get("type") == "data"], (
        f"a data frame arrived before anything was published: {stray!r}"
    )

    markers = [ctx.unique_name(f"ev{i}-") for i in range(len(KEEP))]
    for marker, keep in zip(markers, KEEP):
        status, body = _publish(ctx, http_host, api_key, channel, {"m": marker, "keep": keep})
        assert status == 200 and body.get("failed") == [] and len(body.get("successful") or []) == 1, (
            f"publishing {marker!r} (keep={keep}) was not accepted: {status!r} {body!r}"
        )
    kept = [m for m, k in zip(markers, KEEP) if k]
    dropped = [m for m, k in zip(markers, KEEP) if not k]

    delivered = []
    frame_deadline = time.monotonic() + 60.0
    while time.monotonic() < frame_deadline and len(delivered) < len(kept):
        msg = ws.recv_json(frame_deadline)
        if msg is None:
            break
        if msg.get("type") == "data" and msg.get("id") == sub_id:
            raw = msg["event"][0] if isinstance(msg["event"], list) else msg["event"]
            delivered.append(json.loads(raw)["m"])
            continue
        assert msg.get("type") not in ("error", "connection_error", "__closed__"), (
            f"the socket failed instead of delivering: {msg!r}"
        )
    late = []
    _service_socket(ws, 10.0, late)
    for msg in late:
        if msg.get("type") == "data":
            raw = msg["event"][0] if isinstance(msg["event"], list) else msg["event"]
            delivered.append(json.loads(raw)["m"])
    assert sorted(delivered) == sorted(kept), (
        f"the subscriber must receive exactly the {len(kept)} kept events {sorted(kept)!r} "
        f"and not the handler-dropped {dropped!r}; got {delivered!r}"
    )

    ws.send_json({"type": "unsubscribe", "id": sub_id})
    unsub_deadline = time.monotonic() + 30.0
    unsub = None
    while time.monotonic() < unsub_deadline:
        msg = ws.recv_json(unsub_deadline)
        if msg is None or msg.get("id") == sub_id or msg.get("type") == "__closed__":
            unsub = msg
            break
    assert isinstance(unsub, dict) and unsub.get("type") == "unsubscribe_success", (
        f"unsubscribe was not acknowledged: {unsub!r}"
    )
    after_unsub = _minute_floor(datetime.now(timezone.utc)) + timedelta(minutes=1)

    def _zero_with_live_connection(snap):
        subs = {t: mx for t, _s, mx in snap["series"]["ActiveSubscriptions"] if t >= after_unsub}
        conns = {t: mx for t, _s, mx in snap["series"]["ActiveConnections"] if t >= after_unsub}
        return any(subs[t] == 0 and conns.get(t, 0) >= 1 for t in subs)

    held = []
    gauges = _poll_metrics(
        ws, cw, api_dims, since, ["ActiveSubscriptions", "ActiveConnections"],
        _zero_with_live_connection,
        (f"a minute at/after {after_unsub.isoformat()} reading ActiveSubscriptions == 0 while "
         f"ActiveConnections >= 1 under [EventAPIId]"),
        sink=held,
    )
    assert not ws.eof, f"the server dropped the held connection: {held!r}"
    assert not [m for m in held if m.get("type") == "data"], (
        f"data arrived after unsubscribe: {held!r}"
    )
    conns = {t: mx for t, _s, mx in gauges["series"]["ActiveConnections"]}
    first_zero = min(
        t for t, _s, mx in gauges["series"]["ActiveSubscriptions"]
        if t >= after_unsub and mx == 0 and conns.get(t, 0) >= 1
    )
    relapsed = [(t, mx) for t, _s, mx in gauges["series"]["ActiveSubscriptions"]
                if t > first_zero and mx != 0]
    assert not relapsed, (
        f"once ActiveSubscriptions returned to 0 at {first_zero.isoformat()} it must stay 0; "
        f"later minutes read {relapsed!r}"
    )

    ws.close()

    ns_exact = tuple(sorted(d for d, _v in ns_dims))
    ns_final = _poll_metrics(
        None, cw, ns_dims, since, list(NS_REQUIRED),
        lambda s: all(ns_exact in s["catalogue"].get(n, []) for n in NS_REQUIRED)
        and _total(s["series"]["PublishHandlerInvocations"]) >= len(KEEP)
        and _total(s["series"]["UnsubscribeSuccess"]) >= 1,
        "every namespace-scoped counter under exactly [EventAPIId, ChannelNamespaceName] with "
        "PublishHandlerInvocations >= 4 and UnsubscribeSuccess >= 1",
    )
    cat, ser = ns_final["catalogue"], ns_final["series"]
    assert _total(ser["SubscribeSuccess"]) == 1, (
        f"one subscription: SubscribeSuccess Sum must be 1, got {ser['SubscribeSuccess']!r}"
    )
    assert _total(ser["UnsubscribeSuccess"]) == 1, (
        f"one unsubscribe: UnsubscribeSuccess Sum must be 1, got {ser['UnsubscribeSuccess']!r}"
    )
    assert _total(ser["PublishHandlerInvocations"]) == len(KEEP), (
        f"the onPublish handler ran once per published event ({len(KEEP)}); got "
        f"{ser['PublishHandlerInvocations']!r}"
    )
    assert _total(ser["SuccessfulEvents"]) == len(KEEP), (
        f"all {len(KEEP)} publishes were accepted, so SuccessfulEvents Sum must be {len(KEEP)}; "
        f"got {ser['SuccessfulEvents']!r}"
    )
    assert _total(ser["DroppedEvents"]) == len(dropped), (
        f"the handler dropped exactly {len(dropped)} event, so DroppedEvents Sum must be "
        f"{len(dropped)} (an emulator that ignores the handler reads 0); got "
        f"{ser['DroppedEvents']!r}"
    )
    assert ser["FailedEvents"] and _total(ser["FailedEvents"]) == 0, (
        f"a handler-dropped event is not a failure: FailedEvents must be published with Sum 0, "
        f"got {ser['FailedEvents']!r}"
    )
    on_ns = sorted(n for n in CONNECTION_SCOPED if ns_exact in cat.get(n, []))
    assert not on_ns, (
        f"connection-scoped metrics belong to no namespace and must not be published under "
        f"[EventAPIId, ChannelNamespaceName]; found {on_ns!r} in {cat!r}"
    )

    api_final = _poll_metrics(
        None, cw, api_dims, since, list(CONNECTION_SCOPED),
        lambda s: all(("EventAPIId",) in s["catalogue"].get(n, []) for n in CONNECTION_SCOPED)
        and _total(s["series"]["DisconnectSuccess"]) >= 1,
        "the connection-scoped metrics under exactly [EventAPIId] with DisconnectSuccess >= 1",
    )
    aser = api_final["series"]
    assert _total(aser["ConnectSuccess"]) == 1, (
        f"one acked connection: ConnectSuccess Sum must be 1, got {aser['ConnectSuccess']!r}"
    )
    assert _total(aser["DisconnectSuccess"]) == 1, (
        f"one clean close: DisconnectSuccess Sum must be 1, got {aser['DisconnectSuccess']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
