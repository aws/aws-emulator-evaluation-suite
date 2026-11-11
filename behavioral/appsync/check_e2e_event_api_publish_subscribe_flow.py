"""e2e-event-api-publish-subscribe-flow."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from urllib.parse import urlsplit

CHECK = "e2e-event-api-publish-subscribe-flow"
GROUP = "end-to-end"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An event published over an Event API's HTTP endpoint reaches a live WebSocket subscriber on
    the exact channel of the created namespace."""
    appsync = ctx.client("appsync")
    tag_set = {"sim2real": CHECK, "sim2real:managed": "true"}

    api_name = ctx.unique_name("sim2real-eventapi-")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    api = appsync.create_api(name=api_name, eventConfig=event_config, tags=tag_set)["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    key = appsync.create_api_key(apiId=api_id, description="sim2real publish key")["apiKey"]
    api_key_id = key["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=api_key_id))

    ns_name = _safe_channel_name(ctx, "ns")
    ns = appsync.create_channel_namespace(apiId=api_id, name=ns_name, tags=tag_set)["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=ns_name))
    assert ns["name"] == ns_name, f"expected created namespace name {ns_name!r}, got {ns['name']!r}"

    http_host, realtime_host = _identify_endpoints(api["dns"])
    channel = f"{ns_name}/room1"
    payload = {"msg": "hello-world"}
    event_payload = json.dumps(payload)

    ws_url, ws_route_headers = ctx.endpoint_route(realtime_host, websocket=True)
    sock = _connect_and_ack(
        ws_url, http_host, api_key_id, timeout_s=45,
        route_headers=ws_route_headers, verify=ctx.http_verify,
    )
    try:
        sub_id = _subscribe_with_retry(sock, channel, http_host, api_key_id, timeout_s=45)

        # Newly created Event APIs / keys / namespaces can take a few seconds to propagate
        # through the data plane. Poll with a bounded retry instead of a bare sleep.
        status, body = None, None
        deadline = time.time() + 60
        while time.time() < deadline:
            status, body = _publish_event(ctx, http_host, api_key_id, channel, [event_payload])
            if status == 200:
                break
            if isinstance(body, dict) and body.get("errors") and any(
                "ResourceNotFoundException" in str(e.get("errorType", "")) for e in body["errors"]
            ):
                time.sleep(3)
                continue
            break
        assert status == 200, f"publish did not return 200: status={status!r} body={body!r}"
        assert body.get("failed") == [], f"publish reported failed events: {body!r}"
        successful = body.get("successful", [])
        assert len(successful) == 1, f"expected exactly one successful publish, got {body!r}"
        assert "identifier" in successful[0], f"publish response missing identifier: {successful[0]!r}"

        # The terminal read: an INDEPENDENT observer on the realtime WebSocket -- not the
        # publish call's own response -- must actually receive the event on this channel.
        data_msg = _ws_wait_for(
            sock,
            lambda m: m.get("type") == "data" and m.get("id") == sub_id,
            timeout_s=20,
        )
        raw_event = data_msg["event"]
        # AppSync delivers a single-event "data" message with `event` as the
        # event's JSON text directly, not wrapped in a list, so index into it only if the API
        # actually gave us a list.
        delivered_raw = raw_event[0] if isinstance(raw_event, list) else raw_event
        try:
            delivered = json.loads(delivered_raw)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"could not decode delivered event from data_msg={data_msg!r}: {exc}"
            ) from exc
        assert delivered == payload, f"subscriber received {delivered!r}, expected {payload!r}"

        _ws_send_json(sock, {"type": "unsubscribe", "id": sub_id})
        _ws_wait_for(
            sock,
            lambda m: m.get("id") == sub_id and m.get("type") in ("unsubscribe_success", "unsubscribe_error"),
            timeout_s=10,
        )
    finally:
        sock.close()


def _safe_channel_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if c.isalnum() else "-" for c in raw)
    cleaned = cleaned.strip("-") or "ns0"
    return cleaned[:50]


def _identify_endpoints(dns_map: dict) -> tuple[str, str]:
    http_host = realtime_host = None
    for value in dns_map.values():
        host = value.split("://", 1)[-1].rstrip("/")
        if "realtime" in host:
            realtime_host = host
        else:
            http_host = host
    assert http_host and realtime_host, f"could not identify HTTP/realtime endpoints from dns={dns_map}"
    return http_host, realtime_host


def _publish_event(ctx, http_domain: str, api_key: str, channel: str, events: list[str]):
    http_url, route_headers = ctx.endpoint_route(http_domain)
    url = f"{http_url}/event"
    body = json.dumps({"channel": channel, "events": events}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "x-api-key": api_key, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _b64url(obj) -> str:
    raw = base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
    return raw.replace("+", "-").replace("/", "_").rstrip("=")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ws_connect(ws_url: str, http_host: str, api_key: str, *, route_headers, verify) -> socket.socket:
    parts = urlsplit(ws_url)
    secure = parts.scheme == "wss"
    raw = socket.create_connection((parts.hostname, parts.port or (443 if secure else 80)), timeout=15)
    sock = _ssl_context(verify).wrap_socket(raw, server_hostname=parts.hostname) if secure else raw
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    auth_protocol = "header-" + _b64url({"host": http_host, "x-api-key": api_key})
    request = (
        f"GET /event/realtime HTTP/1.1\r\n"
        f"Host: {route_headers.get('Host', parts.netloc)}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: aws-appsync-event-ws, {auth_protocol}\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode("utf-8"))
    sock.settimeout(15)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        raise AssertionError(f"WebSocket handshake failed: {status_line!r}")
    return sock


def _connect_and_ack(
    ws_url: str, http_host: str, api_key: str, *, timeout_s: float, route_headers, verify
) -> socket.socket:
    """Open the realtime WebSocket, send connection_init, and wait for connection_ack.

    A freshly created API key can take a few seconds to propagate; AppSync responds to an
    as-yet-unrecognized key by closing the just-upgraded socket rather than failing the HTTP
    upgrade itself, so a bounded reconnect-and-retry (not a single attempt) is required here.
    """
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        sock = _ws_connect(ws_url, http_host, api_key, route_headers=route_headers, verify=verify)
        try:
            _ws_send_json(sock, {"type": "connection_init"})
            _ws_wait_for(sock, lambda m: m.get("type") == "connection_ack", timeout_s=10)
            return sock
        except _WsNotReady as exc:
            last_exc = exc
            sock.close()
            time.sleep(3)
    raise AssertionError(f"never received connection_ack within {timeout_s}s; last error: {last_exc}")


def _subscribe_with_retry(sock, channel: str, http_host: str, api_key: str, *, timeout_s: float) -> str:
    """Send a subscribe message and wait for subscribe_success, retrying with a fresh id on
    subscribe_error -- a just-created channel namespace / API key can take a few seconds to
    propagate to the data plane, during which subscribe attempts are transiently rejected."""
    deadline = time.monotonic() + timeout_s
    last_ack = None
    while time.monotonic() < deadline:
        sub_id = str(uuid.uuid4())
        _ws_send_json(
            sock,
            {
                "type": "subscribe",
                "id": sub_id,
                "channel": channel,
                "authorization": {"host": http_host, "x-api-key": api_key},
            },
        )
        ack = _ws_wait_for(
            sock,
            lambda m: m.get("id") == sub_id and m.get("type") in ("subscribe_success", "subscribe_error"),
            timeout_s=15,
        )
        if ack["type"] == "subscribe_success":
            return sub_id
        last_ack = ack
        time.sleep(3)
    raise AssertionError(f"subscribe kept failing within {timeout_s}s; last ack: {last_ack}")


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading a WebSocket frame")
        buf += chunk
    return buf


def _ws_recv_frame(sock):
    """Read one complete WebSocket message, reassembling continuation frames per RFC 6455
    (a message can arrive as an initial FIN=0 frame followed by FIN=0/1 continuation frames;
    treating the first fragment alone as the whole message truncates any payload that doesn't
    fit in a single TCP-level frame)."""
    opcode = None
    payload = b""
    while True:
        header = _recv_exact(sock, 2)
        b1, b2 = header[0], header[1]
        fin = bool(b1 & 0x80)
        frame_opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
        mask_bit = b2 & 0x80
        mask_key = _recv_exact(sock, 4) if mask_bit else None
        frame_payload = _recv_exact(sock, length) if length else b""
        if mask_key:
            frame_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(frame_payload))
        if frame_opcode != 0x0:
            opcode = frame_opcode
        payload += frame_payload
        if fin:
            return opcode, payload


def _ws_send_text(sock, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    length = len(payload)
    if length <= 125:
        header.append(0x80 | length)
    elif length <= 65535:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def _ws_send_json(sock, obj) -> None:
    _ws_send_text(sock, json.dumps(obj))


class _WsNotReady(AssertionError):
    """The socket closed or stayed silent: the only failure the connection retry may absorb."""


def _ws_wait_for(sock, predicate, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(deadline - time.monotonic(), 0.1)
        sock.settimeout(remaining)
        try:
            opcode, payload = _ws_recv_frame(sock)
        except socket.timeout:
            continue
        if opcode == 0x8:
            raise _WsNotReady(f"server closed the WebSocket: {payload!r}")
        if opcode != 0x1:
            continue
        try:
            msg = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if predicate(msg):
            return msg
    raise _WsNotReady(f"timed out after {timeout_s}s waiting for the expected WebSocket message")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
