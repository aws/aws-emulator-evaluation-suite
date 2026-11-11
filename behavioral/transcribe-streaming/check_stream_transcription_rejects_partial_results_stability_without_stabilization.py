"""stream-transcription-rejects-partial-results-stability-without-stabilization."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import socket
import ssl
import struct
import time
import urllib.parse

from botocore.eventstream import EventStreamBuffer

from behavioral_harness import tags
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest

CHECK = "stream-transcription-rejects-partial-results-stability-without-stabilization"
GROUP = "negative-classes"
SERVICES = ["transcribe-streaming"]


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Asking for a partial-results stability level without enabling stabilization is
    refused with BadRequestException and transcribes nothing; supplying both parameters
    streams normally."""
    audio = _pcm_tone(1.0)

    rejected = _stream(ctx, dict(_BASE_PARAMS, **{"partial-results-stability": "high"}), audio)
    raised = _exceptions(rejected)
    assert len(raised) == 1, f"expected exactly one exception message, got {raised!r}"
    kind, message = raised[0]
    assert kind == "BadRequestException", (
        f"stability without stabilization raised {kind!r} ({message!r}), expected "
        f"BadRequestException"
    )
    assert message == (
        "Partial Results Stabilization must be enabled while specifying partial results "
        "stability in the request. Please enable Partial Results Stabilization and try again."
    ), f"unexpected message for the missing stabilization flag: {message!r}"
    assert [e for e in rejected["events"] if e["event_type"] == "TranscriptEvent"] == [], (
        f"a rejected stream still transcribed audio: {rejected['events']!r}"
    )

    accepted = _stream(ctx, dict(_BASE_PARAMS, **{
        "enable-partial-results-stabilization": "true", "partial-results-stability": "high",
    }), audio)
    assert _exceptions(accepted) == [], (
        f"supplying both parameters raised {_exceptions(accepted)!r}"
    )
    assert accepted["events"], "the positive control returned no event at all"


# botocore ships no `transcribestreaming` service model, so there is no ctx.client() for this
# API at all: the streaming data plane is spoken directly over its documented WebSocket
# endpoint — a SigV4 query-signed upgrade, then vnd.amazon.eventstream messages in both
# directions (AudioEvent up, TranscriptEvent/exception down).
_WS_PATH = "/stream-transcription-websocket"
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_AUDIO_EVENT_HEADERS = {
    ":message-type": "event",
    ":event-type": "AudioEvent",
    ":content-type": "application/octet-stream",
}
_BASE_PARAMS = {"language-code": "en-US", "media-encoding": "pcm", "sample-rate": "16000"}


def _target(ctx) -> tuple[str, int, bool]:
    """(host, port, tls) for the streaming data plane."""
    parsed = urllib.parse.urlsplit(
        ctx.service_url(f"https://transcribestreaming.{ctx.region}.amazonaws.com:8443")
    )
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), \
        parsed.scheme == "https"


def _presigned_query(ctx, params: dict) -> str:
    """The SigV4 query-signed query string for the WebSocket upgrade."""
    host, port, tls = _target(ctx)
    creds = ctx.client("sts")._request_signer._credentials
    assert creds is not None, "no credentials resolved for the streaming data plane"
    query = "&".join(
        f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items())
    )
    scheme = "https" if tls else "http"
    request = AWSRequest(method="GET", url=f"{scheme}://{host}:{port}{_WS_PATH}?{query}")
    SigV4QueryAuth(creds, "transcribe", ctx.region, expires=300).add_auth(request)
    return urllib.parse.urlsplit(request.url).query


def _eventstream_message(headers: dict, payload: bytes) -> bytes:
    """One vnd.amazon.eventstream message: prelude + prelude CRC, headers, payload, msg CRC."""
    blob = b""
    for name, value in headers.items():
        name_bytes = name.encode()
        value_bytes = value.encode()
        blob += struct.pack("!B", len(name_bytes)) + name_bytes + b"\x07" \
            + struct.pack("!H", len(value_bytes)) + value_bytes
    prelude = struct.pack("!II", 16 + len(blob) + len(payload), len(blob))
    head = prelude + struct.pack("!I", binascii.crc32(prelude) & 0xFFFFFFFF) + blob + payload
    return head + struct.pack("!I", binascii.crc32(head) & 0xFFFFFFFF)


def _ws_frame(payload: bytes, opcode: int = 0x2) -> bytes:
    """A masked client WebSocket frame — RFC 6455 requires client frames to be masked."""
    size = len(payload)
    if size < 126:
        header = struct.pack("!BB", 0x80 | opcode, 0x80 | size)
    elif size <= 0xFFFF:
        header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, size)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, size)
    mask = os.urandom(4)
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def _ws_unframe(pending: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Every complete server frame in ``pending`` as (opcode, payload), plus the remainder."""
    frames: list[tuple[int, bytes]] = []
    while len(pending) >= 2:
        first, second = pending[0], pending[1]
        size = second & 0x7F
        offset = 2
        if size == 126:
            if len(pending) < 4:
                break
            size = struct.unpack("!H", pending[2:4])[0]
            offset = 4
        elif size == 127:
            if len(pending) < 10:
                break
            size = struct.unpack("!Q", pending[2:10])[0]
            offset = 10
        assert not second & 0x80, "server sent a MASKED WebSocket frame, which RFC 6455 forbids"
        if len(pending) < offset + size:
            break
        frames.append((first & 0x0F, pending[offset:offset + size]))
        pending = pending[offset + size:]
    return frames, pending


def _upgrade(ctx, params: dict, timeout_s: float = 30.0, query: str | None = None) -> dict:
    """Open the TLS socket and perform the WebSocket upgrade.

    ``query`` overrides the signed query string, so a check can drive the handshake with a
    query of its own making.
    """
    host, port, tls = _target(ctx)
    query = _presigned_query(ctx, params) if query is None else query
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        f"GET {_WS_PATH}?{query} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").splitlines()
    parts = lines[0].split() if lines else []
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return {
        "sock": sock,
        "status": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
        "status_line": lines[0] if lines else "",
        "headers": headers,
        "body": rest,
        "expected_accept": base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()  # noqa: S324 - RFC 6455 mandates sha1
        ).decode(),
    }


def _drain(sock, budget_s: float) -> dict:
    """Read server frames until the close frame or ``budget_s`` expires."""
    buffer = EventStreamBuffer()
    events: list[dict] = []
    pending = b""
    close_code = None
    close_reason = None
    sock.settimeout(budget_s)
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and close_code is None:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        pending += chunk
        frames, pending = _ws_unframe(pending)
        for opcode, payload in frames:
            if opcode == 0x8:
                close_code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 0
                close_reason = payload[2:].decode("utf-8", "replace")
                break
            if opcode == 0x9:
                sock.sendall(_ws_frame(payload, opcode=0x0A))
                continue
            if opcode not in (0x0, 0x2):
                continue
            buffer.add_data(payload)
            for message in buffer:
                headers = dict(message.headers)
                events.append({
                    "message_type": headers.get(":message-type"),
                    "event_type": headers.get(":event-type"),
                    "exception_type": headers.get(":exception-type"),
                    "content_type": headers.get(":content-type"),
                    "payload": message.payload,
                })
    return {"events": events, "close_code": close_code, "close_reason": close_reason}


def _stream(ctx, params: dict, audio: bytes = b"", *, chunk_ms: int = 100,
            pace: float = 0.5, budget_s: float = 40.0,
            messages: list[bytes] | None = None, query: str | None = None) -> dict:
    """Run one full streaming session and return everything the server said.

    ``audio`` is chunked into AudioEvents and terminated with the documented empty
    AudioEvent; ``messages`` overrides that with raw eventstream bytes (used to probe the
    framing itself). The pacing loop is what makes this a live bidirectional stream rather
    than a request/response: results come back while later audio is still being written.
    """
    upgrade = _upgrade(ctx, params, query=query)
    sock = upgrade["sock"]
    try:
        assert upgrade["status"] == 101, (
            f"WebSocket upgrade for {params!r} returned {upgrade['status_line']!r}, expected "
            f"101; headers={upgrade['headers']!r} body={upgrade['body'][:400]!r}"
        )
        assert upgrade["headers"].get("sec-websocket-accept") == upgrade["expected_accept"], (
            f"Sec-WebSocket-Accept was {upgrade['headers'].get('sec-websocket-accept')!r}, "
            f"expected {upgrade['expected_accept']!r} for this Sec-WebSocket-Key"
        )
        if messages is None:
            channels = int(params.get("number-of-channels", 1))
            step = max(2, int(int(params["sample-rate"]) * 2 * channels * chunk_ms / 1000))
            messages = [_eventstream_message(_AUDIO_EVENT_HEADERS, audio[i:i + step])
                        for i in range(0, len(audio), step)]
            messages.append(_eventstream_message(_AUDIO_EVENT_HEADERS, b""))
        for message in messages:
            sock.sendall(_ws_frame(message))
            time.sleep(chunk_ms / 1000.0 * pace)
        session = _drain(sock, budget_s)
    finally:
        sock.close()
    session["status"] = upgrade["status"]
    session["headers"] = upgrade["headers"]
    session["session_id"] = upgrade["headers"].get("x-amzn-sessionid")
    session["request_id"] = upgrade["headers"].get("x-amzn-requestid")
    session["params"] = params
    return session


def _results(session: dict) -> list[dict]:
    """Every Result in every TranscriptEvent of a session, in arrival order."""
    out: list[dict] = []
    for event in session["events"]:
        if event["event_type"] != "TranscriptEvent":
            continue
        out.extend(json.loads(event["payload"])["Transcript"]["Results"])
    return out


def _exceptions(session: dict) -> list[tuple[str, str]]:
    """(exception type, message) for every exception message the stream carried."""
    return [(event["exception_type"], json.loads(event["payload"]).get("Message", ""))
            for event in session["events"] if event["message_type"] == "exception"]


def _transcript(result: dict) -> str:
    return result["Alternatives"][0]["Transcript"]


def _items(result: dict, kind: str = "pronunciation") -> list[dict]:
    return [i for i in result["Alternatives"][0]["Items"] if i["Type"] == kind]


def _finals(session: dict) -> list[dict]:
    return [r for r in _results(session) if not r["IsPartial"]]


def _heard_fraction(spoken: str, heard: str) -> tuple[float, list[str]]:
    """How much of ``spoken`` survives in ``heard``, and which words did not."""
    words = sorted({w.strip(".,!?").lower() for w in spoken.split() if w.strip(".,!?")})
    lowered = heard.lower()
    missing = [w for w in words if w not in lowered]
    return (len(words) - len(missing)) / len(words), missing


def _pcm_tone(seconds: float, rate: int = 16000, hz: float = 440.0) -> bytes:
    """Audio synthesized locally, in-process: 16-bit little-endian mono PCM, no asset fetched."""
    samples = bytearray()
    for i in range(int(seconds * rate)):
        samples += struct.pack("<h", int(12000 * math.sin(2 * math.pi * hz * i / rate)))
    return bytes(samples)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
