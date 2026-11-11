"""post-to-connection-fragments-large-payload-across-frames."""
from __future__ import annotations

import base64
import io
import json
import math
import os
import socket
import ssl
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-to-connection-fragments-large-payload-across-frames"

GROUP = "state"

SERVICES = ["apigatewaymanagementapi"]

#: The WebSocket frame-size quota, in bytes. From "Quotas for configuring and running a WebSocket
#: in API Gateway": `WebSocket frame size | 32 KB | Can be increased: No`. Pinning this is correct
#: because the quota is identical and non-adjustable in every account — unlike a
#: concurrency pool, it cannot be raised through Service Quotas or Support.
_FRAME_QUOTA_BYTES = 32 * 1024

#: The `Data` blob's modelled ceiling: `smithy.api#length {min: 0, max: 131072}` on
#: `com.amazonaws.apigatewaymanagementapi#Data`, matching the quota table's 128 KB message payload.
_MAX_DATA_BYTES = 128 * 1024

#: A payload that MUST fragment under any conforming splitter (3 full frames plus a remainder) and
#: still fits the message ceiling with room to spare. Derived from the quota, not a magic number.
_LARGE_BYTES = 3 * _FRAME_QUOTA_BYTES + 1234


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:representation", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PostToConnection payload above the 32 KB frame quota reaches the client as a FRAGMENTED
    RFC-6455 message — a leading data frame with FIN=0, continuation frames, a final FIN=1 frame,
    none exceeding the quota — and the reassembled bytes equal the sent bytes exactly.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role = _lambda_role(ctx, account)
    fn = _create_function(ctx, role["arn"])
    api_id, stage, api_endpoint = _deploy_websocket_api(ctx, account, fn)
    mgmt = _management_client(ctx, api_endpoint, stage)
    sock, connection_id = _open_and_identify(ctx, api_id, stage, api_endpoint)

    # Both payload sizes are correct BY CONSTRUCTION, so neither is guarded by an assert: the two
    # comparisons that would express it (_LARGE_BYTES <= _MAX_DATA_BYTES, and the control payload
    # being under the frame quota) are relations between module constants and a fixed-length
    # unique_name, so they can never fail at runtime and would only pad the assertion count.
    # For the record: _LARGE_BYTES is 3 * 32768 + 1234 = 99538, under the 131072 Data ceiling; and
    # ctx.unique_name returns tens of bytes, four orders of magnitude under the 32768 frame quota.

    # ---- calibration + positive control: a payload that fits ONE frame arrives as ONE frame ----
    # This is what makes the multi-frame result below meaningful. Without it, "I counted 25 frames"
    # could be an artifact of the reader rather than a property of the service, and the absence
    # assertion at the end would have no measured latency to derive its window from.
    small = ctx.unique_name("sim2real-behav-small-").encode()
    started = time.monotonic()
    mgmt.post_to_connection(ConnectionId=connection_id, Data=small)
    small_frames, small_message = _ws_recv_message(sock, timeout_s=60.0)
    small_latency = time.monotonic() - started
    assert small_message == small, (
        f"the single-frame control payload came back as {small_message[:120]!r} "
        f"({len(small_message)} bytes), not the {len(small)} bytes sent"
    )
    assert len(small_frames) == 1, (
        f"a {len(small)}-byte payload — well under the {_FRAME_QUOTA_BYTES}-byte frame quota — "
        f"arrived as {len(small_frames)} frames with sizes "
        f"{[len(p) for _, _, p in small_frames]}; a payload that fits one frame must not be split"
    )
    assert small_frames[0][0] is True, (
        f"the single-frame control payload ({len(small)} bytes) arrived with FIN=0, so the message "
        f"was never terminated and a real client would still be waiting for a continuation"
    )

    # ---- the subject: a payload above the frame quota ----
    large = _position_encoded(_LARGE_BYTES)
    mgmt.post_to_connection(ConnectionId=connection_id, Data=large)
    frames, message = _ws_recv_message(sock, timeout_s=90.0)
    sizes = [len(p) for _, _, p in frames]
    opcodes = [op for _, op, _ in frames]
    fins = [fin for fin, _, _ in frames]

    # (a) it WAS fragmented. This is the leg a single-frame emulator fails.
    minimum_frames = math.ceil(len(large) / _FRAME_QUOTA_BYTES)
    assert len(frames) >= 2, (
        f"a {len(large)}-byte payload arrived as ONE frame of {sizes[0] if sizes else 0} bytes. "
        f"The 32 KB WebSocket frame quota is not adjustable, so a message this size must be split "
        f"into at least {minimum_frames} frames"
    )
    assert len(frames) >= minimum_frames, (
        f"a {len(large)}-byte payload arrived as {len(frames)} frames with sizes {sizes}; at the "
        f"{_FRAME_QUOTA_BYTES}-byte frame quota it needs at least {minimum_frames}"
    )

    # (b) every frame honours the documented, non-adjustable ceiling.
    oversized = [(i, n) for i, n in enumerate(sizes) if n > _FRAME_QUOTA_BYTES]
    assert not oversized, (
        f"frames {oversized} exceed the non-adjustable {_FRAME_QUOTA_BYTES}-byte WebSocket frame "
        f"quota; all sizes were {sizes}"
    )

    # (c) the framing is standard RFC-6455 continuation framing, not N independent messages. An
    # emulator that loops PostToConnection-style single messages produces N data opcodes with
    # FIN=1 each, which a real client delivers to the application as N separate messages.
    assert opcodes[0] in (0x1, 0x2), (
        f"the FIRST frame of the fragmented message had opcode {opcodes[0]:#x}; the leading frame "
        f"of a message must carry a data opcode (0x1 text or 0x2 binary), never a continuation "
        f"(0x0) or a control opcode. Full opcode sequence: {[hex(o) for o in opcodes]}"
    )
    continuation_defects = [
        (i, hex(op)) for i, op in enumerate(opcodes) if i > 0 and op != 0x0
    ]
    assert not continuation_defects, (
        f"frames {continuation_defects} after the first do not carry the CONTINUATION opcode 0x0; "
        f"full sequence {[hex(o) for o in opcodes]}. A repeated data opcode means the payload was "
        f"delivered as several separate MESSAGES rather than one fragmented message, which is a "
        f"different thing to the receiving application"
    )
    assert fins == [False] * (len(frames) - 1) + [True], (
        f"the FIN bits were {fins}; exactly the last frame of a fragmented message sets FIN, and "
        f"every earlier one must clear it"
    )

    # (d) [not asserted] API Gateway does not split a message into frames of a uniform size, so
    # only the per-frame ceiling in (b) is asserted.

    # (e) the terminal read: the reassembled bytes are exactly what was sent. Position-encoded, so
    # the message names WHERE it first diverged rather than only that it did.
    assert len(message) == len(large), (
        f"the reassembled message is {len(message)} bytes, not the {len(large)} sent; frame sizes "
        f"{sizes} sum to {sum(sizes)}"
    )
    assert message == large, (
        f"the reassembled {len(message)}-byte message differs from the payload sent: first "
        f"differing {_WORD_BYTES}-byte word is index {_first_word_mismatch(message, large)} of "
        f"{len(large) // _WORD_BYTES}. Each word encodes its own index, so this names the chunk "
        f"that was dropped, duplicated or reordered"
    )

    # (f) exactly one message, not two. The window is 3x the latency MEASURED on this same wiring
    # for the single-frame control above, so a correct-but-slow target is not scored as duplicating.
    quiet_window = max(3.0 * small_latency, 3.0)
    extra = _ws_recv_message_or_none(sock, quiet_window)
    assert extra is None, (
        f"a second message of {len(extra)} bytes arrived within {quiet_window:.2f}s "
        f"(3x the {small_latency:.2f}s measured delivery latency) after the fragmented message was "
        f"fully reassembled; one PostToConnection must produce exactly one message"
    )


# ===== helpers (self-contained) =====

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: `$default` echoes the caller its own connection id over the socket. That is the only way a
#: WebSocket client can learn the server-minted id it needs to address itself with.
_HANDLER = """
import json
import boto3


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    cid = rc.get("connectionId")
    if route in ("$connect", "$disconnect"):
        return {"statusCode": 200}
    endpoint = "https://" + rc.get("domainName") + "/" + rc.get("stage")
    boto3.client("apigatewaymanagementapi", endpoint_url=endpoint).post_to_connection(
        ConnectionId=cid, Data=json.dumps({"connectionId": cid}).encode()
    )
    return {"statusCode": 200}
"""


class _NoFrame(Exception):
    """No WebSocket frame arrived inside the window. Purpose-built and narrow: it is only ever
    raised by the frame reader on a read timeout or a peer close, and only ever caught where the
    ABSENCE of a frame is the thing being asserted."""


#: Bytes per position-encoded word. 8-char ASCII hex, not 4 raw bytes: see `_position_encoded`.
_WORD_BYTES = 8


def _position_encoded(n: int) -> bytes:
    """`n` ASCII bytes in which every 8-byte word holds its own word index as zero-padded hex.

    A byte-exact comparison already catches any corruption; the encoding exists so the failure
    MESSAGE can name which chunk was dropped, duplicated or reordered — which is the difference
    between "the bytes differ" and "frame 7 was delivered twice".

    Every byte is ASCII (<0x80) BY CONSTRUCTION, unlike a raw big-endian word index (whose low byte
    spans the full 0-255 range and so is frequently >=0x80). That constraint is load-bearing, not
    cosmetic: PostToConnection delivers Data as a TEXT frame and relays a >0x7F byte through a
    UTF-8 decode-with-replacement round trip, inflating and corrupting the payload from the first
    such byte onward. This check's subject is frame-splitting mechanics, not byte-transparency of
    arbitrary binary Data, so the payload is constructed to be immune to that orthogonal
    behavior rather than tripping over it.
    """
    words = n // _WORD_BYTES
    body = b"".join(f"{i:0{_WORD_BYTES}x}".encode("ascii") for i in range(words))
    return body + b"." * (n - len(body))


def _first_word_mismatch(got: bytes, want: bytes) -> int:
    """The index of the first differing word, or -1 if the common prefix matches."""
    for i in range(min(len(got), len(want)) // _WORD_BYTES):
        lo, hi = i * _WORD_BYTES, i * _WORD_BYTES + _WORD_BYTES
        if got[lo:hi] != want[lo:hi]:
            return i
    return -1


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _lambda_role(ctx, account):
    """An execution role allowing ONLY execute-api:ManageConnections, cleanup registered.

    Deliberately no `logs:*`: the `/aws/lambda/<fn>` group materialises asynchronously, after
    `ctx.on_cleanup` has already run, so granting the permission leaks a log group.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-wsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["execute-api:ManageConnections"],
                        "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:*/*",
                    }
                ],
            }
        ),
    )
    return {"name": role_name, "arn": arn}


def _create_function(ctx, role_arn):
    """The `$default` integration, cleanup registered."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-wsfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)
    payload = buf.getvalue()

    def _create():
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": payload},
                Timeout=20,
                Tags=_TAGS,
            )
            return True
        except ClientError as exc:
            # A brand-new role is not yet assumable by Lambda; this bounded retry is the control.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return False
            raise

    _poll_until(_create, bool, timeout_s=120.0, interval_s=4.0,
                description=f"Lambda {name} created once its role became assumable")
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    config = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": config["FunctionArn"]}


def _deploy_websocket_api(ctx, account, fn, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    for route_key in ("$connect", "$disconnect", "$default"):
        v2.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration}")
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId=f"sim2real-behav-apigw-{api_id}",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return api_id, stage, api["ApiEndpoint"]


def _ws_target(ctx, api_endpoint, stage):
    """(use_tls, connect_host, port, Host header, path). Transport fork only: no assertion
    is guarded by it."""
    from urllib.parse import urlparse

    parsed = urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = parsed.scheme == "wss"
    port = parsed.port or (443 if use_tls else 80)
    return use_tls, parsed.hostname, port, parsed.hostname, parsed.path


def _ws_connect(ctx, api_endpoint, stage, timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket; returns (socket, status line)."""
    use_tls, host, port, http_host, path = _ws_target(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {http_host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(timeout_s)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
    return sock, (head.splitlines() or [""])[0]


def _ws_upgraded(ctx, api_endpoint, stage):
    """A socket that completed the 101 upgrade, or None while the stage is still settling (a fresh
    stage answers 403 for a few seconds; a deploy delay, not a fidelity signal)."""
    try:
        sock, status = _ws_connect(ctx, api_endpoint, stage)
    except OSError:
        return None
    if " 101 " in status:
        return sock
    sock.close()
    return None


def _ws_send_text(sock, payload):
    """One masked FIN text frame (client->server frames MUST be masked, RFC 6455 5.3)."""
    data = payload.encode()
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += n.to_bytes(2, "big")
    else:
        header.append(0x80 | 127)
        header += n.to_bytes(8, "big")
    mask = os.urandom(4)
    header += mask
    sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def _ws_recv_exact(sock, n, deadline):
    """Exactly `n` bytes before `deadline`, or `_NoFrame`."""
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _NoFrame(f"timed out after {len(buf)} of {n} expected bytes")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(n - len(buf))
        except TimeoutError as exc:  # socket.timeout is an alias of TimeoutError from 3.10
            raise _NoFrame(f"read timed out after {len(buf)} of {n} expected bytes") from exc
        if not chunk:
            raise _NoFrame(f"the peer closed the socket after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_raw_frame(sock, deadline):
    """(fin, opcode, payload) for the next frame — control frames INCLUDED.

    Unlike the reader the rest of this directory shares, this one does NOT collapse control frames
    or hide the FIN bit, because the FIN bit and the opcode sequence ARE this check's subject.
    """
    b1 = _ws_recv_exact(sock, 1, deadline)[0]
    b2 = _ws_recv_exact(sock, 1, deadline)[0]
    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    n = b2 & 0x7F
    if n == 126:
        n = int.from_bytes(_ws_recv_exact(sock, 2, deadline), "big")
    elif n == 127:
        n = int.from_bytes(_ws_recv_exact(sock, 8, deadline), "big")
    mask = _ws_recv_exact(sock, 4, deadline) if b2 & 0x80 else None
    payload = _ws_recv_exact(sock, n, deadline) if n else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def _ws_recv_message(sock, timeout_s=60.0):
    """(message_frames, reassembled_bytes) for one complete message.

    `message_frames` is the list of (fin, opcode, payload) DATA frames in arrival order. Control
    frames are answered where required and excluded from the list: RFC 6455 5.4 permits a ping to
    be interleaved between continuation frames, and counting one as a message frame would turn a
    conforming server into a failure.
    """
    deadline = time.monotonic() + timeout_s
    frames = []
    while True:
        fin, opcode, payload = _ws_recv_raw_frame(sock, deadline)
        if opcode == 0x9:  # ping -> pong, then keep reading the same message
            _ws_send_pong(sock, payload)
            continue
        if opcode == 0xA:  # pong
            continue
        if opcode == 0x8:  # close
            code = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
            raise AssertionError(
                f"the server closed the socket with code {code!r} and reason "
                f"{payload[2:][:120]!r} while a message was being read; "
                f"{len(frames)} data frames had arrived with sizes {[len(p) for _, _, p in frames]}"
            )
        frames.append((fin, opcode, payload))
        if fin:
            return frames, b"".join(p for _, _, p in frames)


def _ws_recv_message_or_none(sock, timeout_s):
    """The next message's bytes, or None if none arrived in the window.

    Used ONLY where an absence is the assertion, and only after a positive control on the same
    socket established the delivery latency the window is derived from.
    """
    try:
        _frames, message = _ws_recv_message(sock, timeout_s=timeout_s)
    except _NoFrame:
        return None
    return message


def _ws_send_pong(sock, payload):
    header = bytearray([0x8A])
    header.append(0x80 | len(payload))
    mask = os.urandom(4)
    header += mask
    sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _ws_close(sock):
    """Send a masked CLOSE frame and close the TCP socket. Idempotent."""
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _management_client(ctx, api_endpoint, stage):
    """The @connections client. The endpoint is PER-API, which is why `ctx.client` is handed an
    explicit `endpoint_url` — the service's own model documentation requires the caller to set it."""
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _open_and_identify(ctx, api_id, stage, api_endpoint):
    """A live socket plus the server-minted connection id it was given, learned off the socket."""
    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, stage),
        lambda s: s is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"a 101 WebSocket upgrade against API {api_id} stage {stage}",
    )
    ctx.on_cleanup(lambda: _ws_close(sock))
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    _frames, payload = _ws_recv_message(sock, timeout_s=90.0)
    connection_id = json.loads(payload)["connectionId"]
    assert connection_id, f"the $default route echoed no connection id: {payload[:120]!r}"
    return sock, connection_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
