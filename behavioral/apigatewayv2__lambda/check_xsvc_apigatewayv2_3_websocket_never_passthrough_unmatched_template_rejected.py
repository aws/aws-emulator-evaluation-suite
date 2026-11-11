"""xsvc-apigatewayv2-3-websocket-never-passthrough-unmatched-template-rejected."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigatewayv2-3-websocket-never-passthrough-unmatched-template-rejected"

GROUP = "websocket"

SERVICES = ["apigatewayv2", "lambda"]

_HANDLER = """
def handler(event, context):
    return {"received": event}
"""

_TEMPLATE = (
    '{"marker":"%s","echo":$input.json(\'$.payload\'),"routeKey":"$context.routeKey",'
    '"connectionId":"$context.connectionId"}'
)


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """With PassthroughBehavior=NEVER, a WebSocket frame selecting no request template gets an
    "Internal server error" frame while a matched frame reaches the function rendered;
    WHEN_NO_MATCH then passes the unmatched frame through verbatim."""
    marker = _name(ctx, "wsnever")
    fn = _create_function(ctx, _HANDLER, env={"MARKER": marker})
    account = _account_id(ctx)

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_name(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags={"sim2real": CHECK},
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    uri = f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"

    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS",
        IntegrationMethod="POST",
        IntegrationUri=uri,
        RequestTemplates={"known": _TEMPLATE % marker},
        TemplateSelectionExpression="${request.body.kind}",
        PassthroughBehavior="NEVER",
    )["IntegrationId"]
    agw.create_integration_response(
        ApiId=api_id, IntegrationId=integration_id, IntegrationResponseKey="$default"
    )
    route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="strict",
        Target=f"integrations/{integration_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    agw.create_route_response(ApiId=api_id, RouteId=route_id, RouteResponseKey="$default")

    stage = "live"
    agw.create_stage(ApiId=api_id, StageName=stage, AutoDeploy=True)
    _allow_invoke(
        ctx, fn["name"], "apigw-ws", f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*"
    )

    sock = _poll_until(
        lambda: _try_ws_connect(ctx, api_endpoint, stage),
        lambda s: s is not None,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"WebSocket upgrade to stage {stage!r} returning 101",
    )
    ctx.on_cleanup(lambda: _ws_close(sock))

    known_msg = {"action": "strict", "kind": "known", "payload": {"n": 1}}
    frame = _exchange_until(
        sock, known_msg, lambda f: "received" in f, "a 'received' echo for kind=known"
    )
    connection_id = frame["received"].get("connectionId")
    assert isinstance(connection_id, str) and connection_id, (
        f"$context.connectionId must render to the live connection id, got {frame!r}"
    )
    expected = {
        "marker": marker,
        "echo": {"n": 1},
        "routeKey": "strict",
        "connectionId": connection_id,
    }
    assert frame["received"] == expected, (
        f"kind=known must invoke the function with the rendered 'known' template; expected "
        f"{expected!r}, got {frame['received']!r}"
    )

    unknown_msg = {"action": "strict", "kind": "unknown", "payload": {"n": 2}, "extra": marker}
    _ws_send_text(sock, json.dumps(unknown_msg))
    refused = json.loads(_ws_recv_text(sock))
    # Lowercase "server error", unlike an HTTP API's "Internal Server Error".
    assert sorted(refused) == ["connectionId", "message", "requestId"], (
        f"an unmatched template under PassthroughBehavior NEVER must be refused with an error "
        f"frame of keys [connectionId, message, requestId], got {refused!r} (a 'received' key "
        f"means the frame was passed through to the function)"
    )
    assert refused["message"] == "Internal server error", (
        f"expected the refusal message 'Internal server error', got {refused['message']!r}"
    )
    assert refused["connectionId"] == connection_id, (
        f"the refusal frame must name this connection {connection_id!r}, got "
        f"{refused['connectionId']!r}"
    )
    assert marker not in json.dumps(refused), (
        f"effect-absent: nothing of the refused frame may come back; marker {marker!r} found in "
        f"{refused!r}"
    )

    frame = _exchange_until(
        sock, known_msg, lambda f: "received" in f, "kind=known still served after the refusal"
    )
    assert frame["received"] == expected, (
        f"kind=known must keep rendering beside the refused frame; expected {expected!r}, got "
        f"{frame['received']!r}"
    )

    agw.update_integration(
        ApiId=api_id, IntegrationId=integration_id, PassthroughBehavior="WHEN_NO_MATCH"
    )
    frame = _exchange_until(
        sock,
        unknown_msg,
        lambda f: "received" in f,
        "the unmatched frame passing through once PassthroughBehavior is WHEN_NO_MATCH",
        timeout_s=150.0,
    )
    assert frame["received"] == unknown_msg, (
        f"under WHEN_NO_MATCH an unmatched frame must reach the function verbatim; expected "
        f"{unknown_msg!r}, got {frame['received']!r}"
    )


_PREFIX = "sim2real-xsvc-"


def _name(ctx, kind):
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _rejection(fn):
    """(code, message) of the ClientError fn() raises; raise if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) and return it; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _reap_log_group(ctx, fn_name):
    """Delete /aws/lambda/<fn> in a loop: a buffered stream can recreate it after a delete."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise RuntimeError(f"could not delete log group {group}: {exc}") from exc
        time.sleep(4)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g.get("logGroupName") == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after its function was deleted")


def _create_function(ctx, code, *, env, timeout_s=10):
    """A python3.12 function behind a role with no policies (so it writes no logs), retried
    through role propagation and waited to Active."""
    iam = ctx.client("iam")
    role_name = _name(ctx, "role")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "index.handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout_s,
        "MemorySize": 128,
        "Environment": {"Variables": env},
        "Tags": {"sim2real": CHECK},
    }

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None  # the brand-new role is not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"CreateFunction {name} once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_invoke(ctx, fn_name, statement_id, source_arn):
    """One resource-policy statement letting API Gateway invoke fn_name from source_arn. It is
    removed with the function, so it needs no cleanup of its own."""
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API stage."""
    url = urllib.parse.urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _try_ws_connect(ctx, api_endpoint, stage, timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket: the connected socket on 101, else None."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        if use_tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: {http_host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError as exc:  # execute-api DNS/TLS still settling
        print(f"[ws] connect to {http_host}{path} failed: {exc}")
        return None
    status_line = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    if " 101 " not in status_line:
        print(f"[ws] upgrade to {http_host}{path} not accepted yet: {status_line!r}")
        sock.close()
        return None
    return sock


def _ws_send_text(sock, payload):
    """Send one masked FIN text frame (client frames MUST be masked, RFC 6455 5.3)."""
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


def _ws_recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"WebSocket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_text(sock, timeout_s=30.0):
    """Read frames until a text frame arrives; return its payload. Control frames are skipped."""
    sock.settimeout(timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        b1, b2 = _ws_recv_exact(sock, 2)
        opcode = b1 & 0x0F
        n = b2 & 0x7F
        if n == 126:
            n = int.from_bytes(_ws_recv_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(_ws_recv_exact(sock, 8), "big")
        mask = _ws_recv_exact(sock, 4) if b2 & 0x80 else None
        payload = _ws_recv_exact(sock, n) if n else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x1:
            return payload.decode("utf-8", "replace")
        if opcode == 0x8:
            raise AssertionError(f"WebSocket server sent CLOSE instead of a text frame: {payload!r}")
    raise AssertionError(f"no WebSocket text frame within {timeout_s}s")


def _exchange_until(sock, message, predicate, description, timeout_s=90.0):
    """Send `message` and read the reply until predicate(frame); raise on timeout.

    Retrying covers AutoDeploy propagation, when a not-yet-deployed route answers 'Forbidden'."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        _ws_send_text(sock, json.dumps(message))
        text = _ws_recv_text(sock)
        try:
            last = json.loads(text)
        except ValueError:
            last = {"_unparsed": text}
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not received within {timeout_s}s; last frame {last!r}")
        time.sleep(3.0)


def _ws_close(sock):
    """Masked empty CLOSE frame, then close the socket."""
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
