"""websocket-two-way-route-needs-a-route-response-to-reach-the-client."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-two-way-route-needs-a-route-response-to-reach-the-client"

GROUP = "websocket-dataplane"

SERVICES = ["apigatewayv2"]

#: One integration behind every route. `$default` posts the caller its own connection id back
#: out-of-band (the only way a raw client learns the server-minted id, and the positive control for
#: socket delivery); `echo` returns a normal integration response, which only reaches the client if
#: a route response exists.
_HANDLER = """
import json
import os

import boto3


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    marker = os.environ["MARKER"]
    if route in ("$connect", "$disconnect"):
        return {"statusCode": 200}
    if route == "echo":
        body = json.loads(event.get("body") or "{}")
        print("ECHO seq=" + str(body.get("seq")) + " " + marker)
        return {
            "statusCode": 200,
            "body": json.dumps({"echo": marker, "seq": body.get("seq")}),
        }
    endpoint = "https://" + rc.get("domainName") + "/" + rc.get("stage")
    boto3.client("apigatewaymanagementapi", endpoint_url=endpoint).post_to_connection(
        ConnectionId=rc.get("connectionId"),
        Data=json.dumps({"connectionId": rc.get("connectionId"), "marker": marker}).encode(),
    )
    return {"statusCode": 200}
"""

_STAGE = "dev"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WebSocket route's integration response reaches the client only once a route response
    exists: declared two-way but with no RouteResponse, the integration runs yet the client's
    socket stays silent; after CreateRouteResponse the identical message arrives as a text frame.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-integration-responses.html
    """
    marker = ctx.unique_name("sim2real-behav-ws-")
    account = _account_id(ctx)
    fn = _create_lambda(
        ctx,
        _HANDLER,
        env={"MARKER": marker},
        permissions=[
            {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:*/*",
            }
        ],
    )
    log_group = f"/aws/lambda/{fn['name']}"

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "wsapi-routeresp"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    for route_key in ("$connect", "$disconnect", "$default"):
        agw.create_route(
            ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration_id}"
        )
    # Declared two-way from the start, so the ONLY thing missing for the first leg is the route
    # response resource itself.
    echo_route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="echo",
        Target=f"integrations/{integration_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
        statement_id=f"apigw-invoke-{api_id}",
    )
    agw.create_stage(ApiId=api_id, StageName=_STAGE, AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )

    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, _STAGE),
        lambda s: s is not None,
        timeout_s=150.0,
        interval_s=5.0,
        description=f"a 101 WebSocket upgrade against stage {_STAGE}",
    )
    ctx.on_cleanup(lambda: _ws_close(sock))

    # Beat 1 — positive control on this exact socket: an out-of-band PostToConnection issued by the
    # $default integration arrives, and its round trip is the latency the silence window is scaled
    # from. This also hands the client its connection id.
    started = time.monotonic()
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=90.0)
    latency_s = max(time.monotonic() - started, 0.5)
    assert opcode == 0x1, (
        f"the positive control must arrive as a text frame, got opcode {opcode:#x} with "
        f"{payload[:120]!r}"
    )
    hello = json.loads(payload)
    assert hello.get("marker") == marker, (
        f"the control frame must come from this check's integration (marker {marker!r}), got "
        f"{hello!r}"
    )
    connection_id = hello.get("connectionId")
    assert connection_id, f"the $default route echoed no connection id: {payload!r}"

    stored = agw.get_route(ApiId=api_id, RouteId=echo_route_id)
    assert stored.get("RouteResponseSelectionExpression") == "$default", (
        f"the echo route must be declared two-way before the negative leg means anything; GetRoute "
        f"reports RouteResponseSelectionExpression "
        f"{stored.get('RouteResponseSelectionExpression')!r}"
    )
    existing = agw.get_route_responses(ApiId=api_id, RouteId=echo_route_id).get("Items") or []
    assert not existing, (
        f"the echo route must start with NO route response for the negative leg to be about the "
        f"route response; GetRouteResponses returned {existing!r}"
    )

    # Beat 2/3 — break exactly one thing (no route response) and assert the ABSENCE at the client,
    # while proving the integration ran.
    _ws_send_text(sock, json.dumps({"action": "echo", "seq": "no-response"}))
    _ws_expect_silence(
        sock,
        window_s=min(max(3.0 * latency_s, 10.0), 40.0),
        latency_s=latency_s,
        because=(
            "a two-way route with no RouteResponse must not pass the integration's response back "
            "to the sender"
        ),
    )
    _poll_until(
        lambda: _log_events_containing(ctx, log_group, f"ECHO seq=no-response {marker}"),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=5.0,
        description=(
            "the echo integration's own log line for the un-responded message (the silence must be "
            "the route response gate, NOT a message that was never routed)"
        ),
    )

    # Beat 4 — restore: create the route response and demand the identical message now answers.
    agw.create_route_response(
        ApiId=api_id, RouteId=echo_route_id, RouteResponseKey="$default"
    )
    responses = agw.get_route_responses(ApiId=api_id, RouteId=echo_route_id).get("Items") or []
    assert [r.get("RouteResponseKey") for r in responses] == ["$default"], (
        f"expected exactly one '$default' route response after CreateRouteResponse, got "
        f"{[r.get('RouteResponseKey') for r in responses]!r}"
    )

    def _send_and_receive():
        """Send an identifiable echo message and return the first non-ping frame, or None.

        Each attempt carries its own seq so a frame can be attributed to the attempt that caused
        it; the retry exists because the route response reaches a live stage asynchronously.
        """
        seq = f"resp-{int(time.monotonic() * 1000)}"
        _ws_send_text(sock, json.dumps({"action": "echo", "seq": seq}))
        frame = _ws_try_recv_frame(sock, timeout_s=8.0)
        return None if frame is None else (seq, frame)

    seq, (opcode, delivered) = _poll_until(
        _send_and_receive,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=2.0,
        description=(
            "the echo route's integration response arriving on the socket once a $default route "
            "response exists"
        ),
    )
    assert opcode == 0x1, (
        f"the integration response must arrive as a text frame, got opcode {opcode:#x} with "
        f"{delivered[:120]!r}"
    )
    answered = json.loads(delivered)
    assert answered.get("echo") == marker, (
        f"the frame must carry the integration's own body (marker {marker!r}), got {answered!r}"
    )
    assert answered.get("seq") == seq, (
        f"the delivered frame must answer the message that produced it: expected seq {seq!r}, got "
        f"{answered.get('seq')!r}"
    )

    # The connection is still the same one the management API knows about, so the socket that stayed
    # silent is the socket that later answered.
    described = _management_client(ctx, api_endpoint, _STAGE).get_connection(
        ConnectionId=connection_id
    )
    assert described.get("ConnectedAt") is not None, (
        f"GetConnection on the still-open connection {connection_id} returned no ConnectedAt: "
        f"{described!r}"
    )


# ===== plumbing =====


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _log_events_containing(ctx, log_group, needle):
    """Every message in log_group containing `needle`. A missing group means "no events" — the
    group is created by Lambda on first write and may not exist yet."""
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, limit=100
        ):
            for event in page.get("events", []):
                if needle in event.get("message", ""):
                    out.append(event["message"])
            if out:
                break
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


def _ws_target(ctx, api_endpoint, stage):
    """(use_tls, connect_host, port, Host header, path)."""
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
    """A socket that completed the 101 upgrade, or None while the stage is still settling."""
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


def _ws_recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"the socket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_frame(sock, timeout_s=60.0):
    """(opcode, payload) for the next non-ping frame. RAISES if none arrives in time."""
    frame = _ws_try_recv_frame(sock, timeout_s=timeout_s)
    if frame is None:
        raise AssertionError(f"no WebSocket frame within {timeout_s}s")
    return frame


def _ws_try_recv_frame(sock, timeout_s=8.0):
    """(opcode, payload) for the next non-ping frame, or None if the window expires quietly."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            b1 = _ws_recv_exact(sock, 1)[0]
            b2 = _ws_recv_exact(sock, 1)[0]
        except TimeoutError:  # socket.timeout is TimeoutError on Python >= 3.10
            return None
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
        if opcode == 0x9:  # ping: keepalive, not a delivery
            continue
        return opcode, payload


def _ws_expect_silence(sock, *, window_s, latency_s, because):
    """Assert NO data frame arrives for a whole window, scaled to a measured delivery latency.

    Sampled in short slices so a target that answers immediately fails at once rather than after
    the whole window, and so a CLOSE frame is reported as itself instead of as silence.
    """
    deadline = time.monotonic() + window_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        frame = _ws_try_recv_frame(sock, timeout_s=min(2.0, remaining))
        if frame is None:
            continue
        opcode, payload = frame
        raise AssertionError(
            f"{because}: a frame arrived within the {window_s:.1f}s window (calibrated from a "
            f"measured socket delivery latency of {latency_s:.2f}s) — opcode {opcode:#x}, payload "
            f"{payload[:200]!r}"
        )


def _ws_close(sock):
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _management_client(ctx, api_endpoint, stage):
    """The per-API @connections endpoint."""
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. Teardown registered for role, function and the
    auto-created /aws/lambda/<name> log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
