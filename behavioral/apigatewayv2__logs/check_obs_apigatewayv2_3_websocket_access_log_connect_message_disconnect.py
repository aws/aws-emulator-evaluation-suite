"""obs-apigatewayv2-3-websocket-access-log-connect-message-disconnect."""

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

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigatewayv2-3-websocket-access-log-connect-message-disconnect"

GROUP = "observability"

SERVICES = ["apigatewayv2", "logs"]

#: One integration behind $connect / $default / $disconnect. Every invocation prints one JSON line
#: (the integration's own view of the connection), and $default answers two-way with the connection
#: id it saw, so the client becomes a third independent observer of that id.
_HANDLER = """
import json
import os


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    qs = event.get("queryStringParameters") or {}
    marker = os.environ["MARKER"]
    print(json.dumps({
        "marker": marker,
        "routeKey": rc.get("routeKey"),
        "eventType": rc.get("eventType"),
        "connectionId": rc.get("connectionId"),
        "deny": "deny" in qs,
    }))
    if rc.get("routeKey") == "$connect" and "deny" in qs:
        return {"statusCode": 403}
    if rc.get("routeKey") == "$default":
        return {
            "statusCode": 200,
            "body": json.dumps({"connectionId": rc.get("connectionId"), "marker": marker}),
        }
    return {"statusCode": 200}
"""

_STAGE = "live"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A WebSocket stage's access log holds exactly three records for one connection (CONNECT, MESSAGE, DISCONNECT
    on $connect, $default, $disconnect) with distinct request ids, a messageId only on MESSAGE, the connection id
    the integrations saw, and no unexpanded ``$context`` token; the account's CloudWatch role is restored."""
    marker = ctx.unique_name("sim2real-xsvc-wslog-")
    account = _account_id(ctx)

    log_group = f"/sim2real/xsvc/{_xname(ctx, 'wsaccess')}"
    ctx.on_cleanup(lambda: _reap_log_group(ctx, log_group))
    ctx.client("logs").create_log_group(logGroupName=log_group, tags=_xsvc_resource_tags())
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{log_group}"

    _set_account_cloudwatch_role(ctx)

    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    api_id, api_endpoint = _websocket_api(ctx, fn, account)
    log_format = json.dumps(
        {
            "marker": marker,
            "requestId": "$context.requestId",
            "connectionId": "$context.connectionId",
            "eventType": "$context.eventType",
            "routeKey": "$context.routeKey",
            "messageId": "$context.messageId",
            "status": "$context.status",
            "requestTimeEpoch": "$context.requestTimeEpoch",
        }
    )
    _create_logged_stage(ctx, api_id, log_group_arn, log_format)

    stored = ctx.client("apigatewayv2").get_stage(ApiId=api_id, StageName=_STAGE)
    settings = stored.get("AccessLogSettings") or {}
    assert log_group in (settings.get("DestinationArn") or ""), (
        f"the stage must carry the access log destination {log_group!r}; GetStage reports "
        f"{settings!r}"
    )
    assert settings.get("Format") == log_format, (
        f"the stage must store the authored format verbatim; GetStage reports "
        f"{settings.get('Format')!r}"
    )

    warm_ids = _await_log_delivery(ctx, api_endpoint, log_group, marker)

    # One connection: connect, one frame, disconnect.
    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, _STAGE),
        lambda s: s is not None,
        timeout_s=150.0,
        interval_s=5.0,
        description=f"a 101 WebSocket upgrade against stage {_STAGE}",
    )
    ctx.on_cleanup(lambda: _ws_close(sock))
    _ws_send_text(sock, json.dumps({"action": "hello", "marker": marker}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x1, f"the $default reply must be a text frame, got {opcode:#x} {payload!r}"
    reply = json.loads(payload)
    assert reply.get("marker") == marker, (
        f"the reply must come from this check's integration (marker {marker!r}), got {reply!r}"
    )
    connection_id = reply.get("connectionId")
    assert connection_id, f"the $default integration handed back no connection id: {reply!r}"
    assert connection_id not in warm_ids, (
        f"the measured connection must have a fresh id, distinct from the warm-up ids {warm_ids!r}"
    )
    _ws_close_and_wait(sock)

    # Observer 2: the $connect integration's own event.
    lambda_log = f"/aws/lambda/{fn['name']}"
    seen = _poll_until(
        lambda: _json_lines(ctx, lambda_log, marker),
        lambda rs: any(r.get("routeKey") == "$connect" and r.get("connectionId") == connection_id
                       for r in rs),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"the $connect integration's log line for connection {connection_id}",
    )
    connect_seen = [r for r in seen if r.get("routeKey") == "$connect"
                    and r.get("connectionId") == connection_id]
    assert connect_seen[0].get("eventType") == "CONNECT", (
        f"the $connect integration must see eventType CONNECT, got {connect_seen[0]!r}"
    )

    # Observer 3: the access log.
    records = _poll_until(
        lambda: _json_lines(ctx, log_group, marker, keep_raw=True),
        lambda rs: {"CONNECT", "MESSAGE", "DISCONNECT"}.issubset(
            {r.get("eventType") for r in rs if r.get("connectionId") == connection_id}
        ),
        timeout_s=240.0,
        interval_s=5.0,
        description=(
            f"CONNECT, MESSAGE and DISCONNECT access log records in {log_group} for connection "
            f"{connection_id}"
        ),
    )
    for r in records:
        assert "$context" not in r["_raw"], (
            f"an access log record must have every $context variable expanded, got {r['_raw']!r}"
        )
    mine = [r for r in records if r.get("connectionId") == connection_id]
    assert len(mine) == 3, (
        f"one connect + one frame + one disconnect must produce EXACTLY three access log records "
        f"for connection {connection_id}, got {len(mine)}: {[r['_raw'] for r in mine]!r}"
    )
    mine.sort(key=lambda r: int(r.get("requestTimeEpoch")))
    assert [r.get("eventType") for r in mine] == ["CONNECT", "MESSAGE", "DISCONNECT"], (
        f"by request time the records must be CONNECT, MESSAGE, DISCONNECT, got "
        f"{[(r.get('eventType'), r.get('requestTimeEpoch')) for r in mine]!r}"
    )
    assert [r.get("routeKey") for r in mine] == ["$connect", "$default", "$disconnect"], (
        f"the records' route keys must be $connect, $default, $disconnect, got "
        f"{[r.get('routeKey') for r in mine]!r}"
    )
    assert len({r.get("requestId") for r in mine}) == 3, (
        f"each connection event is its own request and must carry its own requestId, got "
        f"{[r.get('requestId') for r in mine]!r}"
    )
    assert [r.get("status") for r in mine] == ["200", "200", "200"], (
        f"every event of this connection succeeded, so each record's status must be 200, got "
        f"{[r.get('status') for r in mine]!r}"
    )
    message_ids = [r.get("messageId") for r in mine]
    assert message_ids[1] not in (None, "", "-"), (
        f"the MESSAGE record must carry the frame's messageId, got {message_ids!r}"
    )
    assert message_ids[0] == "-" and message_ids[2] == "-", (
        f"CONNECT and DISCONNECT carry no message, so their messageId must log as '-', got "
        f"{message_ids!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_PUSH_TO_CWL = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _set_account_cloudwatch_role(ctx):
    """Point the API Gateway account's cloudwatchRoleArn at a role this check owns, restoring the
    original value (possibly unset) on cleanup. The restore is registered after the role, so LIFO
    restores the account BEFORE the role it points at is deleted."""
    apigw = ctx.client("apigateway")
    original = apigw.get_account().get("cloudwatchRoleArn") or ""
    role_arn = _create_role(ctx, "apigateway.amazonaws.com")
    ctx.client("iam").attach_role_policy(RoleName=role_arn.split("/")[-1], PolicyArn=_PUSH_TO_CWL)

    def _restore():
        ctx.client("apigateway").update_account(
            patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original}]
        )

    ctx.on_cleanup(_restore)

    def _try():
        """True once UpdateAccount accepts the role; False on the propagation BadRequestException."""
        try:
            apigw.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise  # any other refusal is a real failure, not propagation
            return False
        return True

    _poll_until(
        _try,
        bool,
        timeout_s=120.0,
        interval_s=5.0,
        description="UpdateAccount accepting a freshly created (propagating) CloudWatch role",
    )
    got = apigw.get_account().get("cloudwatchRoleArn")
    assert got == role_arn, f"the account must now carry role {role_arn!r}, got {got!r}"


def _websocket_api(ctx, fn, account):
    """A WebSocket API with $connect/$disconnect and a two-way $default, all on one Lambda."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "wsapi-accesslog"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_xsvc_resource_tags(),
    )
    api_id = api["ApiId"]
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
    for route_key in ("$connect", "$disconnect"):
        agw.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration_id}")
    default_id = agw.create_route(
        ApiId=api_id,
        RouteKey="$default",
        Target=f"integrations/{integration_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    agw.create_route_response(ApiId=api_id, RouteId=default_id, RouteResponseKey="$default")
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
        statement_id=f"apigw-invoke-{api_id}",
    )
    return api_id, api["ApiEndpoint"]


def _create_logged_stage(ctx, api_id, log_group_arn, log_format):
    """CreateStage with AccessLogSettings, retried ONLY on the account-role BadRequestException
    while the just-set cloudwatchRoleArn propagates."""
    agw = ctx.client("apigatewayv2")

    def _try():
        """True once CreateStage succeeds; False on the account-role BadRequestException."""
        try:
            agw.create_stage(
                ApiId=api_id,
                StageName=_STAGE,
                AutoDeploy=True,
                AccessLogSettings={"DestinationArn": log_group_arn, "Format": log_format},
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "BadRequestException" and "role" in err.get("Message", "").lower()
            ):
                raise  # any other refusal is a real failure, not propagation
            return False
        return True

    _poll_until(
        _try,
        bool,
        timeout_s=120.0,
        interval_s=5.0,
        description="CreateStage with AccessLogSettings once the account CloudWatch role applies",
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )


def _json_lines(ctx, log_group, marker, keep_raw=False):
    """Every JSON line in log_group containing `marker`, parsed; a line that is not JSON is kept
    as {"_raw": ...} so a target that writes a malformed record fails an assertion rather than
    being dropped. A missing group means nothing delivered yet."""
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, limit=200
        ):
            for event in page.get("events", []):
                message = event.get("message", "")
                if marker not in message:
                    continue
                start = message.find("{")
                try:
                    parsed = json.loads(message[start:]) if start >= 0 else {}
                except ValueError:
                    parsed = {}
                if keep_raw:
                    parsed["_raw"] = message
                out.append(parsed)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


def _await_log_delivery(ctx, api_endpoint, log_group, marker, timeout_s=240.0):
    """Warm-up on an OBSERVABLE condition: open throwaway connections (connect, one frame, close)
    until one of them has its CONNECT record delivered to the access log group. Access log
    delivery for a freshly configured stage can take from seconds to several minutes to start,
    so the measured connection only starts once delivery is proven live.
    Returns the warm-up connection ids (excluded from every later assertion by id)."""
    deadline = time.monotonic() + timeout_s
    warm_ids = []
    while time.monotonic() < deadline:
        sock = _ws_upgraded(ctx, api_endpoint, _STAGE)
        if sock is None:
            time.sleep(5.0)
            continue
        try:
            _ws_send_text(sock, json.dumps({"action": "warmup", "marker": marker}))
            frame = _ws_try_recv_frame(sock, timeout_s=30.0)
            if frame is None or frame[0] != 0x1:
                continue  # a just-deployed stage can upgrade before its routes answer: retry
            warm_ids.append(json.loads(frame[1]).get("connectionId"))
        finally:  # a warm-up's own close handshake is not under test: close without waiting
            _ws_close(sock)
        window = time.monotonic() + 30.0
        while time.monotonic() < min(window, deadline):
            ids = {r.get("connectionId") for r in _json_lines(ctx, log_group, marker)}
            if ids & set(warm_ids):
                return warm_ids
            time.sleep(5.0)
    raise AssertionError(
        f"access log delivery to {log_group} never became live within {timeout_s}s: none of the "
        f"{len(warm_ids)} warm-up connections {warm_ids!r} produced a record"
    )


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


def _ws_target(ctx, api_endpoint, stage):
    """(use_tls, connect_host, port, Host header, path), from ``ctx.stage_url``."""
    from urllib.parse import urlsplit

    url = urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _ws_connect(ctx, api_endpoint, stage, query="", timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket; returns (socket, status line)."""
    use_tls, host, port, http_host, path = _ws_target(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
    request = (
        f"GET {path}{query} HTTP/1.1\r\n"
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


def _ws_close_and_wait(sock):
    """Client-initiated close handshake: send a masked CLOSE (1000) and wait for the server's
    CLOSE, so the disconnect is a completed protocol event rather than a dropped TCP stream."""
    mask = os.urandom(4)
    code = (1000).to_bytes(2, "big")
    sock.sendall(b"\x88\x82" + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(code)))
    opcode, payload = _ws_recv_frame(sock, timeout_s=30.0)
    assert opcode == 0x8, (
        f"the server must answer a client CLOSE with a CLOSE frame, got opcode {opcode:#x} "
        f"{payload[:120]!r}"
    )
    sock.close()


def _ws_close(sock):
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _reap_log_group(ctx, name, settle_s=30.0):
    """Delete a log group in a LOOP: a buffered stream can flush after the delete and recreate the
    group. Re-delete across the settle window; raise rather than hang if it never converges."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + settle_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
    if any(g.get("logGroupName") == name for g in groups):
        raise RuntimeError(f"log group {name} reappeared after repeated deletes")


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
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
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
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. The /aws/lambda/<name> reap is registered
    BEFORE the function, so LIFO runs it after the delete."""
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
    name = _xname(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
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
        "Tags": dict(_xsvc_resource_tags()),
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
