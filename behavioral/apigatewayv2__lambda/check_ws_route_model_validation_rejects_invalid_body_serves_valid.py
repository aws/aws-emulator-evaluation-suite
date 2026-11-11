"""ws-route-model-validation-rejects-invalid-body-serves-valid."""

from __future__ import annotations

import base64
import hashlib
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

CHECK = "ws-route-model-validation-rejects-invalid-body-serves-valid"

GROUP = "websocket-request-validation"

SERVICES = ["apigatewayv2", "lambda"]

#: Echoes what the integration itself received, so a reply carrying "routeKey"/"body" proves the
#: Lambda was actually invoked (as opposed to the gateway answering on its own behalf).
_HANDLER = """
import json


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "routeKey": rc.get("routeKey"),
                "connectionId": rc.get("connectionId"),
                "body": event.get("body"),
            }
        ),
    }
"""

_MODEL_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "required": ["text"],
    "properties": {"text": {"type": "string"}},
}


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WebSocket route's RequestModels + ModelSelectionExpression validates the body before the
    integration runs: a body failing the model gets the gateway's 'Invalid request body' frame and
    never reaches the Lambda; a conforming body still reaches it, on the same connection.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-request-validation.html
    """
    account = _account_id(ctx)
    api_id, api_endpoint = _create_ws_api(ctx)
    fn = _create_lambda(ctx, _HANDLER)
    model_id = ctx.client("apigatewayv2").create_model(
        ApiId=api_id,
        Name="SendMsgModel",
        ContentType="application/json",
        Schema=json.dumps(_MODEL_SCHEMA),
    )["ModelId"]
    integration_id = ctx.client("apigatewayv2").create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    route_id = ctx.client("apigatewayv2").create_route(
        ApiId=api_id,
        RouteKey="sendmsg",
        Target=f"integrations/{integration_id}",
        ModelSelectionExpression="$request.body.action",
        RequestModels={"sendmsg": "SendMsgModel"},
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    ctx.client("apigatewayv2").create_route_response(
        ApiId=api_id, RouteId=route_id, RouteResponseKey="$default"
    )
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-ws-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*",
    )
    stage = _deploy(ctx, api_id)

    stored_route = ctx.client("apigatewayv2").get_route(ApiId=api_id, RouteId=route_id)
    assert stored_route.get("RequestModels") == {"sendmsg": "SendMsgModel"} and (
        stored_route.get("ModelSelectionExpression") == "$request.body.action"
    ), (
        f"the mapping must be stored as authored before it can be enforced; GetRoute reports "
        f"RequestModels={stored_route.get('RequestModels')!r} "
        f"ModelSelectionExpression={stored_route.get('ModelSelectionExpression')!r}"
    )

    sock = _ws_open(ctx, api_endpoint, stage)
    close = _close_later(ctx, sock)
    marker = ctx.unique_name("sim2real-ws-model-")

    # Positive control BEFORE the rejection: a conforming body reaches the Lambda.
    valid_before = json.dumps({"action": "sendmsg", "text": marker + "-before"})
    got = _ws_round_trip(sock, valid_before, timeout_s=_budget_s(ctx, 45.0))
    assert got.get("routeKey") == "sendmsg" and got.get("body") == valid_before, (
        f"control: a conforming body must be validated and handed to the Lambda, which echoes "
        f"it; sent {valid_before!r}, got {got!r}"
    )
    connection_id = got.get("connectionId")
    assert connection_id, f"the Lambda's echo must carry a connectionId; got {got!r}"

    # Negative 1: the model requires "text" to be a string; send a non-string.
    wrong_type = json.dumps({"action": "sendmsg", "text": 12345})
    err1 = _ws_round_trip(sock, wrong_type, timeout_s=_budget_s(ctx, 45.0))
    assert err1.get("message") == "Invalid request body", (
        f"a body failing the model's type constraint must be refused with the gateway's "
        f"documented 'Invalid request body' frame; sent {wrong_type!r}, got {err1!r}"
    )
    assert "routeKey" not in err1 and "body" not in err1, (
        f"the refusal must come from the gateway's own validation, never from the integration; "
        f"got {err1!r}"
    )
    assert err1.get("connectionId") == connection_id, (
        f"the error frame should name this connection ({connection_id!r}); got {err1!r}"
    )
    first_request_id = err1.get("requestId")
    assert first_request_id, f"the error frame should carry a requestId; got {err1!r}"

    # Negative 2: the model requires "text"; omit it entirely.
    missing_required = json.dumps({"action": "sendmsg"})
    err2 = _ws_round_trip(sock, missing_required, timeout_s=_budget_s(ctx, 45.0))
    assert err2.get("message") == "Invalid request body", (
        f"a body missing the model's required property must be refused the same way; sent "
        f"{missing_required!r}, got {err2!r}"
    )
    assert "routeKey" not in err2 and "body" not in err2, (
        f"this refusal too must come from the gateway, never the integration; got {err2!r}"
    )
    assert err2.get("connectionId") == connection_id, (
        f"the error frame should still name this connection ({connection_id!r}); got {err2!r}"
    )
    assert err2.get("requestId") and err2.get("requestId") != first_request_id, (
        f"each refusal should carry its own requestId, not a cached one; first "
        f"{first_request_id!r}, second {err2.get('requestId')!r}"
    )

    # Positive control AFTER: the socket survived both rejections and still routes a conforming
    # body to the Lambda on the SAME connection.
    valid_after = json.dumps({"action": "sendmsg", "text": marker + "-after"})
    got = _ws_round_trip(sock, valid_after, timeout_s=_budget_s(ctx, 45.0))
    assert got.get("routeKey") == "sendmsg" and got.get("body") == valid_after, (
        f"after two rejections the same socket must still validate and route a conforming body "
        f"to the Lambda; sent {valid_after!r}, got {got!r}"
    )
    assert got.get("connectionId") == connection_id, (
        f"the rejections should not have replaced the connection; was {connection_id!r}, now "
        f"{got.get('connectionId')!r}"
    )
    close()


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _budget_s(ctx, want):
    """`want` seconds, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. Raises TimeoutError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _reap_log_group(ctx, name):
    """delete_function leaves /aws/lambda/<fn>, and a late log flush can RECREATE it after one
    delete, so the reap re-deletes until the group stays gone over a bounded window."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    quiet = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and quiet < 3:
        try:
            logs.delete_log_group(logGroupName=group)
            quiet = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            quiet += 1
        time.sleep(2)
    if quiet < 3:
        raise RuntimeError(f"log group {group} kept reappearing")


def _create_lambda(ctx, handler_code, timeout=30):
    """Create a Lambda (role scoped to logs only), retrying through IAM role propagation, then
    wait for Active. Teardown registered for role, function and its auto-created log group."""
    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        },
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
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    # Registered BEFORE the create's own teardown below so LIFO runs the reap AFTER delete.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _create_ws_api(ctx):
    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_name(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    return api_id, api_endpoint


def _deploy(ctx, api_id, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    deployment_id = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(
        ApiId=api_id, StageName=stage, DeploymentId=deployment_id, Tags=_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return stage


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API stage,
    from ``ctx.stage_url``."""
    url = urllib.parse.urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _ws_handshake(ctx, api_endpoint, stage, query=None, timeout_s=20.0):
    """An RFC 6455 opening handshake over a stdlib socket. Returns (status, head, sock):
    `sock` is the open socket on a 101 and None (already closed) on anything else."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    if query:
        path = path + "?" + urllib.parse.urlencode(query)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = _ssl_context(ctx.http_verify).wrap_socket(sock, server_hostname=http_host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {http_host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    buf = b""
    sock.settimeout(timeout_s)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
    first = head.splitlines()[0] if head else ""
    parts = first.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
    if status != 101:
        try:
            sock.close()
        except OSError:
            pass
        return status, head, None
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    got_accept = [
        ln.split(":", 1)[1].strip()
        for ln in head.splitlines()
        if ln.lower().startswith("sec-websocket-accept:")
    ]
    assert got_accept == [accept], (
        f"101 upgrade carried no valid Sec-WebSocket-Accept for our key; head was {head!r}"
    )
    return status, head, sock


def _ws_open(ctx, api_endpoint, stage, query=None):
    """A 101 handshake, polled while a freshly deployed stage settles. Returns the socket."""

    def _try():
        try:
            return _ws_handshake(ctx, api_endpoint, stage, query)
        except OSError as exc:
            return (-1, repr(exc), None)

    got = _poll_until(
        _try,
        lambda r: r[0] == 101,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=5.0,
        description=f"WebSocket 101 upgrade on stage {stage} with query {query!r}",
    )
    return got[2]


def _ws_send_text(sock, payload):
    """Send one masked FIN text frame (client->server frames MUST be masked, RFC 6455 5.3)."""
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
    """Read frames until a text frame arrives; return its payload. Control frames other than
    CLOSE are skipped; a CLOSE is an assertion failure naming its payload."""
    deadline = time.monotonic() + timeout_s
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"no WebSocket text frame within {timeout_s}s")
        sock.settimeout(left)
        try:
            b1 = _ws_recv_exact(sock, 1)[0]
        except (socket.timeout, TimeoutError):
            raise TimeoutError(f"no WebSocket text frame within {timeout_s}s") from None
        b2 = _ws_recv_exact(sock, 1)[0]
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
            raise AssertionError(
                f"WebSocket server closed the connection instead of sending a text frame "
                f"(close payload {payload!r})"
            )


def _ws_recv_json(sock, timeout_s=30.0):
    raw = _ws_recv_text(sock, timeout_s)
    try:
        return json.loads(raw)
    except ValueError:
        raise AssertionError(f"text frame was not JSON: {raw!r}") from None


def _ws_round_trip(sock, payload, timeout_s=30.0):
    _ws_send_text(sock, payload)
    return _ws_recv_json(sock, timeout_s)


def _ws_close(sock):
    """Send a masked CLOSE frame with status 1000, then close the socket — the clean
    disconnect that makes the service fire $disconnect."""
    try:
        code = (1000).to_bytes(2, "big")
        mask = os.urandom(4)
        sock.sendall(b"\x88\x82" + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(code)))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _close_later(ctx, sock):
    """Register a socket close that is a no-op if the check already closed it."""
    state = {"open": True}

    def _close():
        if state["open"]:
            state["open"] = False
            _ws_close(sock)

    ctx.on_cleanup(_close)
    return _close


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
