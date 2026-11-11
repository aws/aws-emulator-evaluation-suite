"""websocket-connect-mock-integration-rejected."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-connect-mock-integration-rejected"
GROUP = "websocket-dataplane"
SERVICES = ["apigatewayv2"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_STAGE = "s"


@tags(
    "axis:rejection",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A MOCK integration on a WebSocket API's $connect route fails the handshake with 500, while
    a Lambda-backed $connect upgrades (101) and the same MOCK integration serves an ordinary route.
    """
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    # A fully-templated MOCK integration (request template, response key and response template).
    mock_integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="MOCK",
        RequestTemplates={"$default": '{"statusCode": 200}'},
        TemplateSelectionExpression="\\$default",
    )["IntegrationId"]
    agw.create_integration_response(
        ApiId=api_id,
        IntegrationId=mock_integ_id,
        IntegrationResponseKey="$default",
        ResponseTemplates={"$default": ""},
        TemplateSelectionExpression="\\$default",
    )
    agw.create_route(ApiId=api_id, RouteKey="$connect", Target=f"integrations/{mock_integ_id}")

    # A positive control for MOCK itself: the SAME mock integration, bound to an ordinary route.
    agw.create_route(
        ApiId=api_id,
        RouteKey="whoami",
        Target=f"integrations/{mock_integ_id}",
        RouteResponseSelectionExpression="$default",
    )
    agw.create_route_response(
        ApiId=api_id,
        RouteId=[r["RouteId"] for r in agw.get_routes(ApiId=api_id)["Items"]
                 if r["RouteKey"] == "whoami"][0],
        RouteResponseKey="$default",
    )

    agw.create_stage(ApiId=api_id, StageName=_STAGE, Tags=_TAGS)
    dep = agw.create_deployment(ApiId=api_id, StageName=_STAGE)
    _poll_until(
        lambda: agw.get_deployment(ApiId=api_id, DeploymentId=dep["DeploymentId"]),
        lambda d: d.get("DeploymentStatus") != "PENDING",
        timeout_s=60.0, description="the WebSocket deployment to leave PENDING",
    )
    assert agw.get_deployment(ApiId=api_id, DeploymentId=dep["DeploymentId"]).get(
        "DeploymentStatus") == "DEPLOYED", "the WebSocket deployment must reach DEPLOYED"

    url = ctx.stage_url(api["ApiEndpoint"], _STAGE)

    # The negative: $connect bound to MOCK must fail the handshake with 500, not upgrade.
    result = _poll_until(
        lambda: _ws_connect(url),
        lambda r: r["status"] is not None,
        timeout_s=90.0, interval_s=3.0,
        description=f"a definite (non-transient) handshake outcome at {url}",
    )
    assert result["status"] == 500, (
        f"a $connect route bound to a MOCK integration must fail the handshake with 500 on real "
        f"AWS, got status {result['status']!r} ({result.get('head', result.get('error'))!r})"
    )

    # Rebuild the API with $connect bound to a real Lambda instead: the SAME account, region and
    # client must now upgrade cleanly, isolating the 500 above to the ($connect, MOCK) pairing.
    role_arn = _create_lambda_role(ctx)
    log_groups: list = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, log_groups))
    connect_fn = _create_lambda(ctx, role_arn, _ACCEPT_HANDLER, log_groups)
    account = ctx.client("sts").get_caller_identity()["Account"]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*"
    ctx.client("lambda").add_permission(
        FunctionName=connect_fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )
    lambda_integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=connect_fn["arn"],
        IntegrationMethod="POST",
    )["IntegrationId"]
    connect_route_id = [r["RouteId"] for r in agw.get_routes(ApiId=api_id)["Items"]
                         if r["RouteKey"] == "$connect"][0]
    agw.update_route(ApiId=api_id, RouteId=connect_route_id, Target=f"integrations/{lambda_integ_id}")
    dep2 = agw.create_deployment(ApiId=api_id, StageName=_STAGE)
    _poll_until(
        lambda: agw.get_deployment(ApiId=api_id, DeploymentId=dep2["DeploymentId"]),
        lambda d: d.get("DeploymentStatus") == "DEPLOYED",
        timeout_s=60.0, description="the re-deployment (Lambda $connect) to reach DEPLOYED",
    )
    # A manually-created stage stays pinned to the deployment it was created with; it does NOT
    # follow a later create_deployment on its own, so the stage must be re-pointed explicitly.
    agw.update_stage(ApiId=api_id, StageName=_STAGE, DeploymentId=dep2["DeploymentId"])

    conn = _poll_until(
        lambda: _ws_connect(url),
        lambda r: r["status"] == 101,
        timeout_s=90.0, interval_s=3.0,
        description=f"a 101 upgrade at {url} once the Lambda-backed $connect redeploy propagates",
    )
    assert conn["status"] == 101, (
        f"a $connect route bound to a real Lambda must upgrade (101), got {conn['status']!r} -- "
        f"otherwise the 500 above would not be specific to MOCK on $connect"
    )
    sock = conn["sock"]
    ctx.on_cleanup(lambda: _quiet_close(sock))
    buf = [conn["rest"]]

    # Second positive control: the SAME mock integration still answers correctly on "whoami".
    _ws_send(sock, json.dumps({"action": "whoami"}))
    op, payload = _ws_recv(sock, buf)
    assert op == 1, f"the whoami MOCK route must reply with a text frame, got opcode {op}"

    _ws_send(sock, struct.pack(">H", 1000), opcode=8)
    op, _ = _ws_recv(sock, buf)
    assert op == 8, f"the server must answer a close frame with a close frame, got opcode {op}"
    _quiet_close(sock)


_ACCEPT_HANDLER = """
def lambda_handler(event, context):
    return {"statusCode": 200}
"""


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


def _quiet_close(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _ws_connect(url: str) -> dict:
    """Open a WebSocket (RFC 6455 handshake). Returns {status, sock, rest}; a non-101 closes the
    socket and is returned as a RESULT so the caller can poll while the stage settles."""
    u = urllib.parse.urlparse(url)
    tls = u.scheme == "wss"
    port = u.port or (443 if tls else 80)
    try:
        raw = socket.create_connection((u.hostname, port), timeout=15)
    except OSError as exc:
        return {"status": None, "error": str(exc)}
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) if tls else raw
    key = base64.b64encode(os.urandom(16)).decode()
    host = u.netloc
    sock.sendall(
        (f"GET {u.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
         f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
    )
    data = b""
    sock.settimeout(15)
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        return {"status": None, "error": str(exc)}
    head, _, rest = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    if status != 101:
        _quiet_close(sock)
        return {"status": status, "head": head[:300]}
    sock.settimeout(20)
    return {"status": 101, "sock": sock, "rest": rest}


def _ws_send(sock, data, opcode: int = 1) -> None:
    """Send one FIN frame, client-masked as RFC 6455 requires."""
    payload = data.encode() if isinstance(data, str) else data
    mask = os.urandom(4)
    n = len(payload)
    header = bytes([0x80 | opcode])
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _ws_read(sock, buf, n: int) -> bytes:
    while len(buf[0]) < n:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("the WebSocket closed while a frame was being read")
        buf[0] += chunk
    out, buf[0] = buf[0][:n], buf[0][n:]
    return out


def _ws_recv(sock, buf):
    """Read the next complete message, aggregating continuation frames until FIN, or a close
    frame: (opcode, payload). Pings are answered and skipped. A multi-frame response (AWS
    fragments a reply larger than one frame) must be reassembled, or only the first fragment is
    seen."""
    parts = []
    first_opcode = None
    while True:
        b1, b2 = _ws_read(sock, buf, 2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", _ws_read(sock, buf, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", _ws_read(sock, buf, 8))[0]
        mask = _ws_read(sock, buf, 4) if b2 & 0x80 else None
        payload = _ws_read(sock, buf, n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        if opcode == 9:  # ping -> pong
            _ws_send(sock, payload, opcode=10)
            continue
        if opcode == 10:
            continue
        if opcode == 8:
            return 8, payload
        if first_opcode is None:
            first_opcode = opcode
        parts.append(payload)
        if fin:
            return first_opcode, b"".join(parts)


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=_TAGS_KV,
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": "arn:aws:logs:*:*:*"}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))

    def _cleanup_role():
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return arn


def _reap_log_groups(ctx, names):
    """Delete each /aws/lambda/<fn> group until it stays absent for 20s (bounded at 60s).
    delete_function leaves the group, and a buffered log flush can recreate it after a delete."""
    _leaks: list = []
    logs = ctx.client("logs")
    groups = [f"/aws/lambda/{n}" for n in names]
    absent_since = {g: None for g in groups}
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        for g in groups:
            try:
                logs.delete_log_group(logGroupName=g)
                absent_since[g] = None
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                if absent_since[g] is None:
                    absent_since[g] = now
        if all(t is not None and now - t >= 20.0 for t in absent_since.values()):
            if _leaks:
                raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                    (e for _, e in _leaks if e is not None), None
                )
            return
        time.sleep(2.0)
    for g, t in absent_since.items():
        if t is None or time.monotonic() - t < 20.0:
            _leaks.append((f"log group {g} kept reappearing after delete", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _create_lambda(ctx, role_arn, handler_code, log_groups, env=None, timeout=30):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait for Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    log_groups.append(name)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role_arn,
        "Handler": "lambda_function.lambda_handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout, "MemorySize": 128, "Tags": dict(_TAGS),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    created = _poll_until(
        _try_create, lambda r: r is not None, timeout_s=120.0, interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0, interval_s=2.0, description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
