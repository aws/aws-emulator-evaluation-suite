"""websocket-connect-request-authorizer-token-gate."""
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

CHECK = "websocket-connect-request-authorizer-token-gate"
GROUP = "authorizers"
SERVICES = ["apigatewayv2"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_STAGE = "s"

_ACCEPT_HANDLER = """
def lambda_handler(event, context):
    return {"statusCode": 200}
"""

_AUTHORIZER_HANDLER = """
def lambda_handler(event, context):
    qs = event.get("queryStringParameters") or {}
    effect = "Allow" if qs.get("token") == "allow" else "Deny"
    return {
        "principalId": "sim2real-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": event["methodArn"]}
            ],
        },
    }
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WEBSOCKET ``$connect`` route behind a REQUEST authorizer upgrades with ``?token=allow``;
    a missing or wrong token is refused before reaching the ``$connect`` integration, so an
    authorizer that allows every connection fails."""
    role_arn = _create_lambda_role(ctx)
    log_groups: list = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, log_groups))
    accept_fn = _create_lambda(ctx, role_arn, _ACCEPT_HANDLER, log_groups)
    authz_fn = _create_lambda(ctx, role_arn, _AUTHORIZER_HANDLER, log_groups)

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    account = ctx.client("sts").get_caller_identity()["Account"]

    accept_integ_id = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=accept_fn["arn"],
        IntegrationMethod="POST",
    )["IntegrationId"]
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{authz_fn['arn']}/invocations"
    )
    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["route.request.querystring.token"],
    )["AuthorizerId"]
    agw.create_route(
        ApiId=api_id,
        RouteKey="$connect",
        Target=f"integrations/{accept_integ_id}",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )

    ctx.client("lambda").add_permission(
        FunctionName=accept_fn["name"], StatementId="apigw-invoke",
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    ctx.client("lambda").add_permission(
        FunctionName=authz_fn["name"], StatementId="apigw-authorizer-invoke",
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{authorizer_id}",
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

    base_url = ctx.stage_url(api["ApiEndpoint"], _STAGE)

    # Positive: a valid token upgrades, tolerating IAM/authorizer propagation with a bounded poll.
    allow = _poll_until(
        lambda: _ws_connect(f"{base_url}?token=allow"),
        lambda r: r["status"] == 101,
        timeout_s=120.0, interval_s=3.0,
        description=f"a 101 upgrade at {base_url}?token=allow once the authorizer is live",
    )
    assert allow["status"] == 101, (
        f"?token=allow must be let through by the authorizer, got {allow['status']!r}"
    )
    _quiet_close(allow["sock"])

    # Negative: a wrong token is refused -- and so is no token at all. Each is a positive control
    # for the other (two different ways of failing the SAME check, both must be refused).
    # A token the authorizer evaluates to Deny is Forbidden (403); a handshake that lacks the
    # identity source entirely is refused Unauthorized (401) without the authorizer being called.
    for suffix, label, want in (("?token=deny", "a wrong token", 403), ("", "no token", 401)):
        denied = _poll_until(
            lambda s=suffix: _ws_connect(f"{base_url}{s}"),
            lambda r: r["status"] is not None,
            timeout_s=60.0, interval_s=3.0,
            description=f"a definite handshake outcome at {base_url}{suffix}",
        )
        assert denied["status"] == want, (
            f"{label} must be refused with HTTP {want} at the handshake, got {denied['status']!r}"
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
    target = u.path or "/"
    if u.query:
        target += f"?{u.query}"
    sock.sendall(
        (f"GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
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
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can RECREATE it
    after a delete. One net per check deletes every group, then watches all of them together
    until each has stayed absent for 20s (bounded at 60s), and raises if one never does."""
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
