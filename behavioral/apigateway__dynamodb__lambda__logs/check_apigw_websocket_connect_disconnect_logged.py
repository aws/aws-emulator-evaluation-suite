"""apigw-websocket-connect-disconnect-logged."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import time
import urllib.parse
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-websocket-connect-disconnect-logged"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_LAMBDA_CODE = """
def handler(event, context):
    route = event.get("requestContext", {}).get("routeKey", "UNKNOWN")
    conn = event.get("requestContext", {}).get("connectionId", "")
    print(f"WSHIT route={route} conn={conn}")
    return {"statusCode": 200}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """WebSocket $connect and $disconnect Lambda invocations each produce distinct, observable CloudWatch log entries."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{fn['name']}"
    try:
        logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    apigw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-wsapi-")
    api = apigw.create_api(
        Name=name,
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags={"sim2real": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
    )
    target = f"integrations/{integration['IntegrationId']}"
    apigw.create_route(ApiId=api_id, RouteKey="$connect", Target=target)
    apigw.create_route(ApiId=api_id, RouteKey="$disconnect", Target=target)
    apigw.create_stage(ApiId=api_id, StageName="prod", AutoDeploy=True)

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )

    url = ctx.stage_url(api["ApiEndpoint"], "prod")

    # Clean handshake -> $connect fires synchronously as part of the upgrade.
    sock = _poll_ws_connect(url, timeout_s=90)
    connect_event = _poll_for_log_event(ctx, log_group, "route=$connect", timeout_s=60)

    # Clean close (proper masked close frame, not a raw reset) -> $disconnect fires.
    _ws_close(sock)
    disconnect_event = _poll_for_log_event(ctx, log_group, "route=$disconnect", timeout_s=60)

    assert connect_event["timestamp"] <= disconnect_event["timestamp"]
    assert connect_event["message"] != disconnect_event["message"]
    assert "route=$connect" in connect_event["message"]
    assert "route=$disconnect" in disconnect_event["message"]


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_lambda_function(ctx, role_arn, code, handler="index.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    last_err = None
    resp = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    deadline = time.monotonic() + 60
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"lambda function {name} never became Active (last state={state})")

    return {"name": name, "arn": resp["FunctionArn"]}


def _ws_open(url, timeout=15.0):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    tls = parts.scheme == "wss"
    path = parts.path or "/"
    raw = socket.create_connection((host, parts.port or (443 if tls else 80)), timeout=timeout)
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parts.netloc}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    sock.settimeout(timeout)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 101 " not in status_line:
        sock.close()
        raise AssertionError(f"WebSocket handshake failed: {status_line!r}")
    return sock


def _poll_ws_connect(url, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return _ws_open(url)
        except Exception as e:  # noqa: BLE001 - retry on any handshake failure
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"WebSocket $connect never succeeded within {timeout_s}s: {last_err}")


def _ws_close(sock):
    try:
        mask = os.urandom(4)
        sock.sendall(bytes([0x88, 0x80]) + mask)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _poll_for_log_event(ctx, log_group, substring, timeout_s=60.0, interval_s=3.0) -> dict:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    start_time = int((time.time() - 300) * 1000)
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, startTime=start_time)
        except logs.exceptions.ResourceNotFoundException:
            resp = {"events": []}
        for event in resp.get("events", []):
            if substring in event.get("message", ""):
                return event
        time.sleep(interval_s)
    raise AssertionError(f"log group {log_group} never contained substring {substring!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
