"""apigw-websocket-api-lambda-integration-positive."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-websocket-api-lambda-integration-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_LAMBDA_CODE = """
def handler(event, context):
    route = event.get("requestContext", {}).get("routeKey", "UNKNOWN")
    conn = event.get("requestContext", {}).get("connectionId", "")
    body = event.get("body", "")
    print(f"WSHIT route={route} conn={conn} body={body}")
    return {"statusCode": 200}
"""


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A WebSocket API route integrated with Lambda invokes the function on $connect and $default routes."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{fn['name']}"
    try:
        logs.create_log_group(logGroupName=log_group, tags=_managed_tags())
        ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    apigw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-wsapi-")
    api = apigw.create_api(
        Name=name,
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_managed_tags(),
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
    apigw.create_route(ApiId=api_id, RouteKey="$default", Target=target)
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

    sock = _poll_ws_connect(url, timeout_s=90)
    try:
        _assert_log_contains(ctx, log_group, "route=$connect", timeout_s=60)
        _ws_send_text(sock, json.dumps({"action": "noop", "data": "hello-default"}))
        _assert_log_contains_all(ctx, log_group, ["route=$default", "hello-default"], timeout_s=60)
    finally:
        _ws_close(sock)


def _managed_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-wsapi"}


def _managed_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _managed_tags().items()]


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_managed_tags_kv()
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
                Tags=_managed_tags(),
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


def _ws_send_text(sock, message):
    payload = message.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    header = bytearray([0x81])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", length)
    header += mask
    sock.sendall(bytes(header) + masked)


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


def _assert_log_contains(ctx, log_group, substring, timeout_s=60.0, interval_s=3.0):
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
                return
        time.sleep(interval_s)
    raise AssertionError(f"log group {log_group} never contained substring {substring!r} within {timeout_s}s")


def _assert_log_contains_all(ctx, log_group, substrings, timeout_s=60.0, interval_s=3.0):
    """Every substring must appear in the SAME log event — not just somewhere in the group.

    Distinguishes "the $default route fired with this body" from "some event happens to
    contain this substring" (e.g. a mis-routed $connect invocation that echoes the raw frame).
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    start_time = int((time.time() - 300) * 1000)
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, startTime=start_time)
        except logs.exceptions.ResourceNotFoundException:
            resp = {"events": []}
        for event in resp.get("events", []):
            message = event.get("message", "")
            if all(s in message for s in substrings):
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"log group {log_group} never contained a single event with all of {substrings!r} within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
