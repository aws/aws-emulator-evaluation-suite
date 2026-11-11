"""deploy-apigatewayv2-cfn-websocket-route-selection-expression-dispatches-by-action."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-websocket-route-selection-expression-dispatches-by-action"

GROUP = "deploy"

SERVICES = ["apigatewayv2", "cloudformation"]

_STAGE = "p"

_ROUTER_HANDLER = (
    "import json\n\n\n"
    "def lambda_handler(event, context):\n"
    "    rc = event.get('requestContext') or {}\n"
    "    route = rc.get('routeKey')\n"
    "    body = json.loads(event.get('body') or '{}')\n"
    "    if route == 'ping':\n"
    "        return {'statusCode': 200, 'body': 'pong'}\n"
    "    if route == 'sendMessage':\n"
    "        return {'statusCode': 200, 'body': 'received: ' + str(body.get('data'))}\n"
    "    return {'statusCode': 200, 'body': 'default-route'}\n"
)


def _template(role_name: str, fn_name: str, api_name: str) -> str:
    def route_block(logical: str, route_key: str, two_way: bool) -> dict:
        props: dict[str, Any] = {
            "ApiId": {"Ref": "WsApi"},
            "RouteKey": route_key,
            "Target": {"Fn::Sub": "integrations/${RouterIntegration}"},
        }
        if two_way:
            props["RouteResponseSelectionExpression"] = "$default"
        return {"Type": "AWS::ApiGatewayV2::Route", "Properties": props}

    resources: dict[str, Any] = {
        "ExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "Path": "/sim2real/",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "inline",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                            ],
                            "Resource": "arn:aws:logs:*:*:*",
                        }],
                    },
                }],
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            },
        },
        "RouterFunction": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": fn_name,
                "Runtime": "python3.12",
                "Handler": "index.lambda_handler",
                "Role": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                "Timeout": 20,
                "MemorySize": 128,
                "Code": {"ZipFile": _ROUTER_HANDLER},
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            },
        },
        "WsApi": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {
                "Name": api_name,
                "ProtocolType": "WEBSOCKET",
                "RouteSelectionExpression": "$request.body.action",
            },
        },
        "InvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": {"Fn::GetAtt": ["RouterFunction", "Arn"]},
                "Action": "lambda:InvokeFunction",
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:execute-api:${AWS::Region}:"
                        "${AWS::AccountId}:${WsApi}/*/*"
                    )
                },
            },
        },
        "RouterIntegration": {
            "Type": "AWS::ApiGatewayV2::Integration",
            "Properties": {
                "ApiId": {"Ref": "WsApi"},
                "IntegrationType": "AWS_PROXY",
                "IntegrationUri": {"Fn::GetAtt": ["RouterFunction", "Arn"]},
            },
        },
        "ConnectRoute": route_block("ConnectRoute", "$connect", two_way=False),
        "PingRoute": route_block("PingRoute", "ping", two_way=True),
        "PingRouteResponse": {
            "Type": "AWS::ApiGatewayV2::RouteResponse",
            "Properties": {
                "ApiId": {"Ref": "WsApi"},
                "RouteId": {"Ref": "PingRoute"},
                "RouteResponseKey": "$default",
            },
        },
        "SendMessageRoute": route_block("SendMessageRoute", "sendMessage", two_way=True),
        "SendMessageRouteResponse": {
            "Type": "AWS::ApiGatewayV2::RouteResponse",
            "Properties": {
                "ApiId": {"Ref": "WsApi"},
                "RouteId": {"Ref": "SendMessageRoute"},
                "RouteResponseKey": "$default",
            },
        },
        "DefaultRoute": route_block("DefaultRoute", "$default", two_way=True),
        "DefaultRouteResponse": {
            "Type": "AWS::ApiGatewayV2::RouteResponse",
            "Properties": {
                "ApiId": {"Ref": "WsApi"},
                "RouteId": {"Ref": "DefaultRoute"},
                "RouteResponseKey": "$default",
            },
        },
        # The deployed snapshot only carries two-way delivery wiring that existed when it was
        # taken, so this DependsOn must name the RouteResponses too -- not only the Routes --
        # or the deployment captures a route table with no reply path and every send times out.
        "WsDeployment": {
            "Type": "AWS::ApiGatewayV2::Deployment",
            "DependsOn": [
                "ConnectRoute",
                "PingRoute",
                "SendMessageRoute",
                "DefaultRoute",
                "PingRouteResponse",
                "SendMessageRouteResponse",
                "DefaultRouteResponse",
            ],
            "Properties": {"ApiId": {"Ref": "WsApi"}},
        },
        "WsStage": {
            "Type": "AWS::ApiGatewayV2::Stage",
            "Properties": {
                "ApiId": {"Ref": "WsApi"},
                "StageName": _STAGE,
                "DeploymentId": {"Ref": "WsDeployment"},
            },
        },
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {"ApiId": {"Value": {"Ref": "WsApi"}}},
    })


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WEBSOCKET API declared entirely through CloudFormation, with ``RouteSelectionExpression:
    $request.body.action``, dispatches each live socket frame to the route matching ``action`` (``ping``,
    ``sendMessage``) and an action matching neither to ``$default``."""
    ctx.verify_account_safety()
    role_name = ctx.unique_name("sim2real-xsvc-wsroute-role-")
    fn_name = ctx.unique_name("sim2real-xsvc-wsroute-fn-")
    api_name = ctx.unique_name("sim2real-xsvc-wsroute-api-")

    # Registered BEFORE the stack create, so LIFO reaps the function's log group AFTER the stack
    # delete removes the function itself -- DeleteFunction never removes /aws/lambda/<fn>.
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, [fn_name]))
    stack = _deploy_cfn(
        ctx,
        _template(role_name, fn_name, api_name),
        stack_name=ctx.unique_name("sim2real-xsvc-wsroute-stk-"),
    )
    api_id = stack["outputs"]["ApiId"]

    url = ctx.api_url(api_id, _STAGE, websocket=True)
    conn = _poll_until(
        lambda: _ws_connect(url, verify=ctx.http_verify),
        lambda r: r["status"] == 101,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"a 101 WebSocket upgrade at {url}",
    )
    sock = conn["sock"]
    ctx.on_cleanup(lambda: _quiet_close(sock))
    buf = [conn["rest"]]

    _ws_send(sock, json.dumps({"action": "ping"}))
    op, payload = _ws_recv(sock, buf)
    assert op == 1, f"the ping route reply must be a text frame, got opcode {op}"
    assert payload == b"pong", f"the ping route must reply 'pong', got {payload!r}"

    _ws_send(sock, json.dumps({"action": "sendMessage", "data": "test-data"}))
    op, payload = _ws_recv(sock, buf)
    assert op == 1, f"the sendMessage route reply must be a text frame, got opcode {op}"
    assert payload == b"received: test-data", (
        f"the sendMessage route must reply 'received: test-data', got {payload!r}"
    )

    _ws_send(sock, json.dumps({"action": "unknownAction"}))
    op, payload = _ws_recv(sock, buf)
    assert op == 1, f"the fallthrough $default reply must be a text frame, got opcode {op}"
    assert payload == b"default-route", (
        f"an action matching neither 'ping' nor 'sendMessage' must fall through to $default and "
        f"reply 'default-route', got {payload!r}"
    )

    _ws_send(sock, struct.pack(">H", 1000), opcode=8)
    op, _ = _ws_recv(sock, buf)
    assert op == 8, f"the server must answer a close frame with a close frame, got opcode {op}"
    _quiet_close(sock)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(ctx, stack_name):
    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError as exc:
        if "does not exist" in exc.response.get("Error", {}).get("Message", ""):
            return "GONE"
        raise


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=600.0) -> None:
    ctx.client("cloudformation").delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template_body: str, *, stack_name: str, timeout_s: float = 600.0) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, timeout_s=timeout_s))
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name} reaching a terminal create state",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {stack_name} ended in {stack['StackStatus']}: "
            f"{stack.get('StackStatusReason', '(no reason given)')}"
        )
    return {
        "stack_name": stack_name,
        "outputs": {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])},
    }


def _quiet_close(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ws_connect(url: str, verify=True) -> dict:
    u = urllib.parse.urlparse(url)
    tls = u.scheme == "wss"
    port = u.port or (443 if tls else 80)
    try:
        raw = socket.create_connection((u.hostname, port), timeout=15)
    except OSError as exc:
        return {"status": None, "error": str(exc)}
    sock = _ssl_context(verify).wrap_socket(raw, server_hostname=u.hostname) if tls else raw
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
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError("the WebSocket closed while a frame was being read")
        buf[0] += chunk
    out, buf[0] = buf[0][:n], buf[0][n:]
    return out


def _ws_recv(sock, buf):
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
        if opcode == 9:
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


def _reap_log_groups(ctx, names):
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can RECREATE it
    after a delete. One net per check deletes every group, then watches all of them together
    until each has stayed absent for 20s (bounded at 60s), and RAISES if one never does."""
    from botocore.exceptions import ClientError

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
            return
        time.sleep(2.0)
    unsettled = [
        g for g, t in absent_since.items() if t is None or time.monotonic() - t < 20.0
    ]
    if unsettled:
        raise AssertionError(f"log group(s) {unsettled!r} kept reappearing after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
