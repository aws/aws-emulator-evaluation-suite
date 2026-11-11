"""websocket-inbound-binary-frame-rejected."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import struct
import time
import zipfile
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "websocket-inbound-binary-frame-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_PREFIX = "sim2real-behav-wsbin-"

#: Deliberately not valid UTF-8, so the rejection cannot hinge on an ASCII-safe payload.
_RAW_BYTES = bytes([0x01, 0x02, 0x03, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = _name(ctx, "tbl")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "connectionId", "AttributeType": "S"},
            {"AttributeName": "eventType", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "connectionId", "KeyType": "HASH"},
            {"AttributeName": "eventType", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return table_name


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _name(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return role["Arn"]


def _lambda_zip() -> bytes:
    # Records isBase64Encoded and the body per eventType, so text and binary frames are told apart.
    code = (
        "import boto3, os, time\n"
        "from decimal import Decimal\n"
        "_table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])\n"
        "def handler(event, context):\n"
        "    rc = event.get('requestContext', {})\n"
        "    route = rc.get('routeKey', 'UNKNOWN')\n"
        "    if route == '$connect':\n"
        "        key = 'CONNECT'\n"
        "    else:\n"
        "        key = 'BIN' if event.get('isBase64Encoded') else 'TXT'\n"
        "    _table.put_item(Item={\n"
        "        'connectionId': rc.get('connectionId', 'unknown'),\n"
        "        'eventType': key,\n"
        "        'timestamp': Decimal(str(time.time())),\n"
        "        'isBase64Encoded': bool(event.get('isBase64Encoded', False)),\n"
        "        'body': str(event.get('body') or ''),\n"
        "    })\n"
        "    return {'statusCode': 200}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _drop_log_group(ctx, group: str) -> None:
    """Delete the function's log group and keep deleting until it has stayed absent for 20 s (a
    buffered flush can recreate it just after a delete); raise if it never does within 90 s."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + 90.0
    absent_since = None
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            absent_since = None
        except logs.exceptions.ResourceNotFoundException:
            absent_since = absent_since or time.monotonic()
            if time.monotonic() - absent_since >= 20.0:
                return
        time.sleep(2.0)
    raise AssertionError(f"log group {group} kept reappearing after delete for 90s")


def _create_lambda(ctx, role_arn: str, table_name: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = _name(ctx, "fn")
    # Registered before the function so it runs after delete_function (LIFO); the log group
    # outlives the function.
    ctx.on_cleanup(lambda: _drop_log_group(ctx, f"/aws/lambda/{fn_name}"))
    zip_bytes = _lambda_zip()
    last_err = None
    fn = None
    for _ in range(10):
        try:
            fn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Environment={"Variables": {"TABLE_NAME": table_name}},
                Tags=_TAGS,
            )
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
    if fn is None:
        raise AssertionError(f"lambda role never became assumable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn_name).get("State") == "Active":
            break
        time.sleep(2)
    else:
        raise AssertionError("lambda function never became Active")
    return fn["FunctionArn"], fn_name


def _wait_deployment_deployed(ctx, api_id: str, deployment_id: str, timeout_s: float = 30.0) -> None:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if apigw.get_deployment(ApiId=api_id, DeploymentId=deployment_id).get("DeploymentStatus") == "DEPLOYED":
            return
        time.sleep(2)
    raise AssertionError("websocket deployment never reached DEPLOYED")


def _create_ws_api(ctx, lambda_arn: str, fn_name: str) -> dict:
    apigw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    api = apigw.create_api(
        Name=_name(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integ_id = apigw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=lambda_arn, PayloadFormatVersion="1.0"
    )["IntegrationId"]
    apigw.create_route(ApiId=api_id, RouteKey="$connect", Target=f"integrations/{integ_id}")
    apigw.create_route(ApiId=api_id, RouteKey="$default", Target=f"integrations/{integ_id}")
    stage_name = "test"
    deployment = apigw.create_deployment(ApiId=api_id)
    _wait_deployment_deployed(ctx, api_id, deployment["DeploymentId"])
    apigw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=deployment["DeploymentId"])
    ctx.on_cleanup(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_name))
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="agwv2-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    return {"api_id": api_id, "stage": stage_name, "wss_url": ctx.stage_url(api["ApiEndpoint"], stage_name)}


def _setup_ws_stack(ctx) -> dict:
    table_name = _create_table(ctx)
    role_arn = _create_role(ctx)
    lambda_arn, fn_name = _create_lambda(ctx, role_arn, table_name)
    stack = _create_ws_api(ctx, lambda_arn, fn_name)
    stack["table_name"] = table_name
    return stack


class _SimpleWebSocket:
    """Minimal RFC-6455 client (stdlib-only: socket/ssl)."""

    def __init__(self, sock) -> None:
        self._sock = sock
        self._buf = b""
        self.closed = False

    def _recv_exact(self, n: int, deadline: float) -> bytes:
        while len(self._buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for websocket frame")
            self._sock.settimeout(remaining)
            chunk = self._sock.recv(65536)
            if not chunk:
                self.closed = True
                raise ConnectionError("websocket connection closed by peer")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def recv(self, timeout: float = 10.0):
        deadline = time.monotonic() + timeout
        while True:
            hdr = self._recv_exact(2, deadline)
            b0, b1 = hdr[0], hdr[1]
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2, deadline))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8, deadline))[0]
            mask_key = self._recv_exact(4, deadline) if masked else b""
            payload = self._recv_exact(length, deadline) if length else b""
            if masked:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                self.closed = True
                return 0x8, payload
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            return opcode, payload

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask_key = os.urandom(4)
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        length = len(payload)
        header = bytes([0x80 | opcode])
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += bytes([0x80 | 126]) + struct.pack("!H", length)
        else:
            header += bytes([0x80 | 127]) + struct.pack("!Q", length)
        self._sock.sendall(header + mask_key + masked_payload)

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def send_binary(self, data: bytes) -> None:
        self._send_frame(0x2, data)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except OSError:
            pass
        self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def _open_ws_connection(wss_url: str) -> _SimpleWebSocket:
    parsed = urlparse(wss_url)
    host = parsed.hostname
    use_tls = parsed.scheme == "wss"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    raw_sock = socket.create_connection((host, port), timeout=20)
    sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host) if use_tls else raw_sock
    ws_key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(20)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("websocket handshake failed: connection closed before headers completed")
        resp += chunk
    header_blob, _, leftover = resp.partition(b"\r\n\r\n")
    status_line = header_blob.split(b"\r\n", 1)[0]
    if b"101" not in status_line:
        sock.close()
        raise ConnectionError(f"websocket handshake failed: {status_line!r}")
    ws = _SimpleWebSocket(sock)
    ws._buf = leftover
    return ws


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _get_record(ctx, table_name: str, connection_id: str, event_type: str):
    ddb = ctx.client("dynamodb")
    resp = ddb.get_item(
        TableName=table_name,
        Key={"connectionId": {"S": connection_id}, "eventType": {"S": event_type}},
    )
    return resp.get("Item")


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
    """A client BINARY WebSocket frame closes the connection with 1003 "Binary is not supported"
    and never reaches the Lambda integration, while a TEXT frame on the same connection does.
    """
    stack = _setup_ws_stack(ctx)
    ws = _open_ws_connection(stack["wss_url"])
    ctx.on_cleanup(ws.close)

    connection_id = _poll_until(
        lambda: next(
            (
                item["connectionId"]["S"]
                for item in ctx.client("dynamodb").scan(TableName=stack["table_name"]).get("Items", [])
                if item.get("eventType", {}).get("S") == "CONNECT"
            ),
            None,
        ),
        lambda v: v is not None,
        timeout_s=120.0,
        description="a $connect record in DynamoDB",
    )

    # A TEXT frame reaching the backend shows the rejection below is about the binary opcode.
    control_text = "sim2real-text-control"
    ws.send_text(control_text)
    text_item = _poll_until(
        lambda: _get_record(ctx, stack["table_name"], connection_id, "TXT"),
        lambda v: v is not None,
        timeout_s=30.0,
        description="the TEXT-frame record to reach the Lambda integration",
    )
    assert text_item["isBase64Encoded"]["BOOL"] is False, (
        f"a TEXT frame was recorded with isBase64Encoded=True: {text_item!r}"
    )
    assert text_item["body"]["S"] == control_text, (
        f"TEXT frame body mismatch: expected {control_text!r}, got {text_item['body']['S']!r}"
    )

    ws.send_binary(_RAW_BYTES)
    opcode, payload = ws.recv(timeout=15)
    assert opcode == 0x8, f"expected a close frame (0x8) after the binary send, got opcode 0x{opcode:x}"
    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
    assert code == 1003, f"expected close code 1003 (unsupported data), got {code!r}: {payload[2:]!r}"
    reason = payload[2:].decode("utf-8", "replace")
    assert reason == "Binary is not supported", (
        f"the 1003 close must carry the reason 'Binary is not supported', got {reason!r}"
    )
    assert ws.closed, "the connection must be closed after the binary frame"

    assert _get_record(ctx, stack["table_name"], connection_id, "BIN") is None, (
        "the rejected binary frame reached the Lambda integration anyway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
