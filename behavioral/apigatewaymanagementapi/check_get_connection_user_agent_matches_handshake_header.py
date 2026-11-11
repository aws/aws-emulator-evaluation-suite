"""get-connection-user-agent-matches-handshake-header."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-connection-user-agent-matches-handshake-header"
GROUP = "data-plane"
SERVICES = ["apigatewaymanagementapi"]


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The User-Agent header sent during the WebSocket handshake is recorded verbatim in
    GetConnection's Identity.UserAgent."""
    stack = _setup_ws_stack(ctx)
    custom_agent = f"sim2real-behav-agent/{ctx.unique_name('ua-')}"
    t0 = time.time()
    ws = _open_ws_connection(stack["wss_url"], extra_headers={"User-Agent": custom_agent})
    ctx.on_cleanup(ws.close)
    cid = _wait_for_connect_record(ctx, stack["table_name"], t0)

    mgmt = _management_client(ctx, stack["mgmt_endpoint"])
    resp = mgmt.get_connection(ConnectionId=cid)
    recorded = resp.get("Identity", {}).get("UserAgent", "")
    assert recorded == custom_agent, f"expected UserAgent {custom_agent!r}, got {recorded!r}"


_PREFIX = "sim2real-agwmgmt-"


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_zip() -> bytes:
    code = (
        "import boto3, os, time\n"
        "from decimal import Decimal\n"
        "_table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])\n"
        "def handler(event, context):\n"
        "    rc = event.get('requestContext', {})\n"
        "    _table.put_item(Item={\n"
        "        'connectionId': rc.get('connectionId', 'unknown'),\n"
        "        'eventType': rc.get('eventType', 'UNKNOWN'),\n"
        "        'timestamp': Decimal(str(time.time())),\n"
        "        'sourceIp': str(rc.get('identity', {}).get('sourceIp', '')),\n"
        "        'userAgent': str(rc.get('identity', {}).get('userAgent', '')),\n"
        "    })\n"
        "    return {'statusCode': 200}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return role["Arn"]


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return table_name


def _wait_lambda_active(ctx, fn_name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        if cfg.get("State") == "Active":
            return
        time.sleep(2)
    raise AssertionError("lambda function never became Active")


def _create_lambda(ctx, role_arn: str, table_name: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = _name(ctx, "fn")
    zip_bytes = _lambda_zip()
    last_err = None
    fn = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Environment={"Variables": {"TABLE_NAME": table_name}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
    if fn is None:
        raise AssertionError(f"lambda role never became assumable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_lambda_active(ctx, fn_name)
    return fn["FunctionArn"], fn_name


def _wait_deployment_deployed(ctx, api_id: str, deployment_id: str, timeout_s: float = 30.0) -> None:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dep = apigw.get_deployment(ApiId=api_id, DeploymentId=deployment_id)
        if dep.get("DeploymentStatus") == "DEPLOYED":
            return
        time.sleep(2)
    raise AssertionError("websocket deployment never reached DEPLOYED")


def _create_ws_api(ctx, lambda_arn: str, fn_name: str) -> dict:
    apigw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    api_name = _name(ctx, "wsapi")
    api = apigw.create_api(
        Name=api_name,
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags={"sim2real": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integ = apigw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=lambda_arn, PayloadFormatVersion="1.0"
    )
    integ_id = integ["IntegrationId"]
    apigw.create_route(ApiId=api_id, RouteKey="$connect", Target=f"integrations/{integ_id}")
    apigw.create_route(ApiId=api_id, RouteKey="$disconnect", Target=f"integrations/{integ_id}")
    stage_name = "test"
    deployment = apigw.create_deployment(ApiId=api_id)
    _wait_deployment_deployed(ctx, api_id, deployment["DeploymentId"])
    apigw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=deployment["DeploymentId"])
    ctx.on_cleanup(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_name))
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="agwmgmt-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )
    wss_url = ctx.stage_url(api["ApiEndpoint"], stage_name)
    mgmt_endpoint = ctx.stage_url(api["ApiEndpoint"], stage_name, management=True)
    return {
        "api_id": api_id,
        "stage": stage_name,
        "wss_url": wss_url,
        "mgmt_endpoint": mgmt_endpoint,
        "account_id": account_id,
    }


def _setup_ws_stack(ctx) -> dict:
    table_name = _create_table(ctx)
    role_arn = _create_role(ctx)
    lambda_arn, fn_name = _create_lambda(ctx, role_arn, table_name)
    stack = _create_ws_api(ctx, lambda_arn, fn_name)
    stack["table_name"] = table_name
    return stack


class _SimpleWebSocket:
    """Minimal RFC-6455 client (stdlib-only: socket/ssl), avoiding a 'websockets' dependency."""

    def __init__(self, sock) -> None:
        self._sock = sock
        self._buf = b""
        self.close_code = None
        self._closed = False

    def _recv_exact(self, n: int, deadline: float) -> bytes:
        import socket as _socket

        while len(self._buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for websocket frame")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(65536)
            except _socket.timeout as exc:
                raise TimeoutError("timed out waiting for websocket frame") from exc
            if not chunk:
                raise ConnectionError("websocket connection closed by peer")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def recv(self, timeout: float = 10.0):
        import struct

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
            if opcode == 0x8:  # close frame
                self.close_code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                self._closed = True
                raise ConnectionError("websocket closed by server")
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x1, 0x2):
                return payload if opcode == 0x2 else payload.decode("utf-8")
            continue

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        import os
        import struct

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

    def send(self, data) -> None:
        if isinstance(data, str):
            self._send_frame(0x1, data.encode("utf-8"))
        else:
            self._send_frame(0x2, bytes(data))

    def close(self, code: int = 1000) -> None:
        import struct

        if self._closed:
            return
        try:
            self._send_frame(0x8, struct.pack("!H", code))
        except OSError:
            pass
        self._closed = True
        if self.close_code is None:
            self.close_code = code
        try:
            self._sock.close()
        except OSError:
            pass


def _do_ws_handshake(wss_url: str, extra_headers: dict | None = None):
    import base64
    import hashlib
    import os
    import socket
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(wss_url)
    host = parsed.hostname
    use_tls = parsed.scheme == "wss"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    raw_sock = socket.create_connection((host, port), timeout=20)
    sock = raw_sock
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
    ws_key = base64.b64encode(os.urandom(16)).decode()
    header_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            header_lines.append(f"{k}: {v}")
    request = "\r\n".join(header_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
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
        try:
            sock.close()
        except OSError:
            pass
        raise ConnectionError(f"websocket handshake failed: {status_line!r}")
    expected_accept = base64.b64encode(
        hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    if expected_accept.encode() not in header_blob:
        raise ConnectionError("websocket handshake failed: Sec-WebSocket-Accept mismatch")
    ws = _SimpleWebSocket(sock)
    ws._buf = leftover
    return ws


def _open_ws_connection(wss_url: str, extra_headers: dict | None = None, connect_timeout: float = 60.0):
    # Freshly deployed WEBSOCKET APIs / Lambda proxy integrations can 5xx for a short
    # window while the integration and IAM role propagate; retry transient gateway
    # errors instead of failing the whole check on a provisioning race.
    deadline = time.monotonic() + connect_timeout
    last_exc: Exception | None = None
    while True:
        try:
            return _do_ws_handshake(wss_url, extra_headers)
        except ConnectionError as exc:
            msg = str(exc)
            transient = any(code in msg for code in ("500", "502", "503", "504"))
            if not transient or time.monotonic() >= deadline:
                raise
            last_exc = exc
            time.sleep(2)
    raise last_exc  # pragma: no cover - loop always returns or raises above


def _wait_for_connect_record(
    ctx, table_name: str, since_epoch: float, exclude_ids: tuple[str, ...] = (), timeout_s: float = 30.0
) -> str:
    ddb = ctx.client("dynamodb")
    exclude = set(exclude_ids)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ddb.scan(TableName=table_name)
        for item in resp.get("Items", []):
            if item.get("eventType", {}).get("S") != "CONNECT":
                continue
            cid = item["connectionId"]["S"]
            if cid in exclude:
                continue
            if float(item["timestamp"]["N"]) >= since_epoch:
                return cid
        time.sleep(1.0)
    raise AssertionError("no new $connect record observed in DynamoDB within timeout")


def _management_client(ctx, mgmt_endpoint: str):
    return ctx.client("apigatewaymanagementapi", endpoint_url=mgmt_endpoint)


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
