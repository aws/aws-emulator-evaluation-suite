"""client-initiated-close-invokes-disconnect-route."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import socket
import ssl
import struct
import time
import zipfile
from typing import Any
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "client-initiated-close-invokes-disconnect-route"
GROUP = "event-propagation"
SERVICES = ["apigatewayv2"]

_PREFIX = "sim2real-behav-agwv2cclose-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX}


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A client-initiated close frame on a WebSocket API connection invokes the $disconnect route,
    seen as its Lambda's DynamoDB record for that connection, and no other open connection's.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-keys-connect-disconnect.html
    """
    stack = _setup_ws_stack(ctx)
    t0 = time.time()
    ws = _open_ws_connection(stack["wss_url"])
    cid = _wait_for_connect_record(ctx, stack["table_name"], t0)

    # Client-initiated close: a masked close frame from the socket, not a management-API call.
    ws.close()

    record = _wait_for_disconnect_record(ctx, stack["table_name"], cid, timeout_s=60.0)
    assert record is not None, (
        f"$disconnect route was never invoked for connection {cid} after a client-initiated close"
    )
    assert record.get("connectionId", {}).get("S") == cid, (
        f"the $disconnect record must be keyed on {cid!r}, got {record!r}"
    )

    # Positive control: a second, independent connection on the same stack never got a disconnect
    # record at all (nothing fired spuriously for a connection that is still open at this point).
    ws2 = _open_ws_connection(stack["wss_url"])
    ctx.on_cleanup(ws2.close)
    cid2 = _wait_for_connect_record(ctx, stack["table_name"], t0, exclude_ids=(cid,))
    spurious_record = _get_disconnect_record(ctx, stack["table_name"], cid2)
    assert spurious_record is None, (
        f"a still-open connection {cid2} must not have a $disconnect record, got {spurious_record!r}"
    )


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
    account_id = ctx.account
    api_name = _name(ctx, "wsapi")
    api = apigw.create_api(
        Name=api_name,
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
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
    apigw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=deployment["DeploymentId"], Tags=_TAGS)
    ctx.on_cleanup(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_name))
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="agwv2-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )
    wss_url = ctx.stage_url(api["ApiEndpoint"], stage_name)
    return {"api_id": api_id, "stage": stage_name, "wss_url": wss_url}


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
        self._closed = False

    def _recv_exact(self, n: int, deadline: float) -> bytes:
        while len(self._buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for websocket frame")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as exc:
                raise TimeoutError("timed out waiting for websocket frame") from exc
            if not chunk:
                raise ConnectionError("websocket connection closed by peer")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

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

    def close(self, code: int = 1000) -> None:
        if self._closed:
            return
        try:
            self._send_frame(0x8, struct.pack("!H", code))
        except OSError:
            pass
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def _do_ws_handshake(wss_url: str):
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


def _open_ws_connection(wss_url: str, connect_timeout: float = 90.0):
    # A freshly deployed WebSocket API can 5xx briefly while the integration and IAM role
    # propagate, so transient gateway errors are retried within the bound.
    deadline = time.monotonic() + connect_timeout
    last_exc: Exception | None = None
    while True:
        try:
            return _do_ws_handshake(wss_url)
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


def _get_disconnect_record(ctx, table_name: str, connection_id: str) -> dict | None:
    ddb = ctx.client("dynamodb")
    resp = ddb.get_item(
        TableName=table_name,
        Key={"connectionId": {"S": connection_id}, "eventType": {"S": "DISCONNECT"}},
    )
    return resp.get("Item")


def _wait_for_disconnect_record(ctx, table_name: str, connection_id: str, timeout_s: float = 60.0) -> dict | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        item = _get_disconnect_record(ctx, table_name, connection_id)
        if item is not None:
            return item
        time.sleep(1.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
