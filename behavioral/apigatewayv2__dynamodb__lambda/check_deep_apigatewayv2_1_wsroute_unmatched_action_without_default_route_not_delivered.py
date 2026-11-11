"""deep-apigatewayv2-1-wsroute-unmatched-action-without-default-route-not-delivered."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import textwrap
import time
import urllib.parse
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigatewayv2-1-wsroute-unmatched-action-without-default-route-not-delivered"

GROUP = "websocket-routing"

SERVICES = ["apigatewayv2", "dynamodb", "lambda"]


# One handler source, deployed as three DIFFERENT functions that differ only in MARKER. Every
# invocation writes one row keyed by (MARKER#<frame key>, request id) BEFORE it returns, so the
# number of times a given integration saw a given frame is a consistent Query count, observed
# out of band — not inferred from what the client happened to receive.
_HANDLER = """
import hashlib
import json
import os

import boto3

ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]
MARKER = os.environ["MARKER"]


def _frame_key(body):
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and parsed.get("nonce"):
        return "nonce:" + str(parsed["nonce"])
    return "sha:" + hashlib.sha256((body or "").encode()).hexdigest()


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey") or ""
    if route == "$connect":
        qs = event.get("queryStringParameters") or {}
        key = "connect:" + (qs.get("probe") or "none")
    else:
        key = _frame_key(event.get("body") or "")
    ddb.put_item(
        TableName=TABLE,
        Item={
            "pk": {"S": MARKER + "#" + key},
            "sk": {"S": context.aws_request_id},
            "routeKey": {"S": route},
        },
    )
    return {
        "statusCode": 200,
        "body": json.dumps({"marker": MARKER, "routeKey": route, "key": key}),
    }
"""


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """On a WebSocket API with a `sendmessage` route and no `$default` route, an unmatched frame (route keys match
    exactly, so `SendMessage` is unmatched too) gets a `Forbidden` error frame and reaches no integration,
    while the connection stays open and the next matching frame is still dispatched."""
    v2 = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    account = _account_id(ctx)
    _log_groups_for(ctx)
    table = _create_ddb_table(ctx, kind="wsnodef")

    created_api = v2.create_api(
        Name=_xname(ctx, "wsnodef"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_xsvc_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    role = _create_role(
        ctx, "lambda.amazonaws.com", inline_policy=_lambda_policy(table["arn"])
    )
    marker = ctx.unique_name("mk-send-")
    fn = _create_function_with_retry(
        ctx, _HANDLER, role["arn"], {"TABLE": table["name"], "MARKER": marker}
    )
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-ws-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    integration_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
        IntegrationMethod="POST",
    )["IntegrationId"]
    route_id = v2.create_route(
        ApiId=api_id,
        RouteKey="sendmessage",
        Target=f"integrations/{integration_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    v2.create_route_response(ApiId=api_id, RouteId=route_id, RouteResponseKey="$default")
    stage = "dev"
    deployment_id = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment_id)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )

    def count(key):
        return _count(ctx, table["name"], f"{marker}#{key}")

    ws = _poll_until(
        lambda: _try_open(ctx, api_endpoint, stage, ""),
        lambda w: w is not None,
        timeout_s=150.0,
        interval_s=3.0,
        description=f"WebSocket handshake against stage {stage} of {api_id}",
    )
    live = {"ws": ws}
    ctx.on_cleanup(lambda: live["ws"].close())

    # ---- positive control: the matching frame is dispatched to sendmessage --------------
    t0 = time.monotonic()
    n0, reply = _send_settled(ws, lambda n: {"action": "sendmessage", "nonce": n})
    window = max(3.0 * (time.monotonic() - t0), 12.0)
    assert reply.get("marker") == marker and reply.get("routeKey") == "sendmessage", (
        f"action=sendmessage should be answered by the sendmessage integration "
        f"(marker {marker!r}); got {reply!r}"
    )
    assert count(f"nonce:{n0}") == 1, (
        f"sendmessage should have recorded exactly one invocation for nonce {n0}, recorded "
        f"{count(f'nonce:{n0}')!r}"
    )

    # ---- unmatched frames: answered by the gateway, delivered to nothing ----------------
    for action in ("nosuchroute", "SendMessage"):
        nonce = uuid.uuid4().hex
        reply = _send_json(ws, {"action": action, "nonce": nonce})
        assert reply.get("message") == "Forbidden", (
            f"with no $default route, action={action!r} should be answered by the gateway's "
            f"own Forbidden error frame; got {reply!r}"
        )
        assert "marker" not in reply, (
            f"the unmatched action={action!r} frame was answered by an integration: {reply!r}"
        )
        _assert_absent_for(
            lambda: count(f"nonce:{nonce}"),
            window,
            f"the sendmessage integration was invoked for an unmatched action={action!r} "
            f"frame (nonce {nonce})",
        )

    # ---- positive control: the socket survived and still dispatches ---------------------
    n9 = uuid.uuid4().hex
    reply = _send_json(ws, {"action": "sendmessage", "nonce": n9})
    assert reply.get("marker") == marker, (
        f"after the unmatched frames the same socket should still dispatch action="
        f"sendmessage to its integration (marker {marker!r}); got {reply!r}"
    )
    assert count(f"nonce:{n9}") == 1, (
        f"sendmessage should have recorded exactly one invocation for nonce {n9}, recorded "
        f"{count(f'nonce:{n9}')!r}"
    )


def _lambda_policy(table_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": table_arn},
        ],
    }


def _send_settled(ws, make_doc, timeout_s=60.0):
    """Send fresh-nonce frames until an INTEGRATION answers (its reply carries `marker`).

    Only a gateway error frame (no marker — e.g. while a just-added Lambda permission is
    still propagating) is retried; WHICH integration answered is left to the caller to
    assert, so a misrouted frame is never retried away. Returns (nonce, reply).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        nonce = uuid.uuid4().hex
        reply = _send_json(ws, make_doc(nonce))
        if "marker" in reply or time.monotonic() >= deadline:
            return nonce, reply
        time.sleep(2.0)


def _send_json(ws, doc, timeout_s=60.0):
    """Send one JSON text frame and return the integration's JSON reply."""
    ws.send(json.dumps(doc))
    text = ws.recv(timeout=timeout_s)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AssertionError(f"reply to {doc!r} was not JSON: {text!r}") from exc


def _assert_absent_for(probe, window_s, message):
    """Hold an absence open for `window_s`: probe() must read 0 on every poll."""
    deadline = time.monotonic() + window_s
    while True:
        seen = probe()
        assert seen == 0, f"{message}: {seen!r} invocation record(s)"
        if time.monotonic() >= deadline:
            return
        time.sleep(2.0)


def _count(ctx, table, pk):
    """Consistent Query count of the rows under one partition key, paginated."""
    ddb = ctx.client("dynamodb")
    total, kwargs = 0, {}
    while True:
        resp = ddb.query(
            TableName=table,
            KeyConditionExpression="pk = :p",
            ExpressionAttributeValues={":p": {"S": pk}},
            ConsistentRead=True,
            Select="COUNT",
            **kwargs,
        )
        total += resp["Count"]
        if not resp.get("LastEvaluatedKey"):
            return total
        kwargs = {"ExclusiveStartKey": resp["LastEvaluatedKey"]}


def _paginate(client, op, key, **kwargs):
    out, token = [], None
    while True:
        resp = getattr(client, op)(**kwargs, **({"NextToken": token} if token else {}))
        out.extend(resp.get(key, []))
        token = resp.get("NextToken")
        if not token:
            return out




_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout. Propagation (IAM, stage deploy, message delivery) is
    always waited out this way — never with a bare time.sleep as the assertion.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}."""
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
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function_with_retry(ctx, handler_code, role_arn, env, timeout=30, memory=256):
    """Create a Lambda, RETRYING through the IAM role-propagation window, then wait Active.

    The function's log group joins ONE reap net registered before the first create, so LIFO
    runs it after every delete: a stream buffered by an invocation can flush after the delete
    and recreate the group, so the net re-deletes over a bounded window.
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    _log_groups_for(ctx).append(f"/aws/lambda/{name}")
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
        "Environment": {"Variables": env},
    }
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            # IAM propagation exposes no condition to poll; the bounded retry at first use
            # of the brand-new role is what makes this correct.
            if "cannot be assumed" in str(e) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=90.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


_LOG_GROUPS = {}


def _log_groups_for(ctx):
    """The Lambda log groups this run created, reaped by one net registered on first use.

    Registered before any function exists, so LIFO runs it LAST — after every delete_function
    and after the API that invoked them is gone, which is when no new stream can start.
    """
    key = id(ctx)
    if key not in _LOG_GROUPS:
        _LOG_GROUPS[key] = []
        groups = _LOG_GROUPS[key]
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, groups))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups, window_s=45.0):
    """delete_log_group for every group, then keep re-deleting any that a late flush
    recreates until the bounded window closes; a residual after that is a declared leak."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + window_s
    while True:
        for group in groups:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as e:
                if "ResourceNotFoundException" not in str(e):
                    raise
        if time.monotonic() >= deadline:
            return
        time.sleep(5)


def _create_ddb_table(ctx, kind="table"):
    """An on-demand table keyed (pk S, sk S). Keys are ALWAYS typed. Returns {name,arn}."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"DynamoDB table {name} ACTIVE",
    )
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API. Built from
    ``ctx.stage_url(api_endpoint, stage)``.
    """
    ep = urllib.parse.urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = ep.scheme == "wss"
    port = ep.port or (443 if use_tls else 80)
    return use_tls, ep.hostname, port, ep.hostname, ep.path


class _SimpleWebSocket:
    """Minimal RFC-6455 client (stdlib-only: socket/ssl), avoiding a 'websockets' dependency.

    Inlined from behavioral/apigatewaymanagementapi/.
    """

    def __init__(self, sock) -> None:
        self._sock = sock
        self._buf = b""
        self.close_code = None
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
            if opcode == 0x8:  # close frame
                self.close_code = (
                    struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                )
                self._closed = True
                raise ConnectionError(f"websocket closed by server ({payload!r})")
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x1, 0x2):
                return payload if opcode == 0x2 else payload.decode("utf-8")
            continue

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

    def send(self, data) -> None:
        if isinstance(data, str):
            self._send_frame(0x1, data.encode("utf-8"))
        else:
            self._send_frame(0x2, bytes(data))

    def close(self, code: int = 1000) -> None:
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


def _ws_handshake(ctx, api_endpoint, stage, query="", timeout_s=20.0):
    """Send an RFC-6455 upgrade. Returns (status, head_text, websocket_or_None).

    A refused upgrade is RETURNED with its status rather than raised, so a caller can assert
    on the refusal itself; an accepted one is verified against Sec-WebSocket-Accept.
    """
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
    ws_key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path}{query} HTTP/1.1\r\n"
        f"Host: {http_host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(timeout_s)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    head, _, leftover = resp.partition(b"\r\n\r\n")
    text = head.decode("utf-8", "replace")
    parts = (text.splitlines() or [""])[0].split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    if status != 101:
        try:
            sock.close()
        except OSError:
            pass
        return status, text, None
    expected_accept = base64.b64encode(
        hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    assert expected_accept.encode() in head, (
        f"101 upgrade carried the wrong Sec-WebSocket-Accept; head was {text!r}"
    )
    ws = _SimpleWebSocket(sock)
    ws._buf = leftover
    return status, text, ws


def _try_open(ctx, api_endpoint, stage, query):
    """An upgraded socket, or None while the stage / DNS is still settling."""
    try:
        _, _, ws = _ws_handshake(ctx, api_endpoint, stage, query=query)
    except OSError:
        return None
    return ws


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
