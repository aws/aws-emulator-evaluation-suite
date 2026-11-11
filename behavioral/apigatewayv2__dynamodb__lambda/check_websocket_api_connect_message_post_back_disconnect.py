"""websocket-api-connect-message-post-back-disconnect."""

from __future__ import annotations

import base64
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

CHECK = "websocket-api-connect-message-post-back-disconnect"

GROUP = "websocket"

SERVICES = ["apigatewayv2", "dynamodb", "lambda"]


_HANDLER = """
import json
import os

import boto3

ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]


def _post_back(event, cid, data):
    # The management endpoint is per-API and comes from the request context, so it is never
    # hardcoded. Real AWS is always https; an emulator may front the management API over
    # plain http, so the post is retried on the other scheme before giving up.
    rc = event.get("requestContext") or {}
    host = rc.get("domainName")
    stage = rc.get("stage")
    last = None
    for scheme in ("https", "http"):
        client = boto3.client(
            "apigatewaymanagementapi",
            endpoint_url=scheme + "://" + host + "/" + stage,
        )
        try:
            client.post_to_connection(ConnectionId=cid, Data=data)
            return
        except Exception as exc:  # noqa: BLE001 - scheme probe, re-raised below
            last = exc
    raise last


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    cid = rc.get("connectionId")
    if route == "$connect":
        ddb.put_item(
            TableName=TABLE,
            Item={"pk": {"S": "conn#" + cid}, "connectionId": {"S": cid}},
        )
        return {"statusCode": 200}
    if route == "$disconnect":
        ddb.delete_item(TableName=TABLE, Key={"pk": {"S": "conn#" + cid}})
        return {"statusCode": 200}
    try:
        payload = json.loads(event.get("body") or "{}")
    except ValueError:
        payload = {}
    text = str(payload.get("text", ""))
    ddb.put_item(
        TableName=TABLE,
        Item={
            "pk": {"S": "msg#" + cid},
            "connectionId": {"S": cid},
            "text": {"S": text},
        },
    )
    _post_back(event, cid, json.dumps({"echo": text}).encode())
    return {"statusCode": 200}
"""


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Over a real socket a WebSocket API upgrades with 101, $connect writes a DynamoDB row, $default
    persists a frame and pushes a reply via PostToConnection from the Lambda, and a clean close
    fires $disconnect, which removes the row.
    """
    table = _create_ddb_table(ctx, kind="wsconn")
    account = _account_id(ctx)

    # The API is created FIRST so the Lambda's ManageConnections policy can be scoped to
    # this API's ARN rather than a wildcard.
    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_xname(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_xsvc_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[
            {
                "Action": ["dynamodb:PutItem", "dynamodb:DeleteItem"],
                "Resource": table["arn"],
            },
            {
                "Action": ["execute-api:ManageConnections"],
                "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*",
            },
        ],
        env={"TABLE": table["name"]},
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
    for route_key in ("$connect", "$disconnect", "$default"):
        v2.create_route(
            ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration_id}"
        )
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-ws-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    stage = "dev"
    deployment_id = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment_id)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )

    # The handshake itself is polled: a freshly deployed WebSocket stage needs a moment,
    # and only a 101 upgrade ends the poll.
    sock = _poll_until(
        lambda: _try_ws_connect(ctx, api_endpoint, stage),
        lambda s: s is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"WebSocket handshake against stage {stage}",
    )
    closed = {"done": False}

    def _cleanup_socket():
        if not closed["done"]:
            _ws_close(sock)

    ctx.on_cleanup(_cleanup_socket)

    conn_items = _poll_until(
        lambda: _scan_prefix(ctx, table["name"], "conn#"),
        lambda items: len(items) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description="exactly one conn# row written by the $connect route",
    )
    connection_id = conn_items[0]["connectionId"]["S"]
    assert connection_id, f"the $connect row carries no connectionId: {conn_items[0]!r}"

    text = ctx.unique_name("ws-payload-")
    _ws_send_text(sock, json.dumps({"action": "echo", "text": text}))

    # The frame reached $default and its payload was persisted.
    msg_item = _poll_until(
        lambda: _ddb_item(ctx, table["name"], f"msg#{connection_id}"),
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"the msg# row for connection {connection_id}",
    )
    assert msg_item["text"]["S"] == text, (
        f"$default should have persisted the frame payload {text!r}, got "
        f"{msg_item['text']['S']!r}"
    )

    # The integration pushed a message back down this socket.
    pushed = _ws_recv_text(sock, timeout_s=60.0)
    assert json.loads(pushed).get("echo") == text, (
        f"expected PostToConnection to deliver {{'echo': {text!r}}} on the client socket, "
        f"got {pushed!r} (nothing arriving means the management API accepted the call and "
        f"dropped the payload)"
    )

    # A clean close fires $disconnect, which removes the connection row.
    _ws_close(sock)
    closed["done"] = True
    _poll_until(
        lambda: _ddb_item(ctx, table["name"], f"conn#{connection_id}"),
        lambda i: i is None,
        timeout_s=120.0,
        interval_s=4.0,
        description=(
            f"the conn# row for {connection_id} removed by the $disconnect route "
            f"(still present => $disconnect never fired on a clean client close)"
        ),
    )


def _try_ws_connect(ctx, api_endpoint, stage):
    """An upgraded socket, or None while the stage/DNS is still settling (a socket error
    or a status other than ``101 Switching Protocols``)."""
    try:
        sock, status_line = _ws_upgrade(ctx, api_endpoint, stage)
    except OSError:
        return None
    if " 101 " in status_line:
        return sock
    try:
        sock.close()
    except OSError:
        pass
    return None


def _scan_prefix(ctx, table, prefix):
    """Every item whose pk begins with `prefix`. Used to DISCOVER the server-assigned
    connection id, which the client never sees."""
    out = []
    paginator = ctx.client("dynamodb").get_paginator("scan")
    for page in paginator.paginate(
        TableName=table,
        FilterExpression="begins_with(pk, :p)",
        ExpressionAttributeValues={":p": {"S": prefix}},
        ConsistentRead=True,
    ):
        out.extend(page.get("Items", []))
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
    """Poll probe() until predicate(result) is truthy; return it, or raise AssertionError on timeout."""
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


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its policies-first teardown. Returns {name,arn}.

    The first use of a brand-new role can still fail while IAM propagates.
    """
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
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """Delete the role after removing its attached and inline policies, which IAM requires."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
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
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait for Active.

    Also deletes the /aws/lambda/<name> log group at cleanup, since it outlives the function.
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while True:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_if_present(ctx, group):
    """Delete a Lambda's log group; the group exists only once the function has logged."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
):
    """Create a Lambda whose role allows logs plus `permissions` (IAM statement fragments).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    """Grant apigateway.amazonaws.com lambda:InvokeFunction, scoped to source_arn."""
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e):
            raise


def _create_ddb_table(ctx, kind="table", key="pk"):
    """Create an on-demand DynamoDB table with a single STRING hash key. Returns {name,arn}."""
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
        interval_s=2.0,
        description=f"DynamoDB table {name} ACTIVE",
    )
    return {"name": name, "arn": resp["TableDescription"]["TableArn"], "key": key}


def _ddb_item(ctx, table, key_value, key="pk"):
    """GetItem (consistent read) or None."""
    got = ctx.client("dynamodb").get_item(
        TableName=table, Key={key: {"S": key_value}}, ConsistentRead=True
    )
    return got.get("Item")


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API stage."""
    ep = urllib.parse.urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = ep.scheme == "wss"
    port = ep.port or (443 if use_tls else 80)
    return use_tls, ep.hostname, port, ep.hostname, ep.path


def _ws_upgrade(ctx, api_endpoint, stage, timeout_s=20.0):
    """Send an RFC 6455 handshake over a stdlib socket. Returns (socket, status_line)."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
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
    return sock, (head.splitlines() or [""])[0]


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
            raise AssertionError(
                f"WebSocket closed after {len(buf)} of {n} expected bytes"
            )
        buf += chunk
    return buf


def _ws_recv_text(sock, timeout_s=30.0):
    """Read frames until a text frame arrives; return its payload. Ping frames are skipped."""
    sock.settimeout(timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        b1 = _ws_recv_exact(sock, 1)[0]
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
                f"WebSocket server closed the connection instead of sending a text "
                f"frame (close payload {payload!r})"
            )
    raise AssertionError(f"no WebSocket text frame within {timeout_s}s")


def _ws_close(sock):
    """Send a masked, empty CLOSE frame then close — the clean disconnect that makes the
    service fire $disconnect, rather than an abrupt TCP reset."""
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
