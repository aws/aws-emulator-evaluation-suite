"""wsduplex-oversize-client-message-rejected-close-1009."""

from __future__ import annotations

import base64
import hashlib
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

CHECK = "wsduplex-oversize-client-message-rejected-close-1009"

GROUP = "websocket-duplex"

SERVICES = ["apigatewayv2", "dynamodb", "lambda"]

#: One fragment, comfortably inside the 32 KiB per-frame quota, so the ONLY thing that differs
#: between the accepted message and the refused one is how many of these it is made of.
_FRAGMENT = 16 * 1024

#: 7 fragments = 114688 bytes: under the 128 KiB per-MESSAGE ceiling.
_UNDER_LIMIT_FRAGMENTS = 7

#: 10 fragments = 163840 bytes: over it.
_OVER_LIMIT_FRAGMENTS = 10


_HANDLER = """
import base64
import hashlib
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
    last = None
    for scheme in ("https", "http"):
        client = boto3.client(
            "apigatewaymanagementapi",
            endpoint_url=scheme + "://" + rc.get("domainName") + "/" + rc.get("stage"),
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
        ddb.put_item(TableName=TABLE, Item={"pk": {"S": "conn#" + cid}})
        return {"statusCode": 200}
    if route == "$disconnect":
        ddb.put_item(TableName=TABLE, Item={"pk": {"S": "disc#" + cid}})
        return {"statusCode": 200}
    body = event.get("body") or ""
    is_b64 = bool(event.get("isBase64Encoded"))
    raw = base64.b64decode(body) if is_b64 else body.encode()
    sha = hashlib.sha256(raw).hexdigest()
    # Keyed by the payload digest so the ABSENCE of a particular message is a consistent
    # single-key read, not a scan that has to prove a negative over a whole table.
    ddb.put_item(
        TableName=TABLE,
        Item={
            "pk": {"S": "msg#" + sha},
            "connectionId": {"S": cid},
            "len": {"N": str(len(raw))},
            "b64": {"BOOL": is_b64},
        },
    )
    _post_back(event, cid, json.dumps({"sha": sha, "len": len(raw)}).encode())
    return {"statusCode": 200}
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WebSocket API reassembles 7 x 16 KiB client fragments into ONE 114688-byte `$default` body,
    and answers 10 fragments (past the 128 KiB per-message ceiling) with CLOSE 1009 `Message too
    big` without invoking the integration; the first socket still completes a round trip after."""
    api = _ws_api_with_lambda(ctx, _HANDLER)

    sock = _poll_until(
        lambda: _try_ws_connect(ctx, api["api_endpoint"], api["stage"]),
        lambda s: s is not None,
        timeout_s=150.0,
        interval_s=3.0,
        description=f"WebSocket handshake against stage {api['stage']}",
    )
    live = {"a": sock, "b": None}
    ctx.on_cleanup(lambda: [_ws_close(s) for s in live.values() if s is not None])

    # ---- positive control: a fragmented message is reassembled, and the reply comes back --
    under = _marker_payload(ctx, "wsduplex-under-", _UNDER_LIMIT_FRAGMENTS * _FRAGMENT)
    under_sha = hashlib.sha256(under).hexdigest()
    started = time.monotonic()
    _ws_send_fragmented(sock, under, _FRAGMENT)
    pushed = json.loads(_ws_recv_text(sock, timeout_s=120.0))
    assert pushed.get("len") == len(under), (
        f"$default should have seen the {_UNDER_LIMIT_FRAGMENTS} fragments as ONE "
        f"{len(under)}-byte message; the integration reported {pushed!r} (a per-fragment "
        f"length means the target never reassembled the message)"
    )
    assert pushed.get("sha") == under_sha, (
        f"the reassembled message's digest should be {under_sha}, the integration reported "
        f"{pushed!r}"
    )
    row = _poll_until(
        lambda: _ddb_item(ctx, api["table"], f"msg#{under_sha}"),
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the msg# row $default writes for the {len(under)}-byte message",
    )
    assert row["len"]["N"] == str(len(under)), (
        f"the recorded body length should be {len(under)}, got {row!r}"
    )
    delivered_in = max(time.monotonic() - started, 1.0)

    # ---- break exactly one thing: the same fragments, three more of them ------------------
    over = _marker_payload(ctx, "wsduplex-over-", _OVER_LIMIT_FRAGMENTS * _FRAGMENT)
    over_sha = hashlib.sha256(over).hexdigest()
    sock_b = _ws_connect(ctx, api["api_endpoint"], api["stage"])
    live["b"] = sock_b
    send_error = _ws_send_fragmented(sock_b, over, _FRAGMENT)

    opcode, payload = _ws_recv_frame(sock_b, timeout_s=120.0)
    assert opcode == 0x8, (
        f"a {len(over)}-byte client message should be answered with an RFC-6455 CLOSE frame "
        f"(opcode 0x8); got opcode {opcode:#x} with payload {payload[:200]!r} "
        f"(send error along the way: {send_error!r})"
    )
    close_code = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
    assert close_code == 1009, (
        f"expected WebSocket close code 1009 (message too big) for a {len(over)}-byte "
        f"message, got {close_code!r} (close payload {payload!r})"
    )
    assert payload[2:] == b"Message too big", (
        f"expected the close reason b'Message too big', got {payload[2:]!r}"
    )
    assert _socket_drained(sock_b), (
        "after the 1009 close the service should have torn that socket down; more bytes "
        "arrived instead"
    )
    _ws_close(sock_b)
    live["b"] = None

    # ---- the effect is ABSENT: $default never saw the oversize message -------------------
    window = max(4.0 * delivered_in, 25.0)
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        leaked = _ddb_item(ctx, api["table"], f"msg#{over_sha}")
        assert leaked is None, (
            f"the refused {len(over)}-byte message reached the $default integration anyway: "
            f"row {leaked!r} for digest {over_sha} (a target with no per-message ceiling is "
            f"over-permissive here)"
        )
        time.sleep(2.0)

    # ---- positive control: the refusal was message-scoped; the live twin still works ------
    tail = _marker_payload(ctx, "wsduplex-tail-", _FRAGMENT)
    tail_sha = hashlib.sha256(tail).hexdigest()
    _ws_send_fragmented(sock, tail, _FRAGMENT)
    pushed_tail = json.loads(_ws_recv_text(sock, timeout_s=120.0))
    assert pushed_tail.get("sha") == tail_sha, (
        f"the socket that was open throughout should still complete a duplex round trip "
        f"after the other one was closed with 1009; expected digest {tail_sha}, the "
        f"integration reported {pushed_tail!r}"
    )


def _socket_drained(sock, timeout_s=30.0):
    """True once the peer has torn the connection down. A clean EOF and a reset are the same
    fact here — which one arrives depends on whether our own fragments were still in flight,
    which is not something AWS guarantees either way. A TIMEOUT is not drained and propagates.
    """
    sock.settimeout(timeout_s)
    try:
        return sock.recv(4096) == b""
    except (ConnectionResetError, ssl.SSLError):
        return True


def _marker_payload(ctx, prefix, size):
    """`size` bytes of UTF-8 text that begins with a run-unique marker, so two concurrent
    runs in one account never produce the same digest."""
    marker = ctx.unique_name(prefix).encode()
    assert len(marker) <= size, f"marker {marker!r} does not fit in {size} bytes"
    return marker + b"y" * (size - len(marker))


def _ws_send_fragmented(sock, data, fragment):
    """Send `data` as RFC-6455 continuation fragments of `fragment` bytes each. Returns the
    OSError the service's own close raced into the middle of the send, or None.

    The error is RETURNED rather than raised because a send that dies mid-message is a
    consequence of the refusal under test, not an independent failure — the assertion is on
    the close frame that follows.
    """
    chunks = [data[i : i + fragment] for i in range(0, len(data), fragment)]
    try:
        for i, chunk in enumerate(chunks):
            sock.sendall(
                _ws_frame(
                    0x1 if i == 0 else 0x0, chunk, fin=(i == len(chunks) - 1)
                )
            )
    except OSError as exc:
        return exc
    return None


# ===== helpers =====


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


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}.

    IAM propagation is real: the caller must still tolerate the first use of a brand-new
    role failing (see _create_function_with_retry).
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
    """IAM roles need every attached + inline policy removed before deletion."""
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
    ctx, handler_code, role_arn, env, timeout=30, memory=256, runtime="python3.12"
):
    """Create a Lambda, RETRYING through the IAM role-propagation window, then wait Active.

    Registers the function's teardown plus its auto-created /aws/lambda/<name> log group
    (which survives function deletion and would otherwise leak).
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
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
    deadline = time.monotonic() + 90
    last_err = None
    while True:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
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


def _reap_log_group(ctx, group):
    """delete_log_group in a LOOP: a stream buffered by an invocation that already returned
    can flush after the delete and RECREATE the group, so one delete is one round."""
    logs = ctx.client("logs")
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)


def _create_lambda(ctx, handler_code, permissions=None, env=None):
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM
    statement fragments); logs are always allowed. Role + function each register their own
    teardown. Returns {name,arn}."""
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
    return _create_function_with_retry(ctx, handler_code, role["arn"], env or {})


def _create_ddb_table(ctx, kind="table", key="pk"):
    """Create an on-demand DynamoDB table with a single STRING hash key. Returns {name,arn}.

    DynamoDB keys are ALWAYS typed in this file: {"pk": {"S": "v"}} — in the check and in
    the inline Lambda handler source.
    """
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
        timeout_s=120.0,
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


def _ws_api_with_lambda(ctx, handler, extra_routes=()):
    """A deployed WEBSOCKET API whose $connect/$disconnect/$default routes all target one
    Lambda, plus the DynamoDB table that Lambda records into. Returns
    {api_id, api_endpoint, stage, table, fn}. Every create registers its own teardown
    immediately."""
    table = _create_ddb_table(ctx, kind="wsdup")
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
        handler,
        permissions=[
            {
                "Action": ["dynamodb:PutItem"],
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
    for route_key in ("$connect", "$disconnect", "$default", *extra_routes):
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
    return {"api_id": api_id, "api_endpoint": api_endpoint, "stage": stage,
            "table": table["name"], "fn": fn}


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API. Built from
    ``ctx.stage_url(api_endpoint, stage)``.
    """
    ep = urllib.parse.urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = ep.scheme == "wss"
    port = ep.port or (443 if use_tls else 80)
    return use_tls, ep.hostname, port, ep.hostname, ep.path


def _ws_handshake(ctx, api_endpoint, stage, query="", timeout_s=20.0):
    """Open a socket and send an RFC-6455 handshake. Returns (sock, status_line, rest).

    `rest` is whatever followed the response head in the same read, so a refused upgrade's
    response BODY is not lost to a second recv that may never come.
    """
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path}{query} HTTP/1.1\r\n"
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
    head, _, rest = buf.partition(b"\r\n\r\n")
    text = head.decode("utf-8", "replace")
    return sock, text, rest


def _ws_connect(ctx, api_endpoint, stage, timeout_s=20.0):
    """Handshake and assert the ``101 Switching Protocols`` upgrade — the data-plane fact a
    control-plane CreateRoute/CreateStage 200 does not prove. Returns the socket."""
    sock, head, _ = _ws_handshake(ctx, api_endpoint, stage, timeout_s=timeout_s)
    lines = head.splitlines() or [""]
    assert " 101 " in lines[0], (
        f"WebSocket upgrade on stage {stage} was not accepted; expected '101 Switching "
        f"Protocols', got: {lines[0]!r}"
    )
    return sock


def _try_ws_connect(ctx, api_endpoint, stage):
    """An upgraded socket, or None while the stage/DNS is still settling (a socket error
    or a status other than ``101 Switching Protocols``)."""
    try:
        sock, head, _ = _ws_handshake(ctx, api_endpoint, stage)
    except OSError:
        return None
    if " 101 " in (head.splitlines() or [""])[0]:
        return sock
    try:
        sock.close()
    except OSError:
        pass
    return None


def _ws_frame(opcode, data, fin=True):
    """One masked RFC-6455 frame (client->server frames MUST be masked, RFC 6455 5.3)."""
    header = bytearray([(0x80 if fin else 0x00) | opcode])
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
    return bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _ws_send(sock, opcode, data):
    sock.sendall(_ws_frame(opcode, data))


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


def _ws_recv_frame(sock, timeout_s=30.0):
    """Read exactly one frame; return (opcode, payload)."""
    sock.settimeout(timeout_s)
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
    return opcode, payload


def _ws_recv_text(sock, timeout_s=30.0):
    """Read frames until a TEXT frame arrives; return its payload. Ping frames are skipped
    and a CLOSE is a failure that names the close payload."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        opcode, payload = _ws_recv_frame(sock, timeout_s=timeout_s)
        if opcode == 0x1:
            return payload.decode("utf-8", "replace")
        if opcode == 0x8:
            raise AssertionError(
                f"the service closed the connection instead of delivering a text frame "
                f"(close payload {payload!r})"
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
