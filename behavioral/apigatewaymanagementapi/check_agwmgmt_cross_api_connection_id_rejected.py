"""agwmgmt-cross-api-connection-id-rejected."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agwmgmt-cross-api-connection-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: `$default` echoes the caller its own connection id over the socket. That is the only way a
#: WebSocket client can learn the server-minted id it needs to address itself with, and it keeps
#: this check inside apigatewaymanagementapi rather than routing the id through a data store.
_HANDLER = """
import json
import boto3


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    cid = rc.get("connectionId")
    if route in ("$connect", "$disconnect"):
        return {"statusCode": 200}
    endpoint = "https://" + rc.get("domainName") + "/" + rc.get("stage")
    boto3.client("apigatewaymanagementapi", endpoint_url=endpoint).post_to_connection(
        ConnectionId=cid, Data=json.dumps({"connectionId": cid}).encode()
    )
    return {"statusCode": 200}
"""


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _lambda_role(ctx, account):
    """An execution role allowing ONLY execute-api:ManageConnections, cleanup registered.

    Deliberately no `logs:*`. Lambda creates `/aws/lambda/<fn>` on first invocation only if the
    execution role permits it, and that group is created ASYNCHRONOUSLY: it can
    materialise AFTER `ctx.on_cleanup` has already run its `delete_log_group` (which then
    swallows a ResourceNotFoundException) and survive the run, leaving the account with
    an orphaned log group. Reordering the cleanups so the group is deleted after the function
    does not fix it -- the delivery lag outlives both. Withholding the permission removes the
    resource instead of racing it; the function still executes, it just writes no logs.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-wsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["execute-api:ManageConnections"],
                        "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:*/*",
                    }
                ],
            }
        ),
    )
    return {"name": role_name, "arn": arn}


def _create_function(ctx, role_arn):
    """The `$default` integration, cleanup registered (function + its log group)."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-wsfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)
    payload = buf.getvalue()

    def _create():
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": payload},
                Timeout=20,
                Tags=_TAGS,
            )
            return True
        except ClientError as exc:
            # A brand-new role is not yet assumable by Lambda until IAM propagates it.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return False
            raise

    _poll_until(_create, bool, timeout_s=120.0, interval_s=2.0,
                description=f"Lambda {name} created once its role became assumable")
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    config = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": config["FunctionArn"]}


def _deploy_websocket_api(ctx, account, fn, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    for route_key in ("$connect", "$disconnect", "$default"):
        v2.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration}")
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        # Unique per API: two APIs may share one integration Lambda, and a repeated
        # StatementId is a ResourceConflictException rather than an idempotent no-op.
        StatementId=f"sim2real-behav-apigw-{api_id}",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return api_id, stage, api["ApiEndpoint"]


def _ws_target(ctx, api_endpoint, stage):
    """(use_tls, connect_host, port, Host header, path) for the WebSocket data plane. Built from
    ``ctx.stage_url(api_endpoint, stage)``.
    """
    from urllib.parse import urlparse

    parsed = urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = parsed.scheme == "wss"
    port = parsed.port or (443 if use_tls else 80)
    return use_tls, parsed.hostname, port, parsed.hostname, parsed.path


def _ws_connect(ctx, api_endpoint, stage, timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket; returns (socket, status line)."""
    use_tls, host, port, http_host, path = _ws_target(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=http_host)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {http_host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(timeout_s)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
    return sock, (head.splitlines() or [""])[0]


def _ws_upgraded(ctx, api_endpoint, stage):
    """A socket that completed the 101 upgrade, or None while the stage is still settling.

    A freshly created stage answers 403 for a few seconds; that is a deploy delay, not a
    fidelity signal, so it is polled rather than asserted.
    """
    try:
        sock, status = _ws_connect(ctx, api_endpoint, stage)
    except OSError:
        return None
    if " 101 " in status:
        return sock
    sock.close()
    return None


def _ws_send_text(sock, payload):
    """One masked FIN text frame (client->server frames MUST be masked, RFC 6455 5.3)."""
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
            raise AssertionError(f"the socket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_frame(sock, timeout_s=60.0):
    """(opcode, payload) for the next frame, skipping pings."""
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
        if opcode == 0x9:  # ping
            continue
        return opcode, payload
    raise AssertionError(f"no WebSocket frame within {timeout_s}s")


def _ws_close(sock):
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _management_client(ctx, api_endpoint, stage):
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )



class _UnexpectedSuccess(AssertionError):
    """The call the check expected to be REJECTED succeeded."""


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise _UnexpectedSuccess("the call succeeded but real AWS rejects it")


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A connection id is scoped to the API that minted it: a SECOND API's @connections endpoint
    refuses a LIVE id from a different API with GoneException on all three operations, and that
    second API's DeleteConnection does not close the first API's socket.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role = _lambda_role(ctx, account)
    fn = _create_function(ctx, role["arn"])
    api_a, stage_a, endpoint_a = _deploy_websocket_api(ctx, account, fn)
    api_b, stage_b, endpoint_b = _deploy_websocket_api(ctx, account, fn)
    assert api_a != api_b, f"both APIs came back as {api_a!r}"

    sock = _poll_until(
        lambda: _ws_upgraded(ctx, endpoint_a, stage_a),
        lambda s: s is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"a 101 WebSocket upgrade against API {api_a} stage {stage_a}",
    )

    def _close_socket():
        """Close the client socket; `_ws_close` swallows OSError so this is idempotent."""
        _ws_close(sock)

    ctx.on_cleanup(_close_socket)

    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"expected a text frame carrying the connection id, got opcode {opcode:#x} with "
        f"payload {payload[:120]!r}"
    )
    connection_id = json.loads(payload)["connectionId"]
    assert connection_id, f"the $default route echoed no connection id: {payload!r}"

    mgmt_a = _management_client(ctx, endpoint_a, stage_a)
    mgmt_b = _management_client(ctx, endpoint_b, stage_b)

    # full setup: the id IS live on API A
    live = mgmt_a.get_connection(ConnectionId=connection_id)
    assert live.get("ConnectedAt") is not None, (
        f"API A does not recognise the connection it just minted: {live!r}"
    )

    # break exactly one thing: the API the request is addressed to
    # AWS answers 410 GoneException with an empty body, so the exact message is "".
    observed = {
        "GetConnection": _error(
            lambda: mgmt_b.get_connection(ConnectionId=connection_id)
        ),
        "PostToConnection": _error(
            lambda: mgmt_b.post_to_connection(ConnectionId=connection_id, Data=b"foreign")
        ),
        "DeleteConnection": _error(
            lambda: mgmt_b.delete_connection(ConnectionId=connection_id)
        ),
    }
    assert set(observed.values()) == {("GoneException", "")}, (
        f"API B answered {observed!r} for a connection live on API A; real AWS returns "
        f"('GoneException', '') for all three. A success, or a non-empty message, means the "
        f"connection namespace is shared across APIs"
    )

    # (b) the effect is absent: the foreign DeleteConnection did not close A's socket, and the
    # foreign PostToConnection delivered nothing. Both are read off the socket by pushing a
    # payload from API A and requiring THAT payload — not the foreign one — to arrive next.
    still_live = mgmt_a.get_connection(ConnectionId=connection_id)
    assert still_live.get("ConnectedAt") == live.get("ConnectedAt"), (
        f"after API B's DeleteConnection, API A reports ConnectedAt "
        f"{still_live.get('ConnectedAt')!r} instead of the original "
        f"{live.get('ConnectedAt')!r}; the connection was replaced or torn down"
    )
    mine = json.dumps({"own": ctx.unique_name("sim2real-behav-msg-")})
    mgmt_a.post_to_connection(ConnectionId=connection_id, Data=mine.encode())
    opcode, delivered = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x1, (
        f"the socket is no longer usable after API B's calls: next frame opcode {opcode:#x} "
        f"payload {delivered[:120]!r} (0x8 means API B's DeleteConnection closed it)"
    )
    assert delivered.decode() == mine, (
        f"the next frame on the socket was {delivered!r}, not API A's payload {mine!r} — API "
        f"B's rejected PostToConnection delivered its payload anyway"
    )

    # (c) the positive control: API A's own DeleteConnection DOES close this socket, so the
    # rejections above were about the API and not about the operation being unavailable
    mgmt_a.delete_connection(ConnectionId=connection_id)
    opcode, close_payload = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x8, (
        f"API A's DeleteConnection did not close the socket either: opcode {opcode:#x} payload "
        f"{close_payload[:120]!r}"
    )
    assert _error(lambda: mgmt_a.get_connection(ConnectionId=connection_id)) == (
        "GoneException",
        "",
    ), "after API A deleted the connection, API A still reports it as live"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
