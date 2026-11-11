"""client-initiated-close-converges-to-gone-with-live-twin."""
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

CHECK = "client-initiated-close-converges-to-gone-with-live-twin"

GROUP = "state"

SERVICES = ["apigatewaymanagementapi"]


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane",
      "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After the client sends a WebSocket close frame, GetConnection, PostToConnection and
    DeleteConnection on that id answer GoneException, while a twin connection on the same
    stage stays live and still receives a push.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-how-to-call-websocket-api-connections.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role = _lambda_role(ctx, account)
    fn = _create_function(ctx, role["arn"])
    api_id, stage, api_endpoint = _deploy_websocket_api(ctx, account, fn)
    mgmt = _management_client(ctx, api_endpoint, stage)

    # Two sockets on ONE api/stage: the subject and its control group, minted seconds apart by the
    # same integration so nothing but the close distinguishes them.
    sock_doomed, cid_doomed = _open_and_identify(ctx, api_id, stage, api_endpoint)
    sock_twin, cid_twin = _open_and_identify(ctx, api_id, stage, api_endpoint)
    assert cid_doomed != cid_twin, (
        f"the two sockets were both handed connection id {cid_doomed!r}; a WebSocket API must mint "
        f"one id per connection, and with a shared id this check cannot tell the two apart"
    )

    # ---- full setup: BOTH connections are live, and both wirings demonstrably deliver ----
    described_doomed = mgmt.get_connection(ConnectionId=cid_doomed)
    described_twin = mgmt.get_connection(ConnectionId=cid_twin)
    connected_at_twin = described_twin.get("ConnectedAt")
    assert described_doomed.get("ConnectedAt") is not None, (
        f"GetConnection on the live connection about to be closed returned no ConnectedAt: "
        f"{described_doomed!r}"
    )
    assert connected_at_twin is not None, (
        f"GetConnection on the live twin returned no ConnectedAt: {described_twin!r}"
    )

    # Measure push latency on the connection about to close, so "gone" later is not "slow".
    probe_doomed = ctx.unique_name("sim2real-behav-pre-")
    started = time.monotonic()
    mgmt.post_to_connection(ConnectionId=cid_doomed, Data=probe_doomed.encode())
    _expect_text(sock_doomed, probe_doomed, "the connection about to be closed", timeout_s=60.0)
    delivery_latency_s = time.monotonic() - started

    probe_twin = ctx.unique_name("sim2real-behav-pre-")
    mgmt.post_to_connection(ConnectionId=cid_twin, Data=probe_twin.encode())
    _expect_text(sock_twin, probe_twin, "the twin, before the close", timeout_s=60.0)

    # ---- break exactly one thing: the CLIENT closes ITS end of one socket ----
    # A well-formed masked close frame, which is what a real client library sends. The twin's
    # socket is not touched.
    _ws_close(sock_doomed)

    # ---- poll until the connection is reported gone ----
    converge_started = time.monotonic()
    _poll_until(
        lambda: _error_code_or_success(lambda: mgmt.get_connection(ConnectionId=cid_doomed)),
        lambda code: code == "GoneException",
        timeout_s=60.0,
        interval_s=2.0,
        description=(
            f"GetConnection({cid_doomed}) answering GoneException after the CLIENT closed the "
            f"socket (a push on this same wiring landed in {delivery_latency_s:.2f}s, so the "
            f"connection store is not merely lagging)"
        ),
    )
    converged_in_s = time.monotonic() - converge_started

    # ---- the dead id is unusable, not merely unreadable: a MUTATION on it fails too ----
    # AWS answers 410 GoneException with an empty body, so the exact message is "".
    post_err = _error(
        lambda: mgmt.post_to_connection(ConnectionId=cid_doomed, Data=b"unreachable")
    )
    assert post_err == ("GoneException", ""), (
        f"PostToConnection on a client-closed connection returned {post_err!r}, expected "
        f"('GoneException', ''). A success here means the connection store still holds a socket the "
        f"client provably closed {converged_in_s:.2f}s earlier"
    )
    delete_err = _error(lambda: mgmt.delete_connection(ConnectionId=cid_doomed))
    assert delete_err == ("GoneException", ""), (
        f"DeleteConnection on a client-closed connection returned {delete_err!r}, expected "
        f"('GoneException', '') — deleting a connection that is already gone must not report success"
    )

    # ---- the twin is untouched and still delivers bytes ----
    still_live = mgmt.get_connection(ConnectionId=cid_twin)
    assert still_live.get("ConnectedAt") == connected_at_twin, (
        f"after the OTHER socket closed, the twin reports ConnectedAt "
        f"{still_live.get('ConnectedAt')!r} instead of the original {connected_at_twin!r}; its "
        f"connection was replaced or torn down by a close that had nothing to do with it"
    )
    survivor_payload = ctx.unique_name("sim2real-behav-survivor-")
    mgmt.post_to_connection(ConnectionId=cid_twin, Data=survivor_payload.encode())
    _expect_text(sock_twin, survivor_payload, "the surviving twin", timeout_s=60.0)

    # ---- terminal read on the subject: goneness is terminal, not a flap ----
    final_err = _error(lambda: mgmt.get_connection(ConnectionId=cid_doomed))
    assert final_err == ("GoneException", ""), (
        f"GetConnection({cid_doomed}) answered {final_err!r} on the final read after answering "
        f"'GoneException' {converged_in_s:.2f}s into the run; a closed connection must stay gone "
        f"while its twin on the same API stays live, not flap back into the store"
    )


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: `$default` echoes the caller its own connection id, the only way a client learns its id.
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
    """An execution role allowing only execute-api:ManageConnections. No logs:* on purpose: the
    log group materialises asynchronously after cleanup has run, so granting it leaks a group."""
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
    """The `$default` integration, cleanup registered."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-wsfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)
    payload = buf.getvalue()

    def _create():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
            # A brand-new role is not yet assumable by Lambda; IAM has no condition to poll.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return False
            raise

    _poll_until(_create, bool, timeout_s=120.0, interval_s=4.0,
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
    """(use_tls, connect_host, port, Host header, path) for the stage's WebSocket URL."""
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
    """A socket that completed the 101 upgrade, or None while a fresh stage still answers 403."""
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
        if opcode in (0x9, 0xA):  # ping / pong: control traffic, not a message
            continue
        return opcode, payload
    raise AssertionError(f"no WebSocket frame within {timeout_s}s")


def _ws_close(sock):
    """Send a masked CLOSE frame and close the TCP socket. Idempotent."""
    try:
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _management_client(ctx, api_endpoint, stage):
    """The @connections client; its endpoint is per API, so endpoint_url must be set explicitly."""
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


class _UnexpectedSuccess(AssertionError):
    """The call the check expected to be REJECTED succeeded."""


def _error(fn):
    """The error (Code, Message); raises if the call succeeded."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise _UnexpectedSuccess("the call succeeded but real AWS rejects it")


def _error_code_or_success(fn):
    """The error Code, or the literal `'SUCCEEDED'` while the call still succeeds. Used only as a
    poll probe; every verdict goes through `_error`, which raises on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "SUCCEEDED"


def _open_and_identify(ctx, api_id, stage, api_endpoint):
    """A live socket plus the server-minted connection id it was given, learned off the socket."""
    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, stage),
        lambda s: s is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"a 101 WebSocket upgrade against API {api_id} stage {stage}",
    )
    ctx.on_cleanup(lambda: _ws_close(sock))
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"expected a text frame carrying the connection id, got opcode {opcode:#x} with payload "
        f"{payload[:120]!r}"
    )
    connection_id = json.loads(payload)["connectionId"]
    assert connection_id, f"the $default route echoed no connection id: {payload!r}"
    return sock, connection_id


def _expect_text(sock, expected, which, *, timeout_s=60.0):
    """Read the next data frame off `sock` and require it to be exactly `expected`."""
    opcode, delivered = _ws_recv_frame(sock, timeout_s=timeout_s)
    assert opcode == 0x1, (
        f"expected the pushed payload as a text frame on {which}, got opcode {opcode:#x} with "
        f"{delivered[:120]!r} (0x8 means the socket was closed instead)"
    )
    assert delivered.decode() == expected, (
        f"PostToConnection returned 200 but {which} received {delivered[:120]!r}, not the "
        f"{len(expected)}-byte payload {expected!r}"
    )


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
