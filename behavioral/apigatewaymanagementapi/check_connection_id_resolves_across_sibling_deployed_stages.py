"""connection-id-resolves-across-sibling-deployed-stages."""
from __future__ import annotations

import base64
import datetime
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

CHECK = "connection-id-resolves-across-sibling-deployed-stages"
GROUP = "isolation"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: Error codes a cleanup callback treats as "already deleted".
_MISSING = ("ResourceNotFoundException", "NotFoundException", "NoSuchEntity")

#: A well-formed connection id that no live socket owns. Base64 of 11 bytes, the shape API
#: Gateway mints; a well-formed id that reaches the connection store and answers GoneException.
_WELL_FORMED_UNKNOWN = "Fabc1cWIPHcCJ7A="

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ignore_missing(fn):
    """Run a cleanup call, tolerating only a not-found answer."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _MISSING:
            raise


def _refusal(fn, expectation):
    """(code, message, HTTP status) of a call real AWS refuses; a success is a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message", ""), status
    raise AssertionError(f"{expectation}, but the call SUCCEEDED and returned {str(result)[:300]}")


def _delete_role(ctx, role_name):
    """Delete a role and its inline policies, tolerating only a not-found answer per call."""
    iam = ctx.client("iam")
    names = []
    _ignore_missing(lambda: names.extend(iam.list_role_policies(RoleName=role_name)["PolicyNames"]))
    for name in names:
        _ignore_missing(lambda n=name: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    _ignore_missing(lambda: iam.delete_role(RoleName=role_name))


def _lambda_role(ctx, account):
    """An execution role allowing ONLY execute-api:ManageConnections; returns its ARN.

    Deliberately no `logs:*`: Lambda creates `/aws/lambda/<fn>` on first invocation only if the
    execution role permits it, so withholding the permission means no log group exists to clean
    up. The function still executes, it just writes no logs.
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
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:*/*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return arn


def _create_function(ctx, role_arn):
    """The `$connect`/`$disconnect`/`$default` integration; returns {"name", "arn"}."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-wsfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)
    payload = buf.getvalue()

    def _create():
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": payload},
                Timeout=20,
                Tags=_TAGS,
            )
        except ClientError as exc:
            # A brand-new role is not yet assumable by Lambda; bounded retry, not a sleep.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(_create, bool, timeout_s=_budget_s(ctx, 120.0), interval_s=4.0,
                      description=f"Lambda {name} created once its role became assumable",
                      ctx=ctx,
                      )["FunctionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=2.0,
        description=f"Lambda {name} Active",
        ctx=ctx,
    )
    return {"name": name, "arn": arn}


def _deploy_websocket_api(ctx, account, fn, stages):
    """One WEBSOCKET API whose ``stages`` all serve ONE deployment.

    Returns (api_id, deployment, api_endpoint).

    Stages, routes, the integration and the deployment belong to the API and go with it; the
    invoke permission belongs to the function and goes with that.
    """
    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: v2.delete_api(ApiId=api_id)))
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
        # Unique per API: a repeated StatementId is a ResourceConflictException, not a no-op.
        StatementId=f"sim2real-behav-apigw-{api_id}",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
    )
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    for stage in stages:
        v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    return api_id, deployment, api["ApiEndpoint"]


def _ws_target(ctx, api_endpoint, stage):
    """(use_tls, connect_host, port, Host header, path) for the WebSocket data plane."""
    from urllib.parse import urlparse

    parsed = urlparse(ctx.stage_url(api_endpoint, stage))
    use_tls = parsed.scheme == "wss"
    port = parsed.port or (443 if use_tls else 80)
    return use_tls, parsed.hostname, port, parsed.hostname, parsed.path


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ws_connect(ctx, api_endpoint, stage, timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket; returns (socket, status line)."""
    use_tls, host, port, http_host, path = _ws_target(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    try:
        if use_tls:
            sock = _ssl_context(ctx.http_verify).wrap_socket(sock, server_hostname=http_host)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {http_host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(request.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
        return sock, (head.splitlines() or [""])[0]
    except BaseException:
        sock.close()
        raise


def _ws_upgraded(ctx, api_endpoint, stage):
    """A socket that completed the 101 upgrade, or None while the stage is still settling.

    A freshly created stage answers 403 for a few seconds; that is a deploy delay, not a
    fidelity signal, so it is polled rather than asserted. A TLS verification failure is not:
    it never resolves by retrying, so it propagates instead of being read as "still settling".
    """
    try:
        sock, status = _ws_connect(ctx, api_endpoint, stage)
    except ssl.SSLError:
        raise
    except OSError:
        return None
    if " 101 " in status:
        return sock
    _ws_close(sock)
    return None


def _open_socket(ctx, api_endpoint, stage, label="client"):
    """An upgraded socket whose close is registered for cleanup."""
    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, stage),
        lambda s: s is not None,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=4.0,
        description=f"a 101 WebSocket upgrade against stage {stage} for the {label} socket",
        ctx=ctx,
    )
    ctx.on_cleanup(lambda: _ws_close(sock))
    return sock


def _ws_frame(opcode, data):
    """One masked FIN client frame (client->server frames MUST be masked, RFC 6455 5.3)."""
    header = bytearray([0x80 | opcode])
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
    return bytes(header) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _ws_send_text(sock, payload):
    sock.sendall(_ws_frame(0x1, payload.encode()))


def _ws_recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise AssertionError(f"no WebSocket frame completed: {len(buf)} of {n} bytes") from None
        if not chunk:
            raise AssertionError(f"the socket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_frame(sock, timeout_s=60.0):
    """(opcode, payload) of the next complete data message or a CLOSE frame.

    PINGs are answered and PONGs skipped; a fragmented message is joined up to its FIN frame,
    so a first fragment is never mistaken for the whole message.
    """
    deadline = time.monotonic() + timeout_s
    opcode, parts = None, []
    while True:
        b1, b2 = _ws_recv_exact(sock, 2, deadline)
        n = b2 & 0x7F
        if n == 126:
            n = int.from_bytes(_ws_recv_exact(sock, 2, deadline), "big")
        elif n == 127:
            n = int.from_bytes(_ws_recv_exact(sock, 8, deadline), "big")
        payload = _ws_recv_exact(sock, n, deadline) if n else b""
        frame_opcode = b1 & 0x0F
        if frame_opcode == 0x9:
            sock.sendall(_ws_frame(0xA, payload))
        elif frame_opcode == 0x8:
            return frame_opcode, payload
        elif frame_opcode != 0xA:
            opcode = frame_opcode if opcode is None else opcode
            parts.append(payload)
            if b1 & 0x80:
                return opcode, b"".join(parts)


def _ws_close(sock):
    try:
        sock.settimeout(1.0)
        sock.sendall(b"\x88\x80" + os.urandom(4))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _close_code(payload, what):
    """The status code of a CLOSE frame's payload; a payload without one is a mismatch."""
    assert len(payload) >= 2, f"{what}: the CLOSE frame carried no status code: {payload!r}"
    return int.from_bytes(payload[:2], "big")


def _management_client(ctx, api_endpoint, stage):
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _learn_connection_id(sock):
    """The server-minted id for ``sock``, read back off the socket through the `$default` route."""
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"expected a text frame carrying the connection id, got opcode {opcode:#x} with "
        f"payload {payload[:120]!r}"
    )
    connection_id = json.loads(payload)["connectionId"]
    assert connection_id, f"the $default route echoed no connection id: {payload!r}"
    return connection_id


def _absent_connection_outcome(mgmt, probe_id):
    """(code, message, status) for GetConnection on an absent well-formed id, or None while the
    stage's deployment has not propagated and the endpoint still answers ForbiddenException."""
    outcome = _refusal(
        lambda: mgmt.get_connection(ConnectionId=probe_id),
        f"real AWS refuses GetConnection for the absent well-formed id {probe_id!r}",
    )
    if outcome[0] == "ForbiddenException":
        return None
    return outcome


def _assert_gone(outcome, what):
    code, message, status = outcome
    assert code == "GoneException", (
        f"{what} returned {code!r} with message {message!r} and HTTP {status!r}; real AWS "
        f"answers 'GoneException'"
    )
    assert message == "", (
        f"{what}: the GoneException carried message {message!r}; real AWS sends an empty message "
        f"for this refusal"
    )
    assert status == 410, (
        f"{what}: the GoneException arrived with HTTP {status!r}; real AWS answers 410"
    )


@tags("axis:happy-path", "cap:c1", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A management endpoint's stage segment need only name a deployed stage: through a sibling
    deployed stage of one API, GetConnection reports the minting stage's ConnectedAt and SourceIp,
    PostToConnection reaches the socket and DeleteConnection closes it (200, 200, 204).
    """
    account = ctx.account
    minting_stage = "dev"
    sibling_stage = "alt"

    role_arn = _lambda_role(ctx, account)
    fn = _create_function(ctx, role_arn)
    # Two stages off one deployment is the whole point: they are indistinguishable except for the
    # stage segment of their URLs, so anything that differs between them is attributable to the
    # stage and nothing else.
    api_id, deployment, api_endpoint = _deploy_websocket_api(
        ctx, account, fn, (minting_stage, sibling_stage)
    )

    v2 = ctx.client("apigatewayv2")
    for stage in (minting_stage, sibling_stage):
        described = v2.get_stage(ApiId=api_id, StageName=stage)
        reported_deployment = described.get("DeploymentId")
        assert reported_deployment == deployment, (
            f"stage {stage!r} of api {api_id} reports DeploymentId {reported_deployment!r}, not "
            f"the single deployment {deployment!r} this check created both stages from; the "
            f"comparison only isolates the stage segment while both stages serve the identical "
            f"deployment"
        )
        reported_name = described.get("StageName")
        assert reported_name == stage, (
            f"stage {stage!r} of api {api_id} reports StageName {reported_name!r}, not the stage "
            f"name it was created with"
        )

    sock = _open_socket(ctx, api_endpoint, minting_stage, label="minting-stage")

    # the client learns its own server-minted id off the socket
    connection_id = _learn_connection_id(sock)

    mgmt_minting = _management_client(ctx, api_endpoint, minting_stage)
    mgmt_sibling = _management_client(ctx, api_endpoint, sibling_stage)

    # precondition: the minting stage resolves its own connection
    via_minting = mgmt_minting.get_connection(ConnectionId=connection_id)
    connected_at = via_minting.get("ConnectedAt")
    source_ip = via_minting.get("Identity", {}).get("SourceIp")
    assert (
        isinstance(connected_at, datetime.datetime)
        and isinstance(source_ip, str)
        and source_ip
    ), (
        f"GetConnection through the minting stage {minting_stage!r} for {connection_id!r} must "
        f"report ConnectedAt and Identity.SourceIp for the cross-stage comparison below, but "
        f"returned {via_minting!r}"
    )

    # readiness AND evidence: the sibling stage reaches the connection store, answering Gone for
    # an absent id rather than the ForbiddenException an undeployed stage segment produces.
    probe_id = _WELL_FORMED_UNKNOWN
    absent = _poll_until(
        lambda: _absent_connection_outcome(mgmt_sibling, probe_id),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=5.0,
        description=(
            f"stage {sibling_stage!r} to stop answering ForbiddenException while its deployment "
            f"propagates"
        ),
        ctx=ctx,
    )
    _assert_gone(
        absent,
        f"GetConnection through the sibling stage {sibling_stage!r} for the absent well-formed id "
        f"{probe_id!r}, which shows the sibling stage performs a connection lookup instead of "
        f"refusing the endpoint,",
    )

    # the sibling stage resolves the SAME connection record, not a coincidental second one
    via_sibling = mgmt_sibling.get_connection(ConnectionId=connection_id)
    status = via_sibling["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, (
        f"GetConnection through the sibling stage {sibling_stage!r} for {connection_id!r} was "
        f"served with HTTP {status!r}; real AWS answers 200"
    )
    sibling_connected_at = via_sibling.get("ConnectedAt")
    assert sibling_connected_at == connected_at, (
        f"GetConnection for connection {connection_id!r} reported ConnectedAt "
        f"{sibling_connected_at!r} through stage {sibling_stage!r} but "
        f"{connected_at!r} through stage {minting_stage!r}; both stages serve one deployment of "
        f"one API and must read the same connection record, so the stage segment does not select "
        f"a connection namespace"
    )
    sibling_source_ip = via_sibling.get("Identity", {}).get("SourceIp")
    assert sibling_source_ip == source_ip, (
        f"GetConnection reported Identity.SourceIp {sibling_source_ip!r} through stage "
        f"{sibling_stage!r} but {source_ip!r} through stage {minting_stage!r} for the same "
        f"connection id"
    )

    # delivery is attributable: the payload is pushed through the sibling stage and read off the
    # socket that was opened through the minting stage.
    pushed = json.dumps({"oob": ctx.unique_name("sim2real-behav-msg-")})
    posted = mgmt_sibling.post_to_connection(ConnectionId=connection_id, Data=pushed.encode())
    status = posted["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, (
        f"PostToConnection through the sibling stage {sibling_stage!r} for {connection_id!r} was "
        f"served with HTTP {status!r}; real AWS answers 200"
    )
    opcode, delivered = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x1, (
        f"expected the payload pushed through stage {sibling_stage!r} as a text frame on the "
        f"socket opened through stage {minting_stage!r}, got opcode {opcode:#x} with "
        f"{delivered[:120]!r}"
    )
    received = delivered.decode("utf-8", "replace")
    assert received == pushed, (
        f"PostToConnection through stage {sibling_stage!r} returned 200 but the client on the "
        f"{minting_stage!r} socket received {delivered!r}, not the {len(pushed)}-byte payload "
        f"{pushed!r}"
    )

    # the sibling stage can also terminate a connection the other stage minted
    deleted = mgmt_sibling.delete_connection(ConnectionId=connection_id)
    status = deleted["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 204, (
        f"DeleteConnection through the sibling stage {sibling_stage!r} for {connection_id!r} was "
        f"served with HTTP {status!r}; real AWS answers 204"
    )
    opcode, close_payload = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x8, (
        f"DeleteConnection through stage {sibling_stage!r} did not close the socket opened "
        f"through stage {minting_stage!r}: the next frame had opcode {opcode:#x} with payload "
        f"{close_payload[:120]!r}"
    )
    close_code = _close_code(close_payload, f"DeleteConnection through stage {sibling_stage!r}")
    assert close_code == 1000, (
        f"DeleteConnection through stage {sibling_stage!r} closed the socket with WebSocket "
        f"status {close_code!r} and reason {close_payload[2:].decode('utf-8', 'replace')!r}; "
        f"real AWS closes a deleted connection with 1000 (normal closure)"
    )
    # the record is gone for the minting stage too: one connection store, not one per stage.
    # Probed BEFORE the client closes its own socket, so the only cause of the refusal below is
    # the sibling stage's DeleteConnection and not a client-initiated disconnect.
    _assert_gone(
        _refusal(
            lambda: mgmt_minting.post_to_connection(
                ConnectionId=connection_id, Data=b"after-sibling-delete"
            ),
            f"real AWS refuses PostToConnection through {minting_stage!r} once stage "
            f"{sibling_stage!r} deleted the connection",
        ),
        f"PostToConnection through the minting stage {minting_stage!r} after stage "
        f"{sibling_stage!r} deleted the connection, whose deletion removed the one record both "
        f"stages read,",
    )
    _assert_gone(
        _refusal(
            lambda: mgmt_minting.get_connection(ConnectionId=connection_id),
            f"real AWS refuses GetConnection through {minting_stage!r} once stage "
            f"{sibling_stage!r} deleted the connection",
        ),
        f"GetConnection through the minting stage {minting_stage!r} after stage "
        f"{sibling_stage!r} deleted the connection",
    )
    _ws_close(sock)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
