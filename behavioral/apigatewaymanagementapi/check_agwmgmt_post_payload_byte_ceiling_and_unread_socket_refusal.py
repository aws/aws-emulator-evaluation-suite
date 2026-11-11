"""agwmgmt-post-payload-byte-ceiling-and-unread-socket-refusal."""
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

CHECK = "agwmgmt-post-payload-byte-ceiling-and-unread-socket-refusal"
GROUP = "data-plane"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: Error codes a cleanup callback treats as "already deleted".
_MISSING = ("ResourceNotFoundException", "NotFoundException", "NoSuchEntity")

#: The documented PostToConnection payload maximum.
_MAX_PAYLOAD_BYTES = 131072

#: A 3-code-point, 9-UTF-8-byte repeating unit, and tails for each possible byte remainder. Both
#: tables exist so a payload can be built to an EXACT byte length while its code-point count is
#: controlled independently -- which is what separates a byte ceiling from a character ceiling.
_UNIT = "\u00e9\u20ac\U0001f600"
_FILLER_BY_BYTES = {
    0: "",
    1: "a",
    2: "\u00e9",
    3: "\u20ac",
    4: "\U0001f600",
    5: "\u00e9\u20ac",
    6: "\u20ac\u20ac",
    7: "\u20ac\u00f1\u00e9",
    8: "\u00e9\u00e9\u00e9\u00e9",
}

#: Ceiling on the posts fired at an unread socket: 120 x 131072 bytes = 15 MiB, a ceiling far above
#: the client buffer AWS keeps for a connection that is not draining; the accepted count itself is
#: deliberately NOT pinned. A target that accepts all 120 without refusing has buffered 15 MiB for
#: a client reading nothing, which is the absence of back-pressure this check exists to find, so
#: exhausting the ceiling is reported as a mismatch.
#: A count rather than a wall-clock bound, because a time bound would grade request latency.
_UNREAD_POST_CEILING = 120

#: `$default` echoes the caller its own connection id. That is the only way a WebSocket client can
#: learn the server-minted id it needs to address itself with, and it keeps this check inside
#: apigatewaymanagementapi rather than routing the id through a data store.
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


class _Quiet(Exception):
    """No byte of a new message arrived before the deadline."""


def _ws_recv_exact(sock, n, deadline, frame_start=False):
    buf = b""
    while len(buf) < n:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            if frame_start and not buf:
                raise _Quiet() from None
            raise AssertionError(
                f"the socket stalled after {len(buf)} of {n} bytes of a WebSocket frame"
            ) from None
        if not chunk:
            raise AssertionError(f"the socket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


#: Bound on a reassembled message, eight times the largest this check provokes (131072 bytes), so
#: a corrupt length cannot make the reader allocate or wait for an absurd amount of data.
_MAX_MESSAGE_BYTES = 1 << 20


def _ws_recv_message(sock, timeout_s=60.0):
    """(opcode, payload) of the next message, reassembling continuation frames.

    The service splits a large payload across frames. PINGs are answered and PONGs skipped; a
    CLOSE frame comes back as (0x8, payload).
    """
    deadline = time.monotonic() + timeout_s
    opcode, payload = None, b""
    while True:
        try:
            b1, b2 = _ws_recv_exact(sock, 2, deadline, frame_start=opcode is None)
        except _Quiet:
            raise AssertionError(f"no WebSocket message arrived within {timeout_s}s") from None
        n = b2 & 0x7F
        if n == 126:
            n = int.from_bytes(_ws_recv_exact(sock, 2, deadline), "big")
        elif n == 127:
            n = int.from_bytes(_ws_recv_exact(sock, 8, deadline), "big")
        if len(payload) + n > _MAX_MESSAGE_BYTES:
            raise AssertionError(
                f"a WebSocket message grew past {_MAX_MESSAGE_BYTES} bytes, more than any message "
                f"this check provokes"
            )
        data = _ws_recv_exact(sock, n, deadline) if n else b""
        frame_opcode = b1 & 0x0F
        if frame_opcode == 0x9:
            sock.sendall(_ws_frame(0xA, data))
            continue
        if frame_opcode == 0xA:
            continue
        if frame_opcode == 0x8:
            return 0x8, data
        if opcode is None:
            opcode = frame_opcode
        payload += data
        if b1 & 0x80:
            return opcode, payload


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


def _management_client(ctx, api_endpoint, stage):
    # total_max_attempts counts the first try, unlike max_attempts under the legacy retry mode:
    # LimitExceededException/429 is a throttling error botocore otherwise retries on its own,
    # which would turn a refused post into a silently re-sent one.
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"total_max_attempts": 1}),
    )


def _learn_connection_id(sock):
    """The server-minted id for ``sock``, read back off the socket through the `$default` route."""
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_message(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"expected a text frame carrying the connection id, got opcode {opcode:#x} with "
        f"payload {payload[:120]!r}"
    )
    connection_id = json.loads(payload)["connectionId"]
    assert connection_id, f"the $default route echoed no connection id: {payload!r}"
    return connection_id


def _utf8_payload(n_bytes):
    """A deterministic, valid-UTF-8 string whose encoding is EXACTLY ``n_bytes`` bytes.

    Built from a 9-byte/3-code-point unit plus a remainder tail, so the byte length is exact while
    the code-point count follows from the construction rather than being equal to it. That is the
    whole point: two payloads one byte apart can be given the SAME code-point count, which no
    all-ASCII payload can do.
    """
    unit_bytes = len(_UNIT.encode())
    units, rest = divmod(n_bytes, unit_bytes)
    text = _UNIT * units + _FILLER_BY_BYTES[rest]
    assert len(text.encode()) == n_bytes, (
        f"the payload builder produced {len(text.encode())} bytes for a requested {n_bytes}; the "
        f"boundary comparison is meaningless unless the lengths are exact"
    )
    return text


def _ascii_payload(index, n_bytes=_MAX_PAYLOAD_BYTES):
    """A deterministic ``n_bytes``-byte payload that identifies itself by ``index``."""
    prefix = f"sim2real-behav-chunk-{index:06d}-"
    text = prefix + "x" * (n_bytes - len(prefix))
    assert len(text.encode()) == n_bytes, (
        f"the chunk builder produced {len(text.encode())} bytes for a requested {n_bytes}"
    )
    return text


def _post_until_refused(mgmt, connection_id, *, ceiling):
    """(accepted, refusal) after posting maximum-size payloads until the service refuses.

    The refusal is RETURNED rather than raised so that every property of it is asserted below;
    exhausting ``ceiling`` returns None, which the caller turns into an AssertionError naming the
    byte volume that was accepted.
    """
    accepted = 0
    for index in range(ceiling):
        try:
            mgmt.post_to_connection(
                ConnectionId=connection_id, Data=_ascii_payload(index).encode()
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return accepted, {
                "code": err.get("Code"),
                "message": err.get("Message", ""),
                "status": exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                "index": index,
            }
        accepted += 1
    return accepted, None


def _first_difference(delivered, expected):
    return next(
        (i for i, (a, b) in enumerate(zip(delivered, expected, strict=False)) if a != b),
        min(len(delivered), len(expected)),
    )


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
    """PostToConnection's 131072 ceiling counts bytes, not characters: of two payloads with equal
    code-point counts, 131072 bytes is delivered and 131073 refused with 413 and not delivered; a
    connection not draining its socket draws LimitExceededException (429), stays alive and drains.
    """
    account = ctx.account
    stage = "dev"

    role_arn = _lambda_role(ctx, account)
    fn = _create_function(ctx, role_arn)
    _api_id, _deployment, api_endpoint = _deploy_websocket_api(ctx, account, fn, (stage,))
    mgmt = _management_client(ctx, api_endpoint, stage)

    # the byte ceiling
    at_limit = _utf8_payload(_MAX_PAYLOAD_BYTES)
    over_limit = _utf8_payload(_MAX_PAYLOAD_BYTES + 1)
    assert len(at_limit) == len(over_limit), (
        f"the two boundary payloads carry {len(at_limit)} and {len(over_limit)} code points; the "
        f"claim is that the limit counts bytes rather than characters, which only one pair of "
        f"EQUAL code-point counts can show"
    )
    assert len(at_limit.encode()) + 1 == len(over_limit.encode()), (
        f"the two boundary payloads encode to {len(at_limit.encode())} and "
        f"{len(over_limit.encode())} bytes; they must differ by exactly one byte for the outcome "
        f"to be attributable to the byte ceiling"
    )

    boundary_socket = _open_socket(ctx, api_endpoint, stage, label="byte-boundary")
    boundary_id = _learn_connection_id(boundary_socket)

    mgmt.post_to_connection(ConnectionId=boundary_id, Data=at_limit.encode())
    opcode, delivered = _ws_recv_message(boundary_socket, timeout_s=120.0)
    assert opcode == 0x1, (
        f"expected the {_MAX_PAYLOAD_BYTES}-byte payload as a text message, got opcode "
        f"{opcode:#x} with {delivered[:120]!r}"
    )
    expected_bytes = at_limit.encode()
    assert delivered == expected_bytes, (
        f"PostToConnection accepted the {_MAX_PAYLOAD_BYTES}-byte payload but the client received "
        f"{len(delivered)} bytes that differ from what was sent; first difference at byte "
        f"{_first_difference(delivered, expected_bytes)}"
    )

    code, message, status = _refusal(
        lambda: mgmt.post_to_connection(ConnectionId=boundary_id, Data=over_limit.encode()),
        f"real AWS refuses a PostToConnection payload of {_MAX_PAYLOAD_BYTES + 1} bytes for the "
        f"live connection {boundary_id!r}, even though it carries exactly as many code points "
        f"({len(over_limit)}) as the {_MAX_PAYLOAD_BYTES}-byte payload it just accepted and "
        f"delivered",
    )
    assert code == "413", (
        f"the {_MAX_PAYLOAD_BYTES + 1}-byte payload was refused with code {code!r} and message "
        f"{message!r}; real AWS answers a bare HTTP 413 with no `x-amzn-errortype` header, which "
        f"botocore surfaces as the literal Code '413' rather than the modelled "
        f"`PayloadTooLargeException`"
    )
    assert message == "", (
        f"the {_MAX_PAYLOAD_BYTES + 1}-byte refusal carried message {message!r}; real AWS sends "
        f"no message for it"
    )
    assert status == 413, (
        f"the {_MAX_PAYLOAD_BYTES + 1}-byte payload was refused with HTTP {status!r}; real AWS "
        f"answers 413"
    )
    # Non-delivery is read by ORDERING rather than a quiet window: delivery on one connection is
    # in order, so if the refused payload had been buffered it would arrive before this one, and
    # the next frame actually read is this liveness payload instead.
    liveness = json.dumps({"after-refusal": ctx.unique_name("sim2real-behav-msg-")})
    mgmt.post_to_connection(ConnectionId=boundary_id, Data=liveness.encode())
    opcode, after_refusal = _ws_recv_message(boundary_socket, timeout_s=60.0)
    assert (opcode, after_refusal) == (0x1, liveness.encode()), (
        f"after the {_MAX_PAYLOAD_BYTES + 1}-byte refusal the connection {boundary_id!r} received "
        f"opcode {opcode:#x} with {after_refusal[:120]!r} rather than the {len(liveness)}-byte "
        f"text payload {liveness!r} posted to it; delivery on one connection is in order, so a "
        f"refused payload reaching the client would have arrived as this message instead"
    )
    _ws_close(boundary_socket)

    # the unread socket
    # This socket's id is learned once, up front; from here it is never read until after the
    # refusal, which is the condition under test.
    unread_socket = _open_socket(ctx, api_endpoint, stage, label="unread")
    unread_id = _learn_connection_id(unread_socket)

    accepted, refusal = _post_until_refused(
        mgmt, unread_id, ceiling=_UNREAD_POST_CEILING
    )
    assert refusal is not None, (
        f"real AWS refuses further posts once a client stops draining its socket, but "
        f"{accepted} posts of {_MAX_PAYLOAD_BYTES} bytes "
        f"({accepted * _MAX_PAYLOAD_BYTES} bytes in total) were all accepted for the connection "
        f"{unread_id!r}, whose client read nothing after learning its id"
    )
    assert accepted >= 1, (
        f"the very first post to the connection {unread_id!r} was refused with "
        f"{refusal['code']!r}; the refusal under test is caused by payloads ALREADY buffered for "
        f"a client that is not reading, so at least one post must be accepted before it, and a "
        f"refusal on an empty buffer is a different behaviour"
    )
    assert refusal["code"] == "LimitExceededException", (
        f"post {refusal['index'] + 1} to the unread connection {unread_id!r}, after {accepted} "
        f"accepted posts ({accepted * _MAX_PAYLOAD_BYTES} buffered bytes), was refused with code "
        f"{refusal['code']!r} and message {refusal['message']!r}; real AWS answers "
        f"'LimitExceededException' when the client's buffer is full"
    )
    assert refusal["message"] == "Too Many Requests. WebSocket client buffer full", (
        f"the LimitExceededException for the unread connection {unread_id!r} carried message "
        f"{refusal['message']!r}; real AWS sends exactly 'Too Many Requests. WebSocket client "
        f"buffer full', which names the buffer rather than a request rate"
    )
    assert refusal["status"] == 429, (
        f"the LimitExceededException for the unread connection {unread_id!r} arrived with HTTP "
        f"{refusal['status']!r}; real AWS answers 429"
    )

    # The refusal is back-pressure, not a disconnect: the connection is still there.
    still_live = mgmt.get_connection(ConnectionId=unread_id)
    assert isinstance(still_live.get("ConnectedAt"), datetime.datetime), (
        f"GetConnection for the connection {unread_id!r} after the LimitExceededException must "
        f"report the live connection's ConnectedAt, but returned {still_live!r}"
    )

    # Every accepted post was really buffered, in order, and the refused one was not.
    for index in range(accepted):
        opcode, drained = _ws_recv_message(unread_socket, timeout_s=120.0)
        assert opcode == 0x1, (
            f"draining the unread connection {unread_id!r}: message {index + 1} of {accepted} "
            f"arrived with opcode {opcode:#x} and {len(drained)} bytes"
        )
        assert drained == _ascii_payload(index).encode(), (
            f"draining the unread connection {unread_id!r}: message {index + 1} of {accepted} "
            f"was {len(drained)} bytes starting {drained[:48]!r}, not the payload accepted at "
            f"position {index} starting {_ascii_payload(index).encode()[:48]!r}; every post real "
            f"AWS accepted is delivered once, in order, when the client drains"
        )
    # Recovery: the refusal is transient, and the connection takes traffic again once drained. Its
    # index differs from every earlier post, and absence of the refused payload is read by
    # ORDERING, not a quiet window: it is the very next message after the drain loop above, so a
    # late delivery of the refused payload would have arrived here instead of the recovery payload.
    recovery = _ascii_payload(_UNREAD_POST_CEILING + refusal["index"] + 1)
    mgmt.post_to_connection(ConnectionId=unread_id, Data=recovery.encode())
    opcode, recovered = _ws_recv_message(unread_socket, timeout_s=120.0)
    assert opcode == 0x1, (
        f"the post that followed the drain arrived on {unread_id!r} with opcode {opcode:#x} and "
        f"{len(recovered)} bytes"
    )
    assert recovered == recovery.encode(), (
        f"the post that followed the drain was accepted for {unread_id!r} but the client received "
        f"{len(recovered)} bytes starting {recovered[:48]!r} rather than the payload sent; the "
        f"post that was refused with {refusal['code']!r} must not have been buffered"
    )
    _ws_close(unread_socket)

    # the drained control
    # Same caller, same API, same stage, same payload size; this client reads each message
    # before the next post is sent. It must take strictly more posts than the unread socket did
    # without a single refusal, which attributes the refusal above to the undrained buffer rather
    # than to the NUMBER of posts, their size, or an account quota. The two legs are not paced
    # alike -- this one waits for each delivery -- so the control does not separate an unread
    # buffer from a burst-rate limit; the refusal's own message, which names the client buffer,
    # is what speaks to that.
    drained_socket = _open_socket(ctx, api_endpoint, stage, label="drained control")
    drained_id = _learn_connection_id(drained_socket)
    control_posts = accepted + 1
    for index in range(control_posts):
        payload = _ascii_payload(index)
        mgmt.post_to_connection(ConnectionId=drained_id, Data=payload.encode())
        opcode, echoed = _ws_recv_message(drained_socket, timeout_s=120.0)
        assert opcode == 0x1, (
            f"the drained control connection {drained_id!r} received message {index + 1} with "
            f"opcode {opcode:#x} and {len(echoed)} bytes"
        )
        assert echoed == payload.encode(), (
            f"the drained control connection {drained_id!r} received {len(echoed)} bytes starting "
            f"{echoed[:48]!r} as message {index + 1}, not the payload posted at that position"
        )
    _ws_close(drained_socket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
