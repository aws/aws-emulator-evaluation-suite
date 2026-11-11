"""manage-connections-denial-precedes-connection-lookup."""
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

CHECK = "manage-connections-denial-precedes-connection-lookup"
GROUP = "overly-permissive"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: Error codes a cleanup callback treats as "already deleted".
_MISSING = ("ResourceNotFoundException", "NotFoundException", "NoSuchEntity")
_UNRECOGNISED_TOKEN = ("UnrecognizedClientException", "InvalidClientTokenId")

#: The connection id is the one thing a WebSocket client cannot know up front, and `$default`
#: echoing it back over the socket is the only way to learn it without a side-channel data store.
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

#: Not a connection id in any shape: the space makes it fail validation before any lookup, and
#: the refusal message echoes it verbatim.
_MALFORMED_ID = "not a connection id"

#: A stage segment this check creates no stage for: the only stage it deploys is `dev`, so this
#: name cannot resolve and needs no resource of its own.
_UNDEPLOYED_STAGE = "nodeploy"

#: A well-formed connection id that no live socket owns. Base64 of 11 bytes, the shape API
#: Gateway mints; a well-formed id that reaches the connection store and answers GoneException.
_WELL_FORMED_UNKNOWN = "Fabc1cWIPHcCJ7A="


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


def _management_client(ctx, api_endpoint, stage, creds=None):
    kwargs = {"creds": creds} if creds is not None else {}
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
        **kwargs,
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


def _unprivileged_identity(ctx, account):
    """Credentials for a fresh role carrying NO permission policy, plus the session's ARN.

    The role exists only to be a caller the service has never granted
    `execute-api:ManageConnections`. Its session ARN is read back from STS so the refusal message
    can be rebuilt at runtime without assuming an account, a role name or a session name.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-behav-noperm-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    def _assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav-noperm")
        except ClientError as exc:
            # The trust policy is not yet propagated; bounded retry, not a sleep. Any other
            # refusal is a real failure and must not be retried away.
            if exc.response.get("Error", {}).get("Code") == "AccessDenied":
                return None
            raise

    assumed = _poll_until(
        _assume,
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=4.0,
        description=f"role {role_name} assumable once its trust policy propagated",
        ctx=ctx,
    )
    creds = assumed["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }, assumed["AssumedRoleUser"]["Arn"]


def _denial_message(ctx, caller, acct, api_id, stage, method):
    """The refusal real AWS sends an unauthorised ManageConnections caller, built at runtime.

    AWS masks all but the last four digits of the account and names the route TEMPLATE
    `@connections/{connectionId}`, never the connection id the caller passed. That templating is
    exactly why the message cannot distinguish a live connection from an absent one.
    """
    masked_account = "*" * 8 + acct[-4:]
    return (
        f"User: {caller} is not authorized to perform: execute-api:ManageConnections on "
        f"resource: arn:aws:execute-api:{ctx.region}:{masked_account}:{api_id}/{stage}/{method}/"
        f"@connections/{{connectionId}} because no identity-based policy allows the "
        f"execute-api:ManageConnections action"
    )


def _resolved_connection(mgmt, connection_id):
    """The GetConnection response for ``connection_id``, or None while the stage's deployment has
    not propagated and the endpoint still answers ForbiddenException."""
    try:
        return mgmt.get_connection(ConnectionId=connection_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ForbiddenException":
            return None
        raise


def _refused_operation(ctx, client, method, connection_id, expectation, timeout_s=30.0):
    """The refusal of one @connections operation, ``method`` naming its HTTP verb.

    A freshly assumed session can be answered as an unrecognised token for a few seconds after
    STS issues it, so ONLY those two codes are retried; any other refusal is returned at once and
    an unexpected success raises.
    """
    def call():
        if method == "GET":
            return client.get_connection(ConnectionId=connection_id)
        if method == "POST":
            return client.post_to_connection(ConnectionId=connection_id, Data=b"probe")
        return client.delete_connection(ConnectionId=connection_id)

    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    outcome = None
    while True:
        outcome = _refusal(call, expectation)
        if outcome[0] not in _UNRECOGNISED_TOKEN:
            return outcome
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"{expectation}: the run budget ended first; not graded")
    return outcome


def _assert_refused(outcome, want_code, want_status, what):
    code, message, status = outcome
    assert code == want_code, (
        f"{what} returned {code!r} with message {message!r} and HTTP {status!r}; real AWS "
        f"answers {want_code!r} (HTTP {want_status})"
    )
    assert status == want_status, (
        f"{what}: the {code} arrived with HTTP {status!r}; real AWS answers {want_status}"
    )
    return outcome


@tags("axis:rejection", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Refusals are ordered: stage resolution (ForbiddenException, 403), connection-id shape
    (BadRequestException, 400), ManageConnections authorisation (AccessDeniedException, 403), then
    connection lookup (GoneException, 410); the authorisation 403 is no existence oracle.
    """
    account = ctx.account
    stage = "dev"
    role_arn = _lambda_role(ctx, account)
    fn = _create_function(ctx, role_arn)
    api_id, _deployment, api_endpoint = _deploy_websocket_api(ctx, account, fn, (stage,))

    sock = _open_socket(ctx, api_endpoint, stage, label="live")

    # the client learns its own server-minted id off the socket
    live_id = _learn_connection_id(sock)

    mgmt = _management_client(ctx, api_endpoint, stage)

    # precondition: this connection is live and the privileged caller can resolve it, so a
    # refusal below is never explained by a dead connection. Polled because a freshly created
    # stage answers ForbiddenException for a few seconds while its deployment propagates.
    described = _poll_until(
        lambda: _resolved_connection(mgmt, live_id),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=5.0,
        description=(
            f"stage {stage!r} to resolve the live connection while its deployment propagates"
        ),
        ctx=ctx,
    )
    assert isinstance(described.get("ConnectedAt"), datetime.datetime), (
        f"GetConnection must report ConnectedAt for the connection {live_id!r} this check is "
        f"holding open; without a resolvable live connection the comparison against an absent "
        f"one proves nothing"
    )

    absent_id = _WELL_FORMED_UNKNOWN

    # rung 3, privileged: an authorised caller DOES get an existence signal for an absent id.
    for method in ("GET", "POST", "DELETE"):
        what = (
            f"as an authorised caller, {method} @connections for the absent well-formed id "
            f"{absent_id!r}, which reaches the connection lookup,"
        )
        _code, message, _status = _assert_refused(
            _refused_operation(ctx, mgmt, method, absent_id, f"real AWS refuses {what}"),
            "GoneException",
            410,
            what,
        )
        assert message == "", (
            f"GoneException from {method} @connections carried message {message!r}; real AWS "
            f"sends an empty message for this refusal"
        )

    unprivileged_creds, caller = _unprivileged_identity(ctx, account)
    mgmt_unprivileged = _management_client(ctx, api_endpoint, stage, creds=unprivileged_creds)

    # rung 2: the SAME absent id, from a caller with no grant, is refused for authorisation
    # instead of for non-existence -- so authorisation is decided before the lookup.
    unprivileged_absent = {}
    for method in ("GET", "POST", "DELETE"):
        what = (
            f"without execute-api:ManageConnections, {method} @connections for the absent id "
            f"{absent_id!r}, which an authorised caller saw refused as 'GoneException', because "
            f"authorisation is evaluated before the connection is looked up,"
        )
        _code, message, _status = _assert_refused(
            _refused_operation(ctx, mgmt_unprivileged, method, absent_id, f"real AWS refuses {what}"),
            "AccessDeniedException",
            403,
            what,
        )
        unprivileged_absent[method] = message
        want = _denial_message(ctx, caller, account, api_id, stage, method)
        assert message == want, (
            f"expected the refusal message {want!r} for {method} @connections, got {message!r}"
        )

    # rung 2, the decisive comparison: a LIVE connection id yields the byte-identical refusal for
    # every operation, so the refusal carries no information about whether the connection exists.
    # DELETE runs last and is refused like the others; the delivery at the end of this check is
    # what shows the denied DELETE removed nothing.
    for method in ("GET", "POST", "DELETE"):
        what = (
            f"without execute-api:ManageConnections, {method} @connections for the LIVE "
            f"connection {live_id!r}"
        )
        _code, message, _status = _assert_refused(
            _refused_operation(ctx, mgmt_unprivileged, method, live_id, f"real AWS refuses {what}"),
            "AccessDeniedException",
            403,
            what,
        )
        assert message == unprivileged_absent[method], (
            f"{method} @connections refused the LIVE connection with {message!r} but the absent "
            f"connection with {unprivileged_absent[method]!r}; real AWS sends the identical "
            f"message for both because it names the route template @connections/{{connectionId}} "
            f"rather than the id, so an unauthorised caller cannot use the refusal to learn "
            f"whether a connection exists"
        )

    # rung 1: shape is validated before authorisation -- the unauthorised caller gets 400, not 403
    what = (
        f"without execute-api:ManageConnections, GET @connections for the malformed id "
        f"{_MALFORMED_ID!r}, which the same caller would see refused as 'AccessDeniedException' "
        f"for a well-formed id, because the connection id is validated before authorisation,"
    )
    _code, message, _status = _assert_refused(
        _refusal(
            lambda: mgmt_unprivileged.get_connection(ConnectionId=_MALFORMED_ID),
            f"real AWS refuses {what}",
        ),
        "BadRequestException",
        400,
        what,
    )
    assert message == f"Invalid connectionId: {_MALFORMED_ID}", (
        f"expected the refusal message 'Invalid connectionId: {_MALFORMED_ID}', got {message!r}"
    )

    # rung 0: the stage is resolved before the id's shape is validated. The SAME authorised caller
    # -- the one whose absent-id lookups above reached GoneException, so it demonstrably holds
    # execute-api:ManageConnections -- sending the SAME malformed id to a stage segment no stage
    # was created for is refused for the stage, not for the id and not for authorisation.
    mgmt_undeployed = _management_client(ctx, api_endpoint, _UNDEPLOYED_STAGE)
    what = (
        f"GET @connections for the malformed id {_MALFORMED_ID!r} on the stage segment "
        f"{_UNDEPLOYED_STAGE!r}, which no stage was created for and where this same caller got "
        f"'BadRequestException' (HTTP 400) for this same id on the deployed stage {stage!r}, "
        f"because the stage is resolved before the connection id's shape is validated,"
    )
    _code, forbidden_message, _status = _assert_refused(
        _refusal(
            lambda: mgmt_undeployed.get_connection(ConnectionId=_MALFORMED_ID),
            f"real AWS refuses {what}",
        ),
        "ForbiddenException",
        403,
        what,
    )
    assert forbidden_message == "Forbidden", (
        f"expected the refusal message 'Forbidden' for the unresolvable stage segment "
        f"{_UNDEPLOYED_STAGE!r}, got {forbidden_message!r}"
    )

    # control: the connection was reachable throughout -- including after the denied DELETE --
    # so every 403 above is about authorisation or stage resolution and not about a connection
    # that had quietly died, and none of the denied calls touched it. The denied POST's payload
    # must not have been delivered either: the very next message is the control payload.
    pushed = json.dumps({"control": ctx.unique_name("sim2real-behav-msg-")})
    mgmt.post_to_connection(ConnectionId=live_id, Data=pushed.encode())
    opcode, delivered = _ws_recv_frame(sock, timeout_s=60.0)
    assert opcode == 0x1, (
        f"expected the control payload as a text frame, got opcode {opcode:#x} with "
        f"{delivered[:120]!r}"
    )
    received = delivered.decode("utf-8", "replace")
    assert received == pushed, (
        f"the authorised control PostToConnection returned 200 but the client received "
        f"{delivered!r}, not the {len(pushed)}-byte payload {pushed!r}; the connection the "
        f"denials were measured against must still have been reachable"
    )
    _ws_close(sock)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
