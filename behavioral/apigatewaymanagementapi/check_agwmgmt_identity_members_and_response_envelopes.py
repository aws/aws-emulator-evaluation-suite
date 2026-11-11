"""agwmgmt-identity-members-and-response-envelopes."""
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

CHECK = "agwmgmt-identity-members-and-response-envelopes"
GROUP = "websocket-dataplane"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: Error codes a cleanup callback treats as "already deleted".
_MISSING = ("ResourceNotFoundException", "NotFoundException", "NoSuchEntity")

#: The exact User-Agent the positive-control socket sends in its handshake. Its only job is to be
#: a value the service could not have invented, so that the member's ABSENCE on the bare socket is
#: read against a socket where the same member is PRESENT.
_CONTROL_USER_AGENT = "sim2real-behav-agent/1.0 (measurement)"

#: `$default` echoes the caller its own connection id plus what the integration event reports
#: about the caller's identity. The id is the only way a WebSocket client can learn the
#: server-minted value it must address itself with, and echoing `identity` alongside it gives the
#: GetConnection comparison a second, independent view of the same socket without routing
#: anything through a data store.
_HANDLER = """
import json
import boto3


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    cid = rc.get("connectionId")
    endpoint = "https://" + rc.get("domainName") + "/" + rc.get("stage")
    client = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint)
    if route in ("$connect", "$disconnect"):
        return {"statusCode": 200}
    identity = rc.get("identity") or {}
    client.post_to_connection(
        ConnectionId=cid,
        Data=json.dumps(
            {
                "connectionId": cid,
                "sourceIp": identity.get("sourceIp"),
                "userAgent": identity.get("userAgent"),
            }
        ).encode(),
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


def _ws_connect(ctx, api_endpoint, stage, user_agent=None, timeout_s=20.0):
    """An RFC 6455 handshake over a stdlib socket; returns (socket, status line).

    ``user_agent`` of None sends NO User-Agent header at all; a string sends it verbatim.
    """
    use_tls, host, port, http_host, path = _ws_target(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    try:
        if use_tls:
            sock = _ssl_context(ctx.http_verify).wrap_socket(sock, server_hostname=http_host)
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {http_host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}",
            "Sec-WebSocket-Version: 13",
        ]
        if user_agent is not None:
            lines.append(f"User-Agent: {user_agent}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
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


def _ws_upgraded(ctx, api_endpoint, stage, user_agent=None):
    """A socket that completed the 101 upgrade, or None while the stage is still settling.

    A freshly created stage answers 403 for a few seconds; that is a deploy delay, not a
    fidelity signal, so it is polled rather than asserted. A TLS verification failure is not:
    it never resolves by retrying, so it propagates instead of being read as "still settling".
    """
    try:
        sock, status = _ws_connect(ctx, api_endpoint, stage, user_agent=user_agent)
    except ssl.SSLError:
        raise
    except OSError:
        return None
    if " 101 " in status:
        return sock
    _ws_close(sock)
    return None


def _open_socket(ctx, api_endpoint, stage, user_agent=None, label="client"):
    """An upgraded socket whose close is registered for cleanup."""
    sock = _poll_until(
        lambda: _ws_upgraded(ctx, api_endpoint, stage, user_agent=user_agent),
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
    """No byte of a new frame arrived before the deadline."""


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


def _ws_recv_frame(sock, timeout_s=60.0):
    """(opcode, payload) of the next complete data message or a CLOSE frame.

    PINGs are answered and PONGs skipped; a fragmented message is joined up to its FIN frame.
    """
    deadline = time.monotonic() + timeout_s
    opcode, parts = None, []
    while True:
        try:
            b1, b2 = _ws_recv_exact(sock, 2, deadline, frame_start=True)
        except _Quiet:
            if parts:
                raise AssertionError(
                    f"a fragmented WebSocket message did not complete within {timeout_s}s"
                ) from None
            raise AssertionError(f"no WebSocket frame arrived within {timeout_s}s") from None
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


def _management_client(ctx, api_endpoint, stage):
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _whoami(sock):
    """What the `$default` integration event reports about ``sock``, read back off the socket."""
    _ws_send_text(sock, json.dumps({"action": "whoami"}))
    opcode, payload = _ws_recv_frame(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"expected a text frame carrying the connection id, got opcode {opcode:#x} with "
        f"payload {payload[:120]!r}"
    )
    return json.loads(payload)


def _learn_connection_id(sock):
    """The server-minted id for ``sock``, read back off the socket through the `$default` route."""
    echo = _whoami(sock)
    connection_id = echo.get("connectionId")
    assert connection_id, f"the $default route echoed no connection id: {echo!r}"
    return connection_id


def _envelope_recorder(client):
    """Per-operation (status, body) records off botocore's `after-call` event.

    The modelled shapes carry nothing about the HTTP envelope, so the status line and the body
    bytes of a SUCCESSFUL management call are invisible to a check that only looks at the parsed
    result. This records both, which is the only way to see a 204 with an empty body as something
    other than a 200.
    """
    seen = {}

    def _hook(http_response=None, model=None, **kwargs):
        name = getattr(model, "name", None)
        if http_response is None or not isinstance(name, str):
            return
        try:
            record = (getattr(http_response, "status_code", None), http_response.content)
        except Exception as exc:  # noqa: BLE001 - an unreadable envelope is graded, not raised
            record = (getattr(http_response, "status_code", None), exc)
        seen.setdefault(name, []).append(record)

    client.meta.events.register("after-call", _hook)
    return seen


def _enveloped(seen, operation, fn, expectation):
    """(parsed result, HTTP status, body bytes) of ONE served call, attributed to that call.

    The envelope is the record this very call appended, not the operation's latest record, so a
    status or body can never be credited to a different connection's request.
    """
    before = len(seen.get(operation) or [])
    result = fn()
    records = seen.get(operation) or []
    assert len(records) == before + 1, (
        f"{expectation}; exactly one HTTP envelope must be recorded for this {operation} call, "
        f"but the recorder went from {before} to {len(records)} records for it"
    )
    status, body = records[-1]
    assert isinstance(status, int) and not isinstance(status, bool), (
        f"{expectation}; the {operation} response must carry an integer HTTP status, but it "
        f"carried {status!r}"
    )
    assert isinstance(body, bytes), (
        f"{expectation}; the {operation} response body must be readable bytes, but reading it "
        f"gave {body!r}"
    )
    return result, status, body


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """GetConnection omits Identity.UserAgent for a client that sent no such header and reports a
    SourceIp equal to the integration event's; PostToConnection answers 200, GetConnection 200
    with a body and DeleteConnection 204.
    """
    account = ctx.account
    stage = "dev"

    role_arn = _lambda_role(ctx, account)
    fn = _create_function(ctx, role_arn)
    _api_id, _deployment, api_endpoint = _deploy_websocket_api(ctx, account, fn, (stage,))

    mgmt = _management_client(ctx, api_endpoint, stage)
    envelopes = _envelope_recorder(mgmt)

    # The positive control for the UserAgent member: identical in every respect to the bare
    # socket except that its handshake carries a User-Agent header.
    control = _open_socket(
        ctx, api_endpoint, stage, user_agent=_CONTROL_USER_AGENT, label="user-agent control"
    )
    control_echo = _whoami(control)
    control_id = control_echo.get("connectionId")

    # The subject: a raw socket that sends no User-Agent header at all.
    bare = _open_socket(ctx, api_endpoint, stage, label="bare")
    bare_echo = _whoami(bare)
    bare_id = bare_echo.get("connectionId")
    assert control_id and bare_id and control_id != bare_id, (
        f"the two sockets this check opened did not receive distinct connection ids: "
        f"control {control_id!r}, bare {bare_id!r}; every claim below attributes an observation "
        f"to one of them"
    )

    # Identity members
    bare_connection, bare_get_status, bare_get_body = _enveloped(
        envelopes,
        "GetConnection",
        lambda: mgmt.get_connection(ConnectionId=bare_id),
        f"real AWS resolves the live connection {bare_id!r} opened by a client that sent no "
        f"User-Agent header",
    )
    control_connection = mgmt.get_connection(ConnectionId=control_id)

    bare_identity = bare_connection.get("Identity")
    assert isinstance(bare_identity, dict) and bare_identity, (
        f"GetConnection for the live connection {bare_id!r} must report a populated Identity; "
        f"the absence claim below is only meaningful against one, but it reported "
        f"{bare_identity!r}"
    )

    # Positive control, and the reason the absence below is not vacuous: the SAME operation on a
    # socket that DID send the header reports the member, verbatim.
    control_user_agent = control_connection.get("Identity", {}).get("UserAgent")
    assert control_user_agent == _CONTROL_USER_AGENT, (
        f"GetConnection for the control connection {control_id!r}, whose handshake carried "
        f"'User-Agent: {_CONTROL_USER_AGENT}', reported Identity.UserAgent "
        f"{control_user_agent!r}; real AWS records the handshake header verbatim, and without "
        f"that the absence of the member on the bare connection would say nothing about the "
        f"header"
    )
    assert control_echo.get("userAgent") == _CONTROL_USER_AGENT, (
        f"the $default integration event for the control connection {control_id!r} reported "
        f"userAgent {control_echo.get('userAgent')!r} rather than the header it sent, "
        f"{_CONTROL_USER_AGENT!r}; the integration event and the management API read the same "
        f"handshake"
    )

    # The claim: no UserAgent member for a client that sent no User-Agent header. The other
    # members ARE present on this very response, so this is not an empty Identity passing.
    for member in ("ConnectedAt", "LastActiveAt"):
        assert isinstance(bare_connection.get(member), datetime.datetime), (
            f"GetConnection for the bare connection {bare_id!r} must report {member}; the "
            f"member-level absence claim requires a response that is otherwise fully populated"
        )
    bare_source_ip = bare_identity.get("SourceIp")
    assert isinstance(bare_source_ip, str) and bare_source_ip, (
        f"GetConnection for the bare connection {bare_id!r} must report Identity.SourceIp; an "
        f"Identity that is empty for every member would satisfy the UserAgent absence below for "
        f"the wrong reason"
    )
    assert "UserAgent" not in bare_identity, (
        f"GetConnection for the connection {bare_id!r}, whose handshake carried NO User-Agent "
        f"header, reported Identity.UserAgent {bare_identity.get('UserAgent')!r}; real AWS omits "
        f"the member entirely for such a client -- it does not synthesise a value -- even though "
        f"`Identity.UserAgent` is `smithy.api#required` in the model. The full Identity was "
        f"{bare_identity!r}, and the same operation against the control connection "
        f"{control_id!r} did report {_CONTROL_USER_AGENT!r}, so the member is reported when the "
        f"client sends one"
    )
    assert bare_echo.get("userAgent") is None, (
        f"the $default integration event for the bare connection {bare_id!r} reported userAgent "
        f"{bare_echo.get('userAgent')!r}; real AWS reports no value for a client that sent no "
        f"User-Agent header (the handler echoes an absent and a null member alike, so this reads "
        f"only that no value was invented), and the control connection's event reported its "
        f"header, so the field is populated when there is something to populate it with"
    )

    # Identity.SourceIp is the client's address as the service saw it: it equals what the
    # integration event independently reported for the same socket, and it parses as an address.
    assert bare_source_ip == bare_echo.get("sourceIp"), (
        f"GetConnection reported Identity.SourceIp {bare_source_ip!r} for connection {bare_id!r} "
        f"while the $default integration event reported sourceIp {bare_echo.get('sourceIp')!r} "
        f"for the same socket; both describe the client that opened it and real AWS reports the "
        f"identical value through the two paths"
    )

    # The bare connection's own GetConnection envelope is the positive control for the two
    # empty-body claims below: it shows the recorder does capture a body when the service sends one.
    assert bare_get_status == 200, (
        f"GetConnection for the live connection {bare_id!r} answered HTTP {bare_get_status}; "
        f"real AWS answers 200"
    )
    assert bare_get_body, (
        f"GetConnection for the live connection {bare_id!r} answered HTTP {bare_get_status} with "
        f"a zero-length body; real AWS sends the connection's JSON representation, and without a "
        f"body here the empty-body assertions below would hold for any response at all"
    )
    get_document = json.loads(bare_get_body)
    assert get_document.get("identity") is not None, (
        f"GetConnection's response body {bare_get_body[:200]!r} for the bare connection "
        f"{bare_id!r} carries no `identity` member; the parsed Identity above is read out of "
        f"this body"
    )

    # envelopes and delivery
    pushed = json.dumps({"oob": ctx.unique_name("sim2real-behav-msg-")})
    _result, post_status, post_body = _enveloped(
        envelopes,
        "PostToConnection",
        lambda: mgmt.post_to_connection(ConnectionId=bare_id, Data=pushed.encode()),
        f"real AWS accepts PostToConnection for the live connection {bare_id!r}",
    )
    assert post_status == 200, (
        f"PostToConnection for the live connection {bare_id!r} answered HTTP {post_status} with "
        f"body {post_body[:200]!r}; real AWS answers 200 for a delivered payload, and reserves "
        f"204 for DeleteConnection"
    )
    assert post_body == b"", (
        f"PostToConnection answered HTTP {post_status} with the {len(post_body)}-byte body "
        f"{post_body[:200]!r}; real AWS sends no body, while GetConnection on the same endpoint "
        f"sent {len(bare_get_body)} bytes"
    )
    opcode, delivered = _ws_recv_frame(bare, timeout_s=60.0)
    assert opcode == 0x1, (
        f"expected the pushed payload as a text frame on the bare socket, got opcode "
        f"{opcode:#x} with {delivered[:120]!r}"
    )
    assert delivered == pushed.encode(), (
        f"PostToConnection answered HTTP {post_status} but the client received {delivered!r}, "
        f"not the {len(pushed)}-byte payload {pushed!r}"
    )

    _result, delete_status, delete_body = _enveloped(
        envelopes,
        "DeleteConnection",
        lambda: mgmt.delete_connection(ConnectionId=bare_id),
        f"real AWS accepts DeleteConnection for the live connection {bare_id!r}",
    )
    assert delete_status == 204, (
        f"DeleteConnection for the live connection {bare_id!r} answered HTTP {delete_status}; "
        f"real AWS answers 204 No Content, not the 200 that PostToConnection answers on the same "
        f"endpoint. The operation parses to an empty structure either way, so the status line is "
        f"the only place the difference is visible"
    )
    assert delete_body == b"", (
        f"DeleteConnection answered HTTP {delete_status} with the {len(delete_body)}-byte body "
        f"{delete_body[:200]!r}; real AWS sends no body with a 204, while GetConnection on the "
        f"same endpoint sent {len(bare_get_body)} bytes"
    )

    # Nothing on the untouched control connection: deleting one connection must not disturb
    # another. Read by ORDERING rather than a quiet window: any stray frame here would corrupt
    # the whoami reply the next read expects.
    control_after = _learn_connection_id(control)
    assert control_after == control_id, (
        f"the untouched control socket echoed connection id {control_after!r} after connection "
        f"{bare_id!r} was deleted, but it was minted as {control_id!r}; deleting one connection "
        f"must leave another connection serving under its own id"
    )
    control_still_live = mgmt.get_connection(ConnectionId=control_id)
    connected_before = control_connection.get("ConnectedAt")
    connected_after = control_still_live.get("ConnectedAt")
    assert (
        isinstance(connected_before, datetime.datetime)
        and connected_after == connected_before
    ), (
        f"GetConnection for the untouched connection {control_id!r} now reports ConnectedAt "
        f"{connected_after!r}, but reported "
        f"{connected_before!r} before connection {bare_id!r} was deleted; "
        f"deleting one connection must leave another connection's record alone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
