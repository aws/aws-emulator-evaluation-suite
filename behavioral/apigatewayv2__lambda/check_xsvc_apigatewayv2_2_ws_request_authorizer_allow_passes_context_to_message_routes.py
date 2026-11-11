"""xsvc-apigatewayv2-2-ws-request-authorizer-allow-passes-context-to-message-routes."""

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

CHECK = "xsvc-apigatewayv2-2-ws-request-authorizer-allow-passes-context-to-message-routes"

GROUP = "websocket-authorizer"

SERVICES = ["apigatewayv2", "lambda"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c6",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A $connect REQUEST authorizer's Allow admits the handshake (101), and its principalId and
    context reach every later frame's Lambda as requestContext.authorizer; two connections with
    different tenants each see only their own context."""
    _api_id, api_endpoint, stage, fns = _authorized_api(ctx)

    tenants = {
        "a": ctx.unique_name("sim2real-tenant-a-"),
        "b": ctx.unique_name("sim2real-tenant-b-"),
    }
    socks = {}
    for k, tenant in tenants.items():
        socks[k] = _ws_open(
            ctx, api_endpoint, stage, {"token": "allow", "tenant": tenant, "marker": "m" + k}
        )
        _close_later(ctx, socks[k])

    # Interleave the two sockets so a context stored per API, or "last connection wins",
    # shows up as the wrong tenant.
    for round_no in (1, 2):
        for k in ("a", "b"):
            got = _ws_round_trip(
                socks[k], json.dumps({"action": "ping", "n": round_no}), timeout_s=45.0
            )
            assert got.get("fn") == "ping", f"ping should reach its Lambda; got {got!r}"
            auth = got.get("authorizer") or {}
            assert auth.get("tenant") == tenants[k], (
                f"connection {k!r} was authorized with tenant {tenants[k]!r}; frame {round_no} "
                f"saw requestContext.authorizer {auth!r}"
            )
            assert auth.get("decision") == "Allow", (
                f"the authorizer's context key 'decision' should read 'Allow'; got {auth!r}"
            )
            assert auth.get("principalId") == "sim2real-m" + k, (
                f"the authorizer's principalId should be 'sim2real-m{k}'; got {auth!r}"
            )


def _authorized_api(ctx):
    """A WebSocket API whose `$connect` route is guarded by a REQUEST authorizer Lambda with
    identity source `route.request.querystring.token` (token=allow => Allow policy, anything
    else => Deny), plus a two-way `ping` route. Returns (api_id, api_endpoint, stage, fns)."""
    account = _account_id(ctx)
    v2 = ctx.client("apigatewayv2")
    api_id, api_endpoint = _create_ws_api(ctx)
    role_arn = _create_role(ctx, _role_policy(ctx, api_id, account))
    fns = {
        key: _create_function(ctx, role_arn, key, api_id, account)
        for key in ("authorizer", "$connect", "ping")
    }
    authorizer_id = v2.create_authorizer(
        ApiId=api_id,
        Name=_xname(ctx, "authz"),
        AuthorizerType="REQUEST",
        AuthorizerUri=_integration_uri(ctx, fns["authorizer"]),
        IdentitySource=["route.request.querystring.token"],
    )["AuthorizerId"]
    _add_route(
        ctx,
        api_id,
        "$connect",
        fns["$connect"],
        two_way=False,
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )
    _add_route(ctx, api_id, "ping", fns["ping"], two_way=True)
    stage = _deploy(ctx, api_id)
    return api_id, api_endpoint, stage, fns


def _open_watcher(ctx, api_endpoint, stage, fns):
    """An ALLOWED connection that learns its own id over ping; the authorizer and $connect
    functions are then pointed at it. Returns (sock, watcher_id)."""
    sock = _ws_open(ctx, api_endpoint, stage, {"token": "allow", "marker": "watcher"})
    _close_later(ctx, sock)
    me = _ws_round_trip(sock, json.dumps({"action": "ping"}), timeout_s=45.0)
    watcher_id = me.get("connectionId")
    assert me.get("fn") == "ping" and watcher_id, (
        f"the watcher's ping should be answered by the ping Lambda with a connectionId; got {me!r}"
    )
    for key in ("authorizer", "$connect"):
        _set_watcher(ctx, fns[key], watcher_id)
    return sock, watcher_id


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


# One handler source, deployed as several DISTINCT functions that differ only in FN_TAG. A
# message route answers with a JSON echo of what the service handed it (two-way route, so the
# body travels back down the same socket). $connect / $disconnect / the authorizer cannot answer
# on their own socket, so once the check sets WATCHER they push the same record to a watcher
# connection through the management API instead.
_HANDLER = """
import json
import os

import boto3


def _notify(event, record):
    watcher = os.environ.get("WATCHER")
    if not watcher:
        return
    rc = event.get("requestContext") or {}
    host = rc.get("domainName")
    stage = rc.get("stage")
    last = None
    # Real AWS is always https; an emulator may front the management API over plain http.
    for scheme in ("https", "http"):
        client = boto3.client(
            "apigatewaymanagementapi",
            endpoint_url=scheme + "://" + host + "/" + stage,
        )
        try:
            client.post_to_connection(
                ConnectionId=watcher, Data=json.dumps(record).encode()
            )
            return
        except Exception as exc:  # noqa: BLE001 - scheme probe, re-raised below
            last = exc
    raise last


def _record(event):
    rc = event.get("requestContext") or {}
    qs = event.get("queryStringParameters") or {}
    return {
        "fn": os.environ["FN_TAG"],
        "routeKey": rc.get("routeKey"),
        "eventType": rc.get("eventType"),
        "connectionId": rc.get("connectionId"),
        "authorizer": rc.get("authorizer"),
        "marker": qs.get("marker"),
        "body": event.get("body"),
    }


def lambda_handler(event, context):
    if os.environ["FN_TAG"] == "authorizer":
        qs = event.get("queryStringParameters") or {}
        _notify(event, {"fn": "authorizer", "marker": qs.get("marker")})
        effect = "Allow" if qs.get("token") == "allow" else "Deny"
        return {
            "principalId": "sim2real-" + str(qs.get("marker")),
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": effect,
                        "Resource": event["methodArn"],
                    }
                ],
            },
            "context": {"tenant": str(qs.get("tenant")), "decision": effect},
        }
    record = _record(event)
    route = record["routeKey"]
    if route in ("$connect", "$disconnect"):
        _notify(event, record)
        return {"statusCode": 200}
    return {"statusCode": 200, "body": json.dumps(record)}
"""


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
    """Poll probe() until predicate(result) is truthy; return the final result."""
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


def _create_role(ctx, inline_policy):
    """One Lambda execution role shared by every function in the check. Returns its ARN."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return resp["Role"]["Arn"]


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, name):
    """delete_function leaves /aws/lambda/<fn>, and a late log flush can RECREATE it after one
    delete, so the reap re-deletes until the group stays gone over a bounded window."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    quiet = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and quiet < 3:
        try:
            logs.delete_log_group(logGroupName=group)
            quiet = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            quiet += 1
        time.sleep(2)
    if quiet < 3:
        raise RuntimeError(f"log group {group} kept reappearing")


def _role_policy(ctx, api_id, account):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:/aws/lambda/{_XSVC_PREFIX}*",
            },
            {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*",
            },
        ],
    }


def _create_function(ctx, role_arn, fn_tag, api_id, account):
    """One DISTINCT function (its own name and FN_TAG) from the shared handler, invokable by
    this API only. Retries through IAM role propagation, then waits for Active."""
    name = _xname(ctx, f"fn-{fn_tag.strip('$')}")
    lam = ctx.client("lambda")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(_HANDLER))
    # Registered BEFORE the create so LIFO runs it AFTER the delete_function below.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=15,
                MemorySize=128,
                Environment={"Variables": {"FN_TAG": fn_tag}},
                Tags=dict(_xsvc_resource_tags()),
            )
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "InvalidParameterValueException"
                and time.monotonic() < deadline
            ):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    lam.add_permission(
        FunctionName=name,
        StatementId="apigw-ws-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*",
    )
    return {"name": name, "arn": resp["FunctionArn"], "tag": fn_tag}


def _set_watcher(ctx, fn, watcher_id):
    """Point a $connect/$disconnect/authorizer function at the watcher connection, and wait
    until the new configuration is the one invocations get."""
    lam = ctx.client("lambda")
    lam.update_function_configuration(
        FunctionName=fn["name"],
        Environment={"Variables": {"FN_TAG": fn["tag"], "WATCHER": watcher_id}},
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn["name"]),
        lambda c: c.get("LastUpdateStatus") == "Successful"
        and (c.get("Environment") or {}).get("Variables", {}).get("WATCHER") == watcher_id,
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {fn['name']} configuration update applied",
    )


def _integration_uri(ctx, fn):
    return (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )


def _create_ws_api(ctx):
    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_xname(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_xsvc_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    return api_id, api_endpoint


def _add_route(ctx, api_id, route_key, fn, two_way, **route_kwargs):
    """A route whose target is its OWN Lambda proxy integration. A two-way route carries a
    `$default` route response, so the integration's body is returned to the client."""
    v2 = ctx.client("apigatewayv2")
    integration_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=_integration_uri(ctx, fn),
    )["IntegrationId"]
    kwargs = dict(
        ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration_id}"
    )
    if two_way:
        kwargs["RouteResponseSelectionExpression"] = "$default"
    kwargs.update(route_kwargs)
    route_id = v2.create_route(**kwargs)["RouteId"]
    if two_way:
        v2.create_route_response(
            ApiId=api_id, RouteId=route_id, RouteResponseKey="$default"
        )
    return route_id


def _deploy(ctx, api_id, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    deployment_id = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment_id)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return stage


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API stage,
    from ``ctx.stage_url``."""
    url = urllib.parse.urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _ws_handshake(ctx, api_endpoint, stage, query=None, timeout_s=20.0):
    """An RFC 6455 opening handshake over a stdlib socket. Returns (status, head, sock):
    `sock` is the open socket on a 101 and None (already closed) on anything else."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    if query:
        path = path + "?" + urllib.parse.urlencode(query)
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
    first = head.splitlines()[0] if head else ""
    parts = first.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
    if status != 101:
        try:
            sock.close()
        except OSError:
            pass
        return status, head, None
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    got_accept = [
        ln.split(":", 1)[1].strip()
        for ln in head.splitlines()
        if ln.lower().startswith("sec-websocket-accept:")
    ]
    assert got_accept == [accept], (
        f"101 upgrade carried no valid Sec-WebSocket-Accept for our key; head was {head!r}"
    )
    return status, head, sock


def _ws_open(ctx, api_endpoint, stage, query=None):
    """A 101 handshake, polled while a freshly deployed stage settles. Returns the socket."""
    def _try():
        try:
            return _ws_handshake(ctx, api_endpoint, stage, query)
        except OSError as exc:
            return (-1, repr(exc), None)

    got = _poll_until(
        _try,
        lambda r: r[0] == 101,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"WebSocket 101 upgrade on stage {stage} with query {query!r}",
    )
    return got[2]


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
            raise AssertionError(f"WebSocket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _ws_recv_text(sock, timeout_s=30.0):
    """Read frames until a text frame arrives; return its payload. Control frames other than
    CLOSE are skipped; a CLOSE is an assertion failure naming its payload."""
    deadline = time.monotonic() + timeout_s
    while True:
        left = deadline - time.monotonic()
        assert left > 0, f"no WebSocket text frame within {timeout_s}s"
        sock.settimeout(left)
        try:
            b1 = _ws_recv_exact(sock, 1)[0]
        except (socket.timeout, TimeoutError):
            raise AssertionError(f"no WebSocket text frame within {timeout_s}s") from None
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
                f"WebSocket server closed the connection instead of sending a text frame "
                f"(close payload {payload!r})"
            )


def _ws_recv_json(sock, timeout_s=30.0):
    raw = _ws_recv_text(sock, timeout_s)
    try:
        return json.loads(raw)
    except ValueError:
        raise AssertionError(f"text frame was not JSON: {raw!r}") from None


def _ws_round_trip(sock, payload, timeout_s=30.0):
    _ws_send_text(sock, payload)
    return _ws_recv_json(sock, timeout_s)


def _ws_close(sock):
    """Send a masked CLOSE frame with status 1000, then close the socket — the clean
    disconnect that makes the service fire $disconnect."""
    try:
        code = (1000).to_bytes(2, "big")
        mask = os.urandom(4)
        sock.sendall(
            b"\x88\x82" + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(code))
        )
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _close_later(ctx, sock):
    """Register a socket close that is a no-op if the check already closed it."""
    state = {"open": True}

    def _close():
        if state["open"]:
            state["open"] = False
            _ws_close(sock)

    ctx.on_cleanup(_close)
    return _close


def _watcher_records(sock, until, timeout_s=90.0):
    """Collect watcher frames until `until(records)` holds; return every record read."""
    records = []
    deadline = time.monotonic() + timeout_s
    while not until(records):
        left = deadline - time.monotonic()
        assert left > 0, (
            f"watcher condition not met within {timeout_s}s; records so far {records!r}"
        )
        records.append(_ws_recv_json(sock, left))
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
