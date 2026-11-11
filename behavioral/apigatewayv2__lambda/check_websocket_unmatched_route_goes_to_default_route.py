"""websocket-unmatched-route-goes-to-default-route."""

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

CHECK = "websocket-unmatched-route-goes-to-default-route"

GROUP = "websocket-routing-forbidden-without-default"

SERVICES = ["apigatewayv2", "lambda"]


#: One handler source, deployed as two DISTINCT functions that differ only in FN_TAG. A two-way
#: route relays this body verbatim to the client, so the reply names which function answered and
#: carries the frame it was handed, unmodified.
_HANDLER = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": json.dumps({"fn": os.environ["FN_TAG"], "body": event.get("body")}),
    }
"""


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A frame whose action matches no route key is dispatched unchanged to the $default Lambda;
    after $default is deleted and redeployed the same frame gets a gateway Forbidden error frame
    and the socket stays open, with ping still answering."""
    account = _account_id(ctx)
    role_arn = _create_role(ctx)
    ping_fn = _create_function(ctx, role_arn, "ping")
    default_fn = _create_function(ctx, role_arn, "default")
    api_id, api_endpoint = _create_ws_api(ctx)
    _permit_invoke(ctx, ping_fn, api_id, account)
    _permit_invoke(ctx, default_fn, api_id, account)
    ping_route_id = _add_two_way_route(ctx, api_id, "ping", ping_fn)
    default_route_id = _add_two_way_route(ctx, api_id, "$default", default_fn)
    stage = _deploy(ctx, api_id)

    sock = _ws_open(ctx, api_endpoint, stage)
    close = _close_later(ctx, sock)
    marker = ctx.unique_name("sim2real-ws-")

    # ---- 1. the ping route answers from its own Lambda --------------------------------
    ping_frame = json.dumps({"action": "ping", "text": marker + "-ping-1"})
    got = _ws_round_trip(sock, ping_frame)
    assert got.get("fn") == "ping" and got.get("body") == ping_frame, (
        f"action=ping should be answered by the ping Lambda echoing {ping_frame!r}; got {got!r}"
    )

    # ---- 2. an action naming no route is dispatched to the $default ROUTE's Lambda ------
    unmatched_frame = json.dumps({"action": "no-such-action", "text": marker + "-unmatched"})
    got = _ws_round_trip(sock, unmatched_frame)
    assert got.get("fn") == "default", (
        f"an action matching no route should be answered by the $default route's own "
        f"Lambda (fn='default'); got {got!r}"
    )
    assert got.get("body") == unmatched_frame, (
        f"the $default integration should receive the unmatched frame unchanged "
        f"({unmatched_frame!r}); got body {got.get('body')!r}"
    )

    # ---- 3. positive control: ping is unaffected by the fallback ------------------------
    ping_frame_2 = json.dumps({"action": "ping", "text": marker + "-ping-2"})
    got = _ws_round_trip(sock, ping_frame_2)
    assert got.get("fn") == "ping" and got.get("body") == ping_frame_2, (
        f"ping should still be answered by its own Lambda after the fallback; got {got!r}"
    )

    # ---- 4. remove $default, redeploy: the control plane changed, the data plane follows -
    v2 = ctx.client("apigatewayv2")
    v2.delete_route(ApiId=api_id, RouteId=default_route_id)
    v2.create_deployment(ApiId=api_id, StageName=stage)
    routes = _paginate(v2, "get_routes", "Items", ApiId=api_id)
    assert sorted(r["RouteKey"] for r in routes) == ["ping"], (
        f"after deleting $default only 'ping' should remain, got "
        f"{[r['RouteKey'] for r in routes]!r}"
    )

    # ---- 5. the SAME unmatched frame now gets the gateway's measured refusal ------------
    unmatched_frame_2 = json.dumps({"action": "no-such-action", "text": marker + "-refused"})
    err = _ws_round_trip(sock, unmatched_frame_2, settle=True)
    assert err.get("message") == "Forbidden", (
        f"with no $default route, an unmatched action should be refused with a "
        f"'Forbidden' error frame (the measured real-AWS shape); got {err!r}"
    )
    assert "fn" not in err and "body" not in err, (
        f"the refusal must come from the gateway itself, not from any integration; got {err!r}"
    )
    assert err.get("requestId"), f"the error frame should carry a requestId; got {err!r}"
    connection_id = err.get("connectionId")
    assert connection_id, f"the error frame should carry a connectionId; got {err!r}"

    # ---- 6. positive control: the socket survived, ping still answers -------------------
    ping_frame_3 = json.dumps({"action": "ping", "text": marker + "-ping-3"})
    got = _ws_round_trip(sock, ping_frame_3)
    assert got.get("fn") == "ping" and got.get("body") == ping_frame_3, (
        f"after the refusal the same socket should still route ping to its Lambda; got {got!r}"
    )
    close()


_PREFIX = "sim2real-apigwv2-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx):
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
        Tags=_tags_kv(),
    )
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
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
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
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _reap_log_group(ctx, name):
    """delete_function leaves /aws/lambda/<fn>, and a late log flush can RECREATE it after one
    delete, so the reap re-deletes until the group stays gone over a bounded window."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    deadline = time.monotonic() + 60
    quiet = 0
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


def _create_function(ctx, role_arn, fn_tag):
    name = _xname(ctx, f"fn-{fn_tag}")
    lam = ctx.client("lambda")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(_HANDLER))
    # Registered BEFORE the create so LIFO runs it AFTER delete_function below.
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
                Tags=dict(_resource_tags()),
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
    return {"name": name, "arn": resp["FunctionArn"]}


def _permit_invoke(ctx, fn, api_id, account):
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-ws-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*",
    )


def _create_ws_api(ctx):
    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_xname(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    return api_id, api_endpoint


def _add_two_way_route(ctx, api_id, route_key, fn):
    """A route whose target is `fn`'s own Lambda proxy integration, carrying a `$default`
    RouteResponse so the integration's body is returned to the client."""
    v2 = ctx.client("apigatewayv2")
    integration_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    route_id = v2.create_route(
        ApiId=api_id,
        RouteKey=route_key,
        Target=f"integrations/{integration_id}",
        RouteResponseSelectionExpression="$default",
    )["RouteId"]
    v2.create_route_response(ApiId=api_id, RouteId=route_id, RouteResponseKey="$default")
    return route_id


def _deploy(ctx, api_id, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    deployment_id = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment_id)
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage))
    return stage


def _paginate(client, op, key, **kwargs):
    out, token = [], None
    while True:
        resp = getattr(client, op)(**kwargs, **({"NextToken": token} if token else {}))
        out.extend(resp.get(key, []))
        token = resp.get("NextToken")
        if not token:
            return out


def _ws_endpoint(ctx, api_endpoint, stage):
    url = urllib.parse.urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _ws_handshake(ctx, api_endpoint, stage, timeout_s=20.0):
    """An RFC 6455 opening handshake over a stdlib socket. Returns (status, head, sock):
    `sock` is the open socket on a 101 and None (already closed) on anything else."""
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


def _ws_open(ctx, api_endpoint, stage):
    """A 101 handshake, polled while a freshly deployed stage settles. Returns the socket."""

    def _try():
        try:
            return _ws_handshake(ctx, api_endpoint, stage)
        except OSError as exc:
            return (-1, repr(exc), None)

    got = _poll_until(
        _try,
        lambda r: r[0] == 101,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"WebSocket 101 upgrade on stage {stage}",
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


def _ws_round_trip(sock, payload, timeout_s=45.0, settle=False):
    """Send one frame and return the JSON reply. With `settle`, a just-deleted route's removal
    from the live routing table is not instant (measured: a redeploy can take over a dozen
    seconds to take effect), so a reply still carrying `fn` -- the OLD, now-deleted route still
    answering -- is retried; the gateway's own refusal (no `fn`) ends the retry at once."""
    deadline = time.monotonic() + 90.0 if settle else None
    while True:
        _ws_send_text(sock, payload)
        reply = _ws_recv_json(sock, timeout_s)
        if not settle or "fn" not in reply:
            return reply
        if time.monotonic() >= deadline:
            return reply
        time.sleep(5.0)


def _ws_close(sock):
    """Send a masked CLOSE frame with status 1000, then close the socket."""
    try:
        code = (1000).to_bytes(2, "big")
        mask = os.urandom(4)
        sock.sendall(b"\x88\x82" + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(code)))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
