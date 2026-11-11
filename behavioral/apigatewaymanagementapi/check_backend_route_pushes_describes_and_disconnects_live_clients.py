"""backend-route-pushes-describes-and-disconnects-live-clients."""
from __future__ import annotations

import io
import json
import ssl
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backend-route-pushes-describes-and-disconnects-live-clients"
GROUP = "websocket-dataplane"
SERVICES = ["apigatewaymanagementapi"]

_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}

#: A chat backend on the `$default` route: `whoami` answers GetConnection on the caller's own
#: connection, `send` relays a text to another connection, `kick` deletes one. Each reply goes back
#: to the caller through PostToConnection, so every management call is observed by a live client.
_HANDLER = """
import json
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    if rc.get("routeKey") in ("$connect", "$disconnect"):
        return {"statusCode": 200}
    me = rc["connectionId"]
    mgmt = boto3.client(
        "apigatewaymanagementapi", endpoint_url="https://" + rc["domainName"] + "/" + rc["stage"]
    )
    msg = json.loads(event.get("body") or "{}")
    action = msg.get("action")
    reply = {"route": action}
    try:
        if action == "whoami":
            got = mgmt.get_connection(ConnectionId=me)
            reply.update(
                connectionId=me,
                sourceIp=got["Identity"]["SourceIp"],
                requestSourceIp=(rc.get("identity") or {}).get("sourceIp"),
                connectedAtBeforeLastActive=got["ConnectedAt"] <= got["LastActiveAt"],
            )
        elif action == "send":
            mgmt.post_to_connection(
                ConnectionId=msg["to"], Data=json.dumps({"from": me, "text": msg["text"]}).encode()
            )
            reply["delivered"] = True
        elif action == "kick":
            mgmt.delete_connection(ConnectionId=msg["target"])
            reply["kicked"] = msg["target"]
        else:
            reply["error"] = "unknown action"
    except ClientError as exc:
        reply["error"] = exc.response["Error"]["Code"]
        reply["message"] = exc.response["Error"].get("Message")
    mgmt.post_to_connection(ConnectionId=me, Data=json.dumps(reply).encode())
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


def _poll_until(ctx, probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; return that result or raise on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises, unless the resource is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_role(iam, role_name):
    for policy in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
    iam.delete_role(RoleName=role_name)


def _lambda_role(ctx):
    """An execution role allowing only execute-api:ManageConnections, so no log group is created."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-wsrole-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: _delete_role(iam, role_name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": "execute-api:ManageConnections",
                           "Resource": f"arn:aws:execute-api:{ctx.region}:{ctx.account}:*/*"}],
        }),
    )
    return arn


def _create_function(ctx, role_arn):
    """The route integration, Active, teardown registered."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-wsfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)

    def _create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="index.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=20, Tags=_TAGS,
            )["FunctionArn"]
        except ClientError as exc:
            # A brand-new role is not yet assumable by Lambda.
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(ctx, _create, bool, interval_s=4.0,
                      description="CreateFunction to accept the new execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        description=f"function {name} Active",
    )
    return name, arn


def _deploy_websocket_api(ctx, fn_name, fn_arn, stage="dev"):
    """A WebSocket API routing $connect, $disconnect and $default to the function, deployed."""
    v2 = ctx.client("apigatewayv2")
    api_id = v2.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )["ApiId"]
    ctx.on_cleanup(_teardown(lambda: v2.delete_api(ApiId=api_id), "NotFoundException"))
    integration = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
        ),
    )["IntegrationId"]
    for route_key in ("$connect", "$disconnect", "$default"):
        v2.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integration}")
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId=f"sim2real-behav-apigw-{api_id}",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    return api_id, stage


def _sslopt(ctx):
    verify = ctx.http_verify
    if verify is False:
        return {"cert_reqs": ssl.CERT_NONE}
    return {"ca_certs": verify} if isinstance(verify, str) else {}


def _connect(ctx, url):
    """A live WebSocket client, or None while a new stage still refuses the upgrade."""
    import websocket

    try:
        ws = websocket.create_connection(url, sslopt=_sslopt(ctx), timeout=20)
    except (websocket.WebSocketBadStatusException, OSError):
        return None
    ctx.on_cleanup(ws.close)
    return ws


def _frame(ctx, ws, timeout_s=30.0, *, required=True):
    """(opcode, payload) of the next data or close frame; pings and pongs are skipped.

    With ``required`` false a timeout returns None instead of failing.
    """
    import websocket

    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        ws.settimeout(max(0.5, deadline - time.monotonic()))
        try:
            opcode, payload = ws.recv_data(control_frame=True)
        except websocket.WebSocketTimeoutException:
            break
        if opcode in (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY,
                      websocket.ABNF.OPCODE_CLOSE):
            return opcode, payload
    if not required:
        return None
    if _budget_spent(ctx):
        raise TimeoutError("waiting for a WebSocket frame: the run budget ended first; not graded")
    raise AssertionError(f"no WebSocket frame within {timeout_s:.0f}s")


def _is_whoami(opcode, payload):
    """True for a text frame carrying a ``whoami`` reply."""
    if opcode != 0x1:
        return False
    try:
        return json.loads(payload).get("route") == "whoami"
    except (ValueError, AttributeError):
        return False


def _after_whoami(ctx, ws, timeout_s=30.0, *, required=True):
    """The next frame that is not a late ``whoami`` reply from the first-call retry."""
    while True:
        frame = _frame(ctx, ws, timeout_s, required=required)
        if frame is None or not _is_whoami(*frame):
            return frame


def _reply(ctx, ws, route, *, timeout_s=30.0, required=True):
    """The backend's JSON reply for ``route`` on this client.

    With ``required`` false a missing reply returns None instead of failing.
    """
    import websocket

    read = _frame if route == "whoami" else _after_whoami
    frame = read(ctx, ws, timeout_s, required=required)
    if frame is None:
        return None
    opcode, payload = frame
    assert opcode == websocket.ABNF.OPCODE_TEXT, (
        f"expected the {route!r} reply as a text frame, got opcode {opcode:#x} {payload[:120]!r}"
    )
    reply = json.loads(payload)
    assert reply.get("route") == route, f"expected the {route!r} reply, got {reply!r}"
    return reply


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A route backend's GetConnection describes the calling client, its PostToConnection relays a
    message to a second live client, and its DeleteConnection closes that client with code 1000, after
    which GetConnection and PostToConnection on it answer GoneException while the first stays live.
    """
    import websocket

    role_arn = _lambda_role(ctx)
    fn_name, fn_arn = _create_function(ctx, role_arn)
    api_id, stage = _deploy_websocket_api(ctx, fn_name, fn_arn)
    url = ctx.api_url(api_id, stage, websocket=True)

    alice = _poll_until(ctx, lambda: _connect(ctx, url), bool, interval_s=4.0,
                        description="a 101 WebSocket upgrade on the new stage")
    bob = _poll_until(ctx, lambda: _connect(ctx, url), bool, interval_s=4.0,
                      description="a second WebSocket upgrade")

    def _whoami(ws):
        ws.send(json.dumps({"action": "whoami"}))
        return _reply(ctx, ws, "whoami", timeout_s=10.0, required=False)

    def _first_whoami(ws):
        # A new role's grant reaches each new execution environment late, denying GetConnection
        # (an error reply) or the reply's own PostToConnection (no reply): retry until it holds.
        return _poll_until(
            ctx, lambda: _whoami(ws),
            lambda r: r is not None and r.get("error") != "ForbiddenException",
            interval_s=4.0, description="GetConnection under the backend's new role",
        )

    ids, seen = {}, {}
    for name, me in (("alice", _first_whoami(alice)), ("bob", _first_whoami(bob))):
        assert me.get("connectionId") and "error" not in me, f"whoami for {name} failed: {me!r}"
        assert me.get("sourceIp"), f"GetConnection gave {name} no Identity.SourceIp: {me!r}"
        assert me["sourceIp"] == me["requestSourceIp"], (
            f"GetConnection's Identity.SourceIp {me['sourceIp']!r} differs from the route request's "
            f"identity.sourceIp {me['requestSourceIp']!r}"
        )
        assert me["connectedAtBeforeLastActive"] is True, (
            f"GetConnection reported LastActiveAt before ConnectedAt for {name}: {me!r}"
        )
        ids[name], seen[name] = me["connectionId"], me["sourceIp"]
    assert ids["alice"] != ids["bob"], f"two clients were given one connection id: {ids!r}"

    mgmt = ctx.client("apigatewaymanagementapi", endpoint_url=ctx.api_url(api_id, stage))
    described = (mgmt.get_connection(ConnectionId=ids["bob"]).get("Identity") or {}).get("SourceIp")
    assert described == seen["bob"], (
        f"GetConnection on bob gave SourceIp {described!r}; the backend read {seen['bob']!r}"
    )

    text = ctx.unique_name("hello-")
    alice.send(json.dumps({"action": "send", "to": ids["bob"], "text": text}))
    ack = _reply(ctx, alice, "send")
    assert ack == {"route": "send", "delivered": True}, f"the relay to bob was not acknowledged: {ack!r}"
    opcode, payload = _after_whoami(ctx, bob)
    relayed = json.loads(payload) if opcode == websocket.ABNF.OPCODE_TEXT else {"opcode": opcode}
    assert relayed == {"from": ids["alice"], "text": text}, (
        f"bob received {relayed!r}, expected the text {text!r} from alice's connection"
    )

    alice.send(json.dumps({"action": "kick", "target": ids["bob"]}))
    ack = _reply(ctx, alice, "kick")
    assert ack == {"route": "kick", "kicked": ids["bob"]}, f"deleting bob was not acknowledged: {ack!r}"
    opcode, payload = _after_whoami(ctx, bob)
    assert opcode == websocket.ABNF.OPCODE_CLOSE, f"bob's socket was not closed: next frame opcode {opcode:#x} {payload[:120]!r}"
    code = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
    assert code == 1000, f"DeleteConnection closed bob with code {code!r}, expected 1000"

    gone = _error(lambda: mgmt.get_connection(ConnectionId=ids["bob"]))
    assert gone == ("GoneException", ""), f"GetConnection on the deleted connection gave {gone!r}"
    alice.send(json.dumps({"action": "send", "to": ids["bob"], "text": text}))
    ack = _reply(ctx, alice, "send")
    assert ack == {"route": "send", "error": "GoneException", "message": ""}, (
        f"PostToConnection to the deleted connection answered {ack!r}, expected GoneException"
    )
    live = (mgmt.get_connection(ConnectionId=ids["alice"]).get("Identity") or {}).get("SourceIp")
    assert live == seen["alice"], f"alice's connection did not stay live: SourceIp {live!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
