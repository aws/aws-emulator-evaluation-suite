"""get-connection-last-active-at-advances-on-traffic-not-on-reads."""
from __future__ import annotations

import base64
import datetime as dt
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

CHECK = "get-connection-last-active-at-advances-on-traffic-not-on-reads"

GROUP = "state"

SERVICES = ["apigatewaymanagementapi"]

#: How many GetConnection reads the quiet window holds. Five, so a target that recomputes
#: LastActiveAt per read has five chances to differ rather than one.
_FREEZE_READS = 5

#: The wall-clock span the quiet reads are spread over, well above the timestamp's resolution,
#: so a LastActiveAt minted as now() per read would differ between reads.
_QUIET_WINDOW_S = 6.0

#: How far this host's clock is allowed to sit from the service's when bounding LastActiveAt from
#: above. A tolerance, not a wait. Generous on purpose: the bound exists to catch a value in the
#: wrong hour, not to measure NTP drift.
_CLOCK_SKEW_ALLOWANCE_S = 120.0


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "concern:representation",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetConnection's LastActiveAt stays identical across five reads over ~6 s without traffic,
    then advances into the measured window after an echoed client->server frame; ConnectedAt never
    changes.

    Reference: https://docs.aws.amazon.com/apigateway/latest/api/apigatewaymanagementapi/API_GetConnection.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role = _lambda_role(ctx, account)
    fn = _create_function(ctx, role["arn"])
    api_id, stage, api_endpoint = _deploy_websocket_api(ctx, account, fn)
    mgmt = _management_client(ctx, api_endpoint, stage)
    # The whoami handshake inside _open_and_identify is itself client->server traffic, so the
    # baseline below is taken on a connection that has already been active at least once.
    sock, connection_id = _open_and_identify(ctx, api_id, stage, api_endpoint)

    baseline = mgmt.get_connection(ConnectionId=connection_id)
    connected_at = baseline.get("ConnectedAt")
    baseline_active = baseline.get("LastActiveAt")
    assert connected_at is not None, (
        f"GetConnection on a live connection returned no ConnectedAt: {baseline!r}"
    )
    assert baseline_active is not None, (
        f"GetConnection on a live connection returned no LastActiveAt: {baseline!r}"
    )
    assert baseline_active >= connected_at, (
        f"LastActiveAt {baseline_active!r} precedes ConnectedAt {connected_at!r}; the whoami frame "
        f"this check already sent must have moved the activity clock forward, not backward"
    )

    # ---- leg 1: no socket traffic and no pushes inside this window ----
    reads = [baseline]
    freeze_started = time.monotonic()
    freeze_deadline = freeze_started + _QUIET_WINDOW_S
    while time.monotonic() < freeze_deadline or len(reads) < _FREEZE_READS:
        # Spacing: reads must be separated by real wall clock or now() could repeat a millisecond.
        time.sleep(_QUIET_WINDOW_S / _FREEZE_READS)
        reads.append(mgmt.get_connection(ConnectionId=connection_id))
        if len(reads) >= 4 * _FREEZE_READS:
            break
    freeze_span = time.monotonic() - freeze_started

    active_values = [r.get("LastActiveAt") for r in reads]
    connected_values = [r.get("ConnectedAt") for r in reads]
    assert all(v is not None for v in active_values), (
        f"GetConnection stopped returning LastActiveAt part-way through {len(reads)} quiet reads: "
        f"{active_values!r}"
    )
    assert len(set(active_values)) == 1, (
        f"LastActiveAt changed across {len(reads)} GetConnection reads spanning "
        f"{freeze_span:.2f}s with NO socket traffic: {sorted(set(active_values))!r}. A management "
        f"read is not connection activity; a value that moves here is being minted per request "
        f"rather than recorded when the connection was last used"
    )
    assert len(set(connected_values)) == 1, (
        f"ConnectedAt changed across {len(reads)} reads spanning {freeze_span:.2f}s: "
        f"{sorted(set(connected_values))!r}. It is minted once when the connection is established"
    )
    frozen_active = active_values[0]

    # ---- leg 2: real client->server traffic, proved to have ARRIVED by the route's echo ----
    traffic_started = _utc_now()
    _ws_send_text(sock, json.dumps({"action": "touch", "nonce": ctx.unique_name("touch-")}))
    opcode, echoed = _ws_recv_frame(sock, timeout_s=90.0)
    assert opcode == 0x1, (
        f"the $default route did not echo the traffic frame back as text: opcode {opcode:#x} with "
        f"{echoed[:120]!r}. Without the echo, this check cannot prove the frame reached the "
        f"service, and the advance below would be unattributable"
    )
    assert json.loads(echoed).get("connectionId") == connection_id, (
        f"the echo came back for connection {json.loads(echoed).get('connectionId')!r}, not "
        f"{connection_id!r}"
    )

    advanced_read = _poll_until(
        lambda: mgmt.get_connection(ConnectionId=connection_id),
        lambda r: r.get("LastActiveAt") is not None and r["LastActiveAt"] > frozen_active,
        timeout_s=60.0,
        interval_s=2.0,
        description=(
            f"LastActiveAt advancing past {frozen_active!r} after a client->server frame the "
            f"$default route confirmed receiving (it stayed frozen across {len(reads)} reads and "
            f"{freeze_span:.2f}s before the traffic, so a value that never moves means the field "
            f"is stored once at connect and is not an activity clock)"
        ),
    )
    traffic_ended = _utc_now()
    advanced_active = advanced_read["LastActiveAt"]

    # ---- the two-sided clock bound: the new value is WHEN the traffic happened ----
    lower = traffic_started - dt.timedelta(seconds=_CLOCK_SKEW_ALLOWANCE_S)
    upper = traffic_ended + dt.timedelta(seconds=_CLOCK_SKEW_ALLOWANCE_S)
    assert lower <= advanced_active <= upper, (
        f"LastActiveAt advanced from {frozen_active!r} to {advanced_active!r}, which is outside "
        f"the interval this check measured around the traffic "
        f"[{traffic_started.isoformat()}, {traffic_ended.isoformat()}] widened by "
        f"{_CLOCK_SKEW_ALLOWANCE_S}s of clock-skew allowance. Advancing the field to an unrelated "
        f"instant is as wrong as not advancing it"
    )
    assert advanced_active >= connected_at, (
        f"LastActiveAt {advanced_active!r} is before ConnectedAt {connected_at!r} after the traffic"
    )

    # ---- terminal read: ConnectedAt survived everything the activity clock did ----
    final = mgmt.get_connection(ConnectionId=connection_id)
    assert final.get("ConnectedAt") == connected_at, (
        f"ConnectedAt moved to {final.get('ConnectedAt')!r} from {connected_at!r} once traffic "
        f"advanced LastActiveAt; the two fields must not be the same clock"
    )
    assert final.get("LastActiveAt") == advanced_active, (
        f"LastActiveAt moved again to {final.get('LastActiveAt')!r} from {advanced_active!r} with "
        f"no traffic between the two reads, so the freeze does not hold after an advance either"
    )


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

#: `$default` echoes the caller its own connection id, proving a frame reached the service.
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


def _utc_now():
    """This run's live clock, tz-aware so it is comparable with a parsed __timestampIso8601."""
    return dt.datetime.now(dt.timezone.utc)


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
            # A brand-new role is not yet assumable by Lambda; this bounded retry is the control.
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
    """(opcode, payload) for the next DATA frame; ping/pong control traffic is skipped."""
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
