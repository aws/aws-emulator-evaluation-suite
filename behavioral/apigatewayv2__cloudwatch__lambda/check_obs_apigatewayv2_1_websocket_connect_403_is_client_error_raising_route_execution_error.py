"""obs-apigatewayv2-1-websocket-connect-403-is-client-error-raising-route-execution-error."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import time
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigatewayv2-1-websocket-connect-403-is-client-error-raising-route-execution-error"
GROUP = "metrics-and-alarms"
SERVICES = ["apigatewayv2", "cloudwatch", "lambda"]

#: The metric vocabulary a WebSocket API publishes under {ApiId, Stage}.
_WS_METRICS = (("ConnectCount", "Sum"), ("MessageCount", "Sum"), ("IntegrationError", "Sum"),
               ("ClientError", "Sum"), ("ExecutionError", "Sum"),
               ("IntegrationLatency", "SampleCount"))

#: The $connect integration refuses any handshake on stage `guard` that does not present this
#: query token, and admits every handshake on stage `live`. Same function, same deployment: the
#: stage is the one thing that differs.
_HANDLER = r'''
import json


def handler(event, context):
    rc = event.get("requestContext") or {}
    route = rc.get("routeKey")
    qs = event.get("queryStringParameters") or {}
    if route == "$connect":
        if rc.get("stage") == "guard" and qs.get("token") != "ok":
            return {"statusCode": 403, "body": "denied"}
        return {"statusCode": 200}
    if route == "$disconnect":
        return {"statusCode": 200}
    if route == "boom":
        raise RuntimeError("sim2real-boom")
    return {"statusCode": 200}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-logging.html
@tags("axis:rejection", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e",
      "concern:metrics", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A $connect Lambda returning 403 refuses the handshake and counts as the stage's ClientError; a
    raising route Lambda counts as ExecutionError; IntegrationError stays an explicit 0, and a
    clean sibling stage on the same deployment keeps every error series at 0."""
    v2 = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-xsvc-wserr-")
    created_api = v2.create_api(Name=name, ProtocolType="WEBSOCKET",
                                RouteSelectionExpression="$request.body.action",
                                Tags={_TAG_KEY: CHECK})
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(_retry_throttled(lambda: v2.delete_api(ApiId=api_id)))
    acct = ctx.client("sts").get_caller_identity()["Account"]
    fn_name, fn_arn = _lambda(ctx, name, _HANDLER)
    _allow_invoke(ctx, fn_name, acct, api_id)
    integ = v2.create_integration(ApiId=api_id, IntegrationType="AWS_PROXY",
                                  IntegrationUri=_invoke_uri(ctx, fn_arn),
                                  IntegrationMethod="POST")["IntegrationId"]
    for route_key in ("$connect", "$disconnect", "$default", "boom"):
        v2.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integ}")
    dep = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    _poll_until(lambda: v2.get_deployment(ApiId=api_id, DeploymentId=dep)["DeploymentStatus"],
                lambda s: s != "PENDING", timeout_s=60, interval_s=2,
                description="the WebSocket API deployment leaving PENDING")
    for stage in ("live", "guard"):
        v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=dep)

    t0 = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    # ---- positive control: live admits, accepts one frame, closes cleanly -----------------------
    sock, pre_live = _connect(ctx, api_endpoint, "live")
    _send(sock, 0x1, json.dumps({"action": "tick"}).encode())
    closed = _close_clean(sock)
    assert closed[0] == 0x8, f"live: expected the server's CLOSE frame, got {closed!r}"

    # ---- positive control on guard: the token-bearing handshake is admitted ---------------------
    # Done FIRST so readiness retries (if any) happen on an admitted handshake, not a refused one.
    sock, pre_guard = _connect(ctx, api_endpoint, "guard", "?token=ok")

    # ---- break one thing: the same stage, no token -> $connect returns 403 ----------------------
    denied, head, rest = _handshake(ctx, api_endpoint, "guard")
    try:
        status_line = (head.splitlines() or [""])[0]
        assert status_line.split()[1:2] == ["403"], (
            f"guard: a $connect integration returning 403 must refuse the upgrade with HTTP 403; "
            f"response line {status_line!r}")
        assert "sec-websocket-accept" not in head.lower(), (
            f"guard: the refused handshake must not complete the upgrade; head {head!r}")
        body = _read_body(denied, head, rest)
        assert body == b"denied", (
            f"guard: the refusal should carry the integration's own body b'denied', got {body!r}")
    finally:
        _close_quiet(denied)

    # ---- break one thing: a frame routed to the raising Lambda ----------------------------------
    _send(sock, 0x1, json.dumps({"action": "boom"}).encode())
    err = json.loads(_recv_text(sock))
    assert err.get("message") == "Internal server error", (
        f"guard: a raising route integration should answer with the service's error frame, got "
        f"{err!r}")
    closed = _close_clean(sock)
    assert closed[0] == 0x8, f"guard: expected the server's CLOSE frame, got {closed!r}"

    want = {
        # live: $connect + 1 frame (+ best-effort $disconnect); no errors at all.
        ("live", "ConnectCount"): (1, 1 + pre_live),
        ("live", "MessageCount"): (2, 3 + pre_live),
        ("live", "IntegrationLatency"): (2, 3 + pre_live),
        ("live", "ClientError"): (0, pre_live),
        ("live", "ExecutionError"): (0, pre_live),
        ("live", "IntegrationError"): (0, 0),
        # guard: refused $connect + admitted $connect + boom frame + error frame (+ $disconnect).
        ("guard", "ConnectCount"): (2, 2 + pre_guard),
        ("guard", "MessageCount"): (4, 5 + pre_guard),
        ("guard", "IntegrationLatency"): (3, 4 + pre_guard),
        ("guard", "ClientError"): (1, 1 + pre_guard),
        ("guard", "ExecutionError"): (1, 1 + pre_guard),
        ("guard", "IntegrationError"): (0, 0),
    }
    snap = _settle(ctx, api_id, t0, want)
    for (stage, metric), (lo, hi) in sorted(want.items()):
        total, points = snap[(stage, metric)]
        assert lo <= total <= hi, (
            f"{stage}.{metric} = {total} over {points} datapoints, expected [{lo}, {hi}] "
            f"(pre-upgrade handshakes live={pre_live} guard={pre_guard}); full snapshot "
            f"{_fmt(snap)}")
        assert points >= 1, (
            f"{stage}.{metric} published no datapoint for an active stage; real AWS publishes "
            f"the series (zero-valued where nothing failed). Snapshot {_fmt(snap)}")


def _read_body(sock, head, rest, timeout_s=30.0):
    """The body of a refused handshake: `rest` plus whatever follows, bounded by Content-Length
    when present and by the close otherwise."""
    length = None
    for line in head.splitlines()[1:]:
        key, _, value = line.partition(":")
        if key.strip().lower() == "content-length" and value.strip().isdigit():
            length = int(value.strip())
    body = rest
    sock.settimeout(timeout_s)
    while length is None or len(body) < length:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        body += chunk
    return body if length is None else body[:length]


# ===== helpers =====
_TAG_KEY = "sim2real"
_NS = "AWS/ApiGateway"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout, quoting the last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _quiet(fn):
    """Teardown wrapper: an already-gone resource is fine; any other error raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "NoSuchEntity", "ResourceNotFoundException", "NotFoundException"
            ):
                raise
    return _wrapped


def _retry_throttled(fn):
    """Teardown: API Gateway deletes are rate limited account-wide; retry, then report."""
    def _wrapped():
        for _ in range(12):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "TooManyRequestsException":
                    raise RuntimeError(f"teardown failed: {code}") from exc
                time.sleep(10)
        raise RuntimeError("teardown still throttled after 12 attempts")
    return _wrapped


def _reap_log_group(ctx, group):
    """Belt and braces: the role has no logs permissions, so no group should exist. Deleted in a
    loop anyway, because a late flush can recreate a group after one delete."""
    logs = ctx.client("logs")
    for _ in range(3):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)


def _lambda(ctx, name, handler, manage_connections_api=None):
    """A python3.12 function whose role has NO logs permissions (so no log group is created), and
    optionally execute-api:ManageConnections scoped to one API. Returns (name, arn)."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                 "Principal": {"Service": "lambda.amazonaws.com"}}]}),
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_quiet(lambda: iam.delete_role(RoleName=name)))
    if manage_connections_api:
        acct, api_id = manage_connections_api
        iam.put_role_policy(RoleName=name, PolicyName="manage-connections",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                                "Effect": "Allow", "Action": "execute-api:ManageConnections",
                                "Resource": f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*"}]}))
        ctx.on_cleanup(_quiet(lambda: iam.delete_role_policy(RoleName=name,
                                                             PolicyName="manage-connections")))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", handler)

    def _create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, Tags={_TAG_KEY: CHECK})
        except ClientError as exc:
            # A freshly created role is not assumable for a few seconds (IAM propagation).
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    # Registered BEFORE the create, so LIFO runs it after the function delete.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    fn = _poll_until(_create, lambda r: r is not None, timeout_s=90, interval_s=5,
                     description="lambda.create_function accepting the new role")
    ctx.on_cleanup(_quiet(lambda: lam.delete_function(FunctionName=name)))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name, fn["FunctionArn"]


def _allow_invoke(ctx, fn_name, acct, api_id):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*")


def _invoke_uri(ctx, fn_arn):
    return (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}"
            f"/invocations")


def _ws_endpoint(ctx, api_endpoint, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) for a WebSocket API.

    Split from the stage's ``ctx.stage_url(...)``, on every target.
    """
    url = urllib.parse.urlsplit(ctx.stage_url(api_endpoint, stage))
    use_tls = url.scheme == "wss"
    return use_tls, url.hostname, url.port or (443 if use_tls else 80), url.netloc, url.path


def _handshake(ctx, api_endpoint, stage, query="", timeout_s=20.0):
    """Open a socket and send an RFC 6455 upgrade. Returns (sock, response_head, rest)."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_endpoint, stage)
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET {path}{query} HTTP/1.1\r\nHost: {http_host}\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                  "Sec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    sock.settimeout(timeout_s)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return sock, head.decode("utf-8", "replace"), rest


def _connect(ctx, api_endpoint, stage, query=""):
    """Handshake until ``101 Switching Protocols``. Returns (sock, n_non_upgraded_responses):
    every response that came back without upgrading may have been counted by the service, so it
    widens the caller's upper bounds by exactly that many."""
    seen = []
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            sock, head, _rest = _handshake(ctx, api_endpoint, stage, query)
        except OSError as exc:
            seen.append(f"OSError {exc}")
            time.sleep(3)
            continue
        line = (head.splitlines() or [""])[0]
        if " 101 " in line:
            return sock, sum(1 for s in seen if not s.startswith("OSError"))
        seen.append(line)
        _close_quiet(sock)
        time.sleep(3)
    raise AssertionError(f"stage {stage!r} never upgraded a WebSocket handshake: {seen!r}")


def _frame(opcode, data):
    """One masked RFC 6455 frame (client frames MUST be masked, RFC 6455 5.3)."""
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    else:
        header.append(0x80 | 126)
        header += n.to_bytes(2, "big")
    mask = os.urandom(4)
    header += mask
    return bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _send(sock, opcode, data):
    sock.sendall(_frame(opcode, data))


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"WebSocket closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def _recv_frame(sock, timeout_s=30.0):
    """Read exactly one frame; return (opcode, payload)."""
    sock.settimeout(timeout_s)
    b1, b2 = _recv_exact(sock, 2)
    n = b2 & 0x7F
    if n == 126:
        n = int.from_bytes(_recv_exact(sock, 2), "big")
    elif n == 127:
        n = int.from_bytes(_recv_exact(sock, 8), "big")
    mask = _recv_exact(sock, 4) if b2 & 0x80 else None
    payload = _recv_exact(sock, n) if n else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return b1 & 0x0F, payload


def _recv_text(sock, timeout_s=30.0):
    """The next TEXT frame's payload; pings are skipped and a CLOSE is a failure."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        opcode, payload = _recv_frame(sock, timeout_s)
        if opcode == 0x1:
            return payload.decode("utf-8", "replace")
        if opcode == 0x8:
            raise AssertionError(f"server closed instead of sending a text frame: {payload!r}")
    raise AssertionError(f"no text frame within {timeout_s}s")


def _close_clean(sock, timeout_s=30.0):
    """Send CLOSE 1000 and read until the server's CLOSE comes back. Returns (opcode, payload)
    of the last frame read; the caller asserts it was the CLOSE."""
    try:
        _send(sock, 0x8, (1000).to_bytes(2, "big"))
        deadline = time.monotonic() + timeout_s
        last = (None, b"")
        while time.monotonic() < deadline:
            last = _recv_frame(sock, timeout_s)
            if last[0] == 0x8:
                break
        return last
    finally:
        _close_quiet(sock)


def _close_quiet(sock):
    try:
        sock.close()
    except OSError:
        pass


def _series(ctx, api_id, stage, metric, statistic, t0):
    """(total, n_datapoints) of one statistic over every 60 s datapoint from t0 to now+3 min."""
    pts = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=_NS, MetricName=metric,
        Dimensions=[{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": stage}],
        StartTime=t0, EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
        Statistics=[statistic])["Datapoints"]
    return sum(p[statistic] for p in pts), len(pts)


def _stat_of(metric):
    return dict(_WS_METRICS)[metric]


def _snapshot(ctx, api_id, t0, keys):
    return {(stage, m): _series(ctx, api_id, stage, m, _stat_of(m), t0) for stage, m in keys}


def _settle(ctx, api_id, t0, want, timeout_s=240.0, interval_s=10.0, confirm=3):
    """Poll until every series has published and reached its LOWER bound, then require `confirm`
    further reads `interval_s` apart to return the same totals, so a late datapoint cannot slip in
    after the upper bound is asserted."""
    def _ready(snap):
        return all(snap[k][1] >= 1 and snap[k][0] >= lo for k, (lo, _hi) in want.items())

    snap = _poll_until(lambda: _snapshot(ctx, api_id, t0, want), _ready, timeout_s=timeout_s,
                       interval_s=interval_s,
                       description=f"WebSocket stage metrics reaching {want!r}")
    deadline = time.monotonic() + timeout_s
    stable = 0
    while stable < confirm:
        assert time.monotonic() < deadline, (
            f"WebSocket stage metrics never held still for {confirm} reads; last {_fmt(snap)}")
        time.sleep(interval_s)
        again = _snapshot(ctx, api_id, t0, want)
        if again == snap:
            stable += 1
        else:
            snap, stable = again, 0
    return snap


def _fmt(snap):
    return {f"{s}.{m}": v for (s, m), v in sorted(snap.items())}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
