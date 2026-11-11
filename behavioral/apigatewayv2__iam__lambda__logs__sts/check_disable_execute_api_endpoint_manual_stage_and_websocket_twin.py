"""disable-execute-api-endpoint-manual-stage-and-websocket-twin."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any
from urllib.parse import urlsplit

import urllib.error
import urllib.request
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-execute-api-endpoint-manual-stage-and-websocket-twin"
GROUP = "enforcement"
SERVICES = ["apigatewayv2", "iam", "lambda", "logs", "sts"]

_HTTP_DISABLED = (404, {"message": "Not Found"})
_WS_DISABLED = (403, "Forbidden", ["connectionId", "message", "requestId"])
_ROLE_NOT_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
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
    """UpdateApi(DisableExecuteApiEndpoint=True) refuses an HTTP API's AutoDeploy and
    never-redeployed stages alike without a redeploy, but a WebSocket API's own
    never-redeployed stage keeps accepting handshakes until that stage is itself redeployed.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-disable-default-endpoint.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-disable-default-endpoint.html
    """
    marker = ctx.unique_name("sim2real-behav-dismanual-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"
    account_id = _account_id(ctx)
    agw = ctx.client("apigatewayv2")

    # --- HTTP API with two stages on the same deployment history: $default (AutoDeploy) and a
    # manually-deployed "manual" stage pinned to its own deployment.
    http_id = agw.create_api(Name=_name(ctx, "httpapi-dismanual"), ProtocolType="HTTP", Tags=_resource_tags())[
        "ApiId"
    ]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=http_id))
    http_integration = agw.create_integration(
        ApiId=http_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=http_id,
        RouteKey="GET /hit",
        Target=f"integrations/{http_integration}",
        AuthorizationType="AWS_IAM",
    )
    agw.create_stage(ApiId=http_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=http_id, StageName="$default"))
    manual_deployment_1 = agw.create_deployment(ApiId=http_id)["DeploymentId"]
    _wait_deployment_deployed(agw, http_id, manual_deployment_1)
    agw.create_stage(
        ApiId=http_id, StageName="manual", DeploymentId=manual_deployment_1, Tags=_resource_tags()
    )
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=http_id, StageName="manual"))
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account_id}:{http_id}/*/*")
    default_url = _invoke_url(ctx, http_id, "$default", "/hit")
    manual_url = _invoke_url(ctx, http_id, "manual", "/hit")

    # --- WebSocket twin: one manually-deployed stage, same deploy-gated disable semantics.
    ws_id = agw.create_api(
        Name=_name(ctx, "wsapi-dismanual"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=ws_id))
    ws_integration = agw.create_integration(
        ApiId=ws_id, IntegrationType="AWS_PROXY", IntegrationUri=fn["arn"], PayloadFormatVersion="1.0"
    )["IntegrationId"]
    agw.create_route(
        ApiId=ws_id,
        RouteKey="$connect",
        Target=f"integrations/{ws_integration}",
        AuthorizationType="AWS_IAM",
    )
    ws_deployment_1 = agw.create_deployment(ApiId=ws_id)["DeploymentId"]
    _wait_deployment_deployed(agw, ws_id, ws_deployment_1)
    agw.create_stage(ApiId=ws_id, StageName="live", DeploymentId=ws_deployment_1, Tags=_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=ws_id, StageName="live"))
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account_id}:{ws_id}/*/*", statement_id="apigw-invoke-ws"
    )

    # Beat 1 - positive control: both HTTP stages and the WebSocket stage serve signed requests.
    _wait_routes_deployed(ctx, [default_url, manual_url])
    for label, url in (("$default", default_url), ("manual", manual_url)):
        status, _, text = _http(ctx, "GET", url, headers=_sigv4_headers(ctx, url, {}))
        assert (status, text) == (200, marker), (
            f"precondition: HTTP stage {label} must serve a signed GET /hit with marker {marker!r} "
            f"while the endpoint is enabled; got {status}: {text[:200]!r}"
        )
    pre_status, _ = _attempt_handshake(ctx, ws_id, "live")
    assert pre_status == 101, f"precondition: the WebSocket stage must accept a signed handshake, got {pre_status!r}"

    # Beat 2 - disable the default endpoint for BOTH APIs.
    agw.update_api(ApiId=http_id, DisableExecuteApiEndpoint=True)
    agw.update_api(ApiId=ws_id, DisableExecuteApiEndpoint=True)
    flags = {
        "http": agw.get_api(ApiId=http_id).get("DisableExecuteApiEndpoint"),
        "ws": agw.get_api(ApiId=ws_id).get("DisableExecuteApiEndpoint"),
    }
    assert flags == {"http": True, "ws": True}, f"GetApi must report the flag set on both APIs, got {flags!r}"

    # Beat 3 - BOTH HTTP stages stop serving once the disable propagates: the manually-deployed
    # "manual" stage, still pinned to the deployment it had before the disable and never
    # redeployed since, refuses exactly like the AutoDeploy $default stage.
    _wait_status(ctx, default_url, 404, description="the $default (AutoDeploy) stage refusing once disabled")
    _wait_status(ctx, manual_url, 404, description="the manual (never redeployed) stage refusing once disabled")
    for label, url in (("$default", default_url), ("manual", manual_url)):
        refused = _signed_get_json(ctx, url)
        assert refused == _HTTP_DISABLED, (
            f"the disabled HTTP stage {label} must refuse with {_HTTP_DISABLED!r}, got {refused!r}"
        )

    # Beat 4 - the WebSocket twin's own never-redeployed stage, by contrast, keeps accepting
    # handshakes after the identical UpdateApi call: every read over a sustained window still
    # succeeds, exactly the delay the HTTP stages above did not show.
    ws_still_statuses = []
    for _ in range(6):
        ws_still_statuses.append(_attempt_handshake(ctx, ws_id, "live")[0])
        time.sleep(5.0)
    assert ws_still_statuses == [101] * len(ws_still_statuses), (
        f"the WebSocket stage must keep accepting handshakes after DisableExecuteApiEndpoint "
        f"until it is itself redeployed; statuses seen {ws_still_statuses!r}"
    )

    # Beat 5 - only once the WebSocket stage is redeployed does the disable take effect for it.
    ws_deployment_2 = agw.create_deployment(ApiId=ws_id)["DeploymentId"]
    _wait_deployment_deployed(agw, ws_id, ws_deployment_2)
    agw.update_stage(ApiId=ws_id, StageName="live", DeploymentId=ws_deployment_2)
    _wait_handshake_status(ctx, ws_id, "live", 403, description="the WebSocket stage refusing once redeployed")

    # Beat 6 - both HTTP stages and the WebSocket handshake now refuse, in the same instant.
    final_http = {
        "default": _signed_get_json(ctx, default_url),
        "manual": _signed_get_json(ctx, manual_url),
    }
    assert final_http == {"default": _HTTP_DISABLED, "manual": _HTTP_DISABLED}, (
        f"both HTTP stages must still refuse with {_HTTP_DISABLED!r}, got {final_http!r}"
    )
    ws_status, ws_body = _attempt_handshake(ctx, ws_id, "live")
    final_ws = (ws_status, ws_body.get("message"), sorted(ws_body)) if isinstance(ws_body, dict) else (ws_status, ws_body)
    assert final_ws == _WS_DISABLED, (
        f"the WebSocket handshake must now be refused with {_WS_DISABLED!r}, got {final_ws!r}"
    )


# ===== plumbing =====

_HANDLER = """
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _sigv4_headers(ctx, url, extra):
    """Headers of a GET to url signed for execute-api with the caller's own credentials."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    creds = Credentials(akid, secret, env.get("AWS_SESSION_TOKEN"))
    req = AWSRequest(method="GET", url=url, headers=dict(extra))
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ssl_context(verify):
    """The TLS trust ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, body=None, headers=None, timeout_s=40):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=timeout_s, context=_ssl_context(ctx.http_verify)
        ) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _signed_get_json(ctx, url):
    """(status, parsed JSON body) of one signed GET of url."""
    status, _, text = _http(ctx, "GET", url, headers=_sigv4_headers(ctx, url, {}))
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def _wait_status(ctx, url, want, *, stable_s=20.0, timeout_s=180.0, interval_s=1.0, description="status"):
    """Poll url with a fresh SigV4 signature each try until EVERY answer is `want` for `stable_s`
    seconds running. RAISES on timeout. A streak, not a single read, because the flag reaches the
    edge node by node."""
    deadline = time.monotonic() + timeout_s
    streak_start, seen = None, []
    while True:
        try:
            status = _http(ctx, "GET", url, headers=_sigv4_headers(ctx, url, {}))[0]
        except OSError as exc:
            status = f"connection error: {exc}"
        now = time.monotonic()
        seen.append(status)
        if status == want:
            streak_start = now if streak_start is None else streak_start
            if now - streak_start >= stable_s:
                return
        else:
            streak_start = None
        if now >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description}: {url} never answered {want} continuously for {stable_s}s within "
        f"{timeout_s}s; statuses seen {seen[-20:]!r}"
    )


def _wait_routes_deployed(ctx, urls, *, passes=3, timeout_s=150.0, interval_s=3.0):
    """Poll until EVERY url answers something other than 404 on `passes` consecutive rounds.
    RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    streak, last = 0, {}
    while True:
        ok = True
        for url in urls:
            try:
                status = _http(ctx, "GET", url)[0]
            except OSError as exc:  # execute-api DNS/TLS still settling
                status = f"connection error: {exc}"
            last[url] = status
            ok = ok and status != 404 and isinstance(status, int)
        streak = streak + 1 if ok else 0
        if streak >= passes:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"routes not all deployed within {timeout_s}s; last statuses {last!r}")


def _invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.api_url(api_id, stage or '$default')}/{p}"


def _wait_deployment_deployed(agw, api_id, deployment_id, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dep = agw.get_deployment(ApiId=api_id, DeploymentId=deployment_id)
        if dep.get("DeploymentStatus") == "DEPLOYED":
            return
        time.sleep(2)
    raise AssertionError("deployment never reached DEPLOYED")



def _reap_log_group(ctx, log_group, *, quiet_s=30.0, timeout_s=90.0, interval_s=5.0):
    """Delete log_group until it stays absent for quiet_s; RAISES if it still exists at timeout_s."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    quiet_since = None
    while time.monotonic() < deadline:
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
        if any(g["logGroupName"] == log_group for g in groups):
            quiet_since = None
            try:
                logs.delete_log_group(logGroupName=log_group)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        else:
            quiet_since = time.monotonic() if quiet_since is None else quiet_since
            if time.monotonic() - quiet_since >= quiet_s:
                return
        time.sleep(interval_s)
    if quiet_since is None:
        raise AssertionError(f"log group {log_group} still present after {timeout_s}s of deletes")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/", Tags=_tags_kv()
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, timeout=30):
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    role_arn = _create_role(ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements})

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got == _ROLE_NOT_ASSUMABLE:
                return None
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


def _attempt_handshake(ctx, api_id, stage, connect_timeout: float = 90.0) -> tuple[int, Any]:
    """Performs one SigV4-signed WebSocket upgrade handshake; returns (status, body)."""
    deadline = time.monotonic() + connect_timeout
    while True:
        status, body, sock = _do_handshake_attempt(ctx, api_id, stage)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if status in (403, 401) or status == 101 or time.monotonic() >= deadline:
            return status, body
        time.sleep(2)


def _wait_handshake_status(ctx, api_id, stage, want, *, stable_s=20.0, timeout_s=180.0, interval_s=2.0, description="status"):
    """Poll a fresh signed handshake until EVERY answer is `want` for `stable_s` seconds running."""
    deadline = time.monotonic() + timeout_s
    streak_start, seen = None, []
    while True:
        status, _, sock = _do_handshake_attempt(ctx, api_id, stage)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        now = time.monotonic()
        seen.append(status)
        if status == want:
            streak_start = now if streak_start is None else streak_start
            if now - streak_start >= stable_s:
                return
        else:
            streak_start = None
        if now >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"{description}: never answered {want} continuously for {stable_s}s; saw {seen[-20:]!r}")


def _do_handshake_attempt(ctx, api_id, stage) -> tuple[int, Any, Any]:
    """One SigV4-signed handshake to the stage's WebSocket URL, signed over its HTTP twin URL."""
    parsed = urlsplit(ctx.api_url(api_id, stage, websocket=True))
    secure = parsed.scheme == "wss"
    host = parsed.hostname
    port = parsed.port or (443 if secure else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    signed = _sigv4_headers(ctx, ctx.api_url(api_id, stage), {})
    raw_sock = socket.create_connection((host, port), timeout=20)
    sock = (
        _ssl_context(ctx.http_verify).wrap_socket(raw_sock, server_hostname=host)
        if secure else raw_sock
    )
    ws_key = base64.b64encode(os.urandom(16)).decode()
    header_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    for name, value in signed.items():
        if name.lower() == "host":
            continue
        header_lines.append(f"{name}: {value}")
    request = "\r\n".join(header_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
    sock.settimeout(20)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    header_blob, _, rest = resp.partition(b"\r\n\r\n")
    status_line = header_blob.split(b"\r\n", 1)[0] if header_blob else b""
    parts = status_line.split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        raise AssertionError(f"handshake produced no parseable HTTP status line: {status_line!r}")
    status = int(parts[1])
    if status == 101:
        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        assert expected_accept.encode() in header_blob, (
            f"a 101 upgrade must carry the matching Sec-WebSocket-Accept, got headers {header_blob!r}"
        )
        return status, None, sock
    content_length = None
    for line in header_blob.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            content_length = int(value.strip())
            break
    body_bytes = rest
    if content_length is not None:
        while len(body_bytes) < content_length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body_bytes += chunk
    try:
        body = json.loads(body_bytes.decode("utf-8")) if body_bytes else None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"refusal body is not valid JSON: {body_bytes!r} ({exc})") from exc
    return status, body, sock


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
