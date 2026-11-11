"""websocket-header-mapping-connect-only."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import textwrap
import time
import zipfile
from io import BytesIO
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-header-mapping-connect-only"
GROUP = "routing"
SERVICES = ["apigatewayv2", "iam", "lambda", "logs"]

_PREFIX = "sim2real-behav-"

_SRC_HEADER = "x-sim2real-src"
_DST_HEADER = "x-sim2real-dst"
_WS_AUTHZ_HEADER = "x-sim2real-wsauthz"
_ORIGIN_AUTHZ_HEADER = "x-sim2real-originauthz"

_ROUTE_ONLY_CONNECT = (
    "BadRequestException",
    "Request parameters are only supported for the $connect route in WEBSOCKET APIs",
)


_ROLE_NOT_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A WebSocket $connect route accepts a route-level request parameter and the sibling
    integration's RequestParameters mapping it into a header that reaches an HTTP backend; the
    identical declaration on a non-$connect route is refused with AWS's exact message.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-data-mapping.html
    """
    stack = _setup_stack(ctx)
    agw = stack["agw"]
    api_id = stack["api_id"]

    # --- $connect: the route-level request parameter and the integration's header mapping that
    # sources it were both accepted when the route and integration were created together.
    got_route = agw.get_route(ApiId=api_id, RouteId=stack["connect_route_id"])
    assert got_route.get("RequestParameters") == {
        f"route.request.header.{_SRC_HEADER}": {"Required": False}
    }, f"GetRoute must round-trip the declared $connect request parameter, got {got_route.get('RequestParameters')!r}"
    got_integ = agw.get_integration(ApiId=api_id, IntegrationId=stack["connect_integ_id"])
    assert (
        got_integ.get("RequestParameters", {}).get(f"integration.request.header.{_DST_HEADER}")
        == f"route.request.header.{_SRC_HEADER}"
    ), f"GetIntegration must store the header mapping as authored, got {got_integ.get('RequestParameters')!r}"

    # The mapping takes effect on the wire: a handshake carrying the source header reaches the
    # HTTP backend (through the integration) bearing the mapped destination header.
    marker = ctx.unique_name("sim2real-behav-conn-")
    _attempt_handshake(
        ctx, stack["wss_url"], extra_headers={_SRC_HEADER: marker, _WS_AUTHZ_HEADER: "allow"}
    )
    event = _poll_until(
        lambda: _latest_logged_event(ctx, stack["origin_log_group"], marker),
        lambda e: e is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="the HTTP backend's logged event for this $connect handshake",
    )
    assert event["headers"].get(_DST_HEADER) == marker, (
        f"the integration's RequestParameters mapping must deliver the client's {_SRC_HEADER!r} "
        f"handshake header to the HTTP backend as {_DST_HEADER!r}; the backend saw headers "
        f"{event['headers']!r}"
    )

    # --- A non-$connect route refuses the identical route-level declaration outright, with AWS's
    # exact message -- the documented restriction that route-level request parameters (header,
    # querystring and their multi-value forms) exist only on $connect.
    expect_error(
        lambda: agw.create_route(
            ApiId=api_id,
            RouteKey="ping",
            RequestParameters={f"route.request.header.{_SRC_HEADER}": {"Required": False}},
        ),
        *_ROUTE_ONLY_CONNECT,
    )

    # Positive control: the same route key, with no request parameters, is accepted -- so the
    # refusal above is about the request-parameter declaration, not about "ping" being invalid.
    plain_route_id = agw.create_route(
        ApiId=api_id, RouteKey="ping", Target=f"integrations/{stack['plain_integ_id']}"
    )["RouteId"]
    plain = agw.get_route(ApiId=api_id, RouteId=plain_route_id)
    assert plain.get("RequestParameters", {}) == {}, (
        f"the control route must carry no request parameters, got {plain.get('RequestParameters')!r}"
    )


# ===== plumbing =====


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


_ORIGIN_HANDLER = """
import json


def lambda_handler(event, context):
    print("EVENT " + json.dumps({"headers": event.get("headers") or {}}))
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"ok": True}),
    }
"""

#: A fixed-Allow WebSocket REQUEST authorizer (classic IAM-policy response format).
_WS_AUTHORIZER_HANDLER = """
def lambda_handler(event, context):
    return {
        "principalId": "sim2real-caller",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": event.get("methodArn") or event.get("routeArn"),
            }],
        },
    }
"""

#: A fixed-Allow HTTP API REQUEST authorizer (payload format 2.0 simple response).
_HTTP_AUTHORIZER_HANDLER = """
def lambda_handler(event, context):
    return {"isAuthorized": True}
"""


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


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


def _create_lambda(ctx, handler_code, timeout=30):
    """Create a Lambda (role scoped to logs), retrying through the IAM role-propagation window,
    then wait for Active."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

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

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got == _ROLE_NOT_ASSUMABLE:
                return None  # brand-new role not yet assumable by Lambda
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


def _reap_log_group(ctx, log_group_name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete log_group_name until `reads` consecutive reads find it absent. Raises if it is
    still coming back when budget_s runs out: a residue is declared, never hung on."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
        if any(g["logGroupName"] == log_group_name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=log_group_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {log_group_name} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


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
    raise AssertionError("websocket deployment never reached DEPLOYED")


def _setup_stack(ctx) -> dict:
    agw = ctx.client("apigatewayv2")
    account_id = ctx.account

    origin_fn = _create_lambda(ctx, _ORIGIN_HANDLER)
    http_authz_fn = _create_lambda(ctx, _HTTP_AUTHORIZER_HANDLER)
    origin_id = agw.create_api(
        Name=_name(ctx, "httpapi-origin"), ProtocolType="HTTP", Tags=_resource_tags()
    )["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=origin_id))

    # The origin route is reachable over the internet (WebSocket HTTP integrations support no
    # private connection type), so it requires an authorizer like any other invoked HTTP route.
    origin_authorizer_id = agw.create_authorizer(
        ApiId=origin_id,
        Name=_name(ctx, "originauthz"),
        AuthorizerType="REQUEST",
        AuthorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{http_authz_fn['arn']}/invocations"
        ),
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        IdentitySource=[f"$request.header.{_ORIGIN_AUTHZ_HEADER}"],
    )["AuthorizerId"]
    _allow_apigw_invoke(
        ctx,
        http_authz_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account_id}:{origin_id}/authorizers/{origin_authorizer_id}",
        statement_id="apigw-invoke-originauthz",
    )

    origin_integration = agw.create_integration(
        ApiId=origin_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=origin_fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=origin_id,
        RouteKey="POST /origin",
        Target=f"integrations/{origin_integration}",
        AuthorizationType="CUSTOM",
        AuthorizerId=origin_authorizer_id,
    )
    agw.create_stage(ApiId=origin_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=origin_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, origin_fn["name"], f"arn:aws:execute-api:{ctx.region}:{account_id}:{origin_id}/*/*"
    )
    origin_url = _invoke_url(ctx, origin_id, "$default", "/origin")

    api_id = agw.create_api(
        Name=_name(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    ws_authz_fn = _create_lambda(ctx, _WS_AUTHORIZER_HANDLER)
    ws_authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        Name=_name(ctx, "wsauthz"),
        AuthorizerType="REQUEST",
        AuthorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{ws_authz_fn['arn']}/invocations"
        ),
        IdentitySource=[f"route.request.header.{_WS_AUTHZ_HEADER}"],
    )["AuthorizerId"]
    _allow_apigw_invoke(
        ctx,
        ws_authz_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{ws_authorizer_id}",
        statement_id="apigw-invoke-wsauthz",
    )

    connect_integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP",
        IntegrationUri=origin_url,
        IntegrationMethod="POST",
        RequestParameters={
            f"integration.request.header.{_DST_HEADER}": f"route.request.header.{_SRC_HEADER}",
            f"integration.request.header.{_ORIGIN_AUTHZ_HEADER}": "'allow'",
        },
    )["IntegrationId"]
    agw.create_integration_response(
        ApiId=api_id, IntegrationId=connect_integ_id, IntegrationResponseKey="$default"
    )
    connect_route_id = agw.create_route(
        ApiId=api_id,
        RouteKey="$connect",
        AuthorizationType="CUSTOM",
        AuthorizerId=ws_authorizer_id,
        RequestParameters={f"route.request.header.{_SRC_HEADER}": {"Required": False}},
        Target=f"integrations/{connect_integ_id}",
    )["RouteId"]

    plain_integ_id = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=origin_fn["arn"], PayloadFormatVersion="1.0"
    )["IntegrationId"]
    _allow_apigw_invoke(
        ctx,
        origin_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
        statement_id="apigw-invoke-ws-plain",
    )

    stage_name = "test"
    deployment = agw.create_deployment(ApiId=api_id)
    _wait_deployment_deployed(agw, api_id, deployment["DeploymentId"])
    agw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=deployment["DeploymentId"], Tags=_resource_tags())
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName=stage_name))

    wss_url = ctx.api_url(api_id, stage_name, websocket=True)
    return {
        "agw": agw,
        "api_id": api_id,
        "wss_url": wss_url,
        "connect_route_id": connect_route_id,
        "connect_integ_id": connect_integ_id,
        "plain_integ_id": plain_integ_id,
        "origin_log_group": f"/aws/lambda/{origin_fn['name']}",
    }


def _latest_logged_event(ctx, log_group, needle):
    """The most recent ``EVENT {...}`` log line whose headers mention ``needle``, parsed, or None."""
    logs = ctx.client("logs")
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=log_group, filterPattern=f'"{needle}"'
        )
        events = [e["message"] for page in pages for e in page.get("events", [])]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise
    for message in reversed(events):
        idx = message.find("EVENT ")
        if idx == -1:
            continue
        try:
            payload = json.loads(message[idx + len("EVENT "):])
        except ValueError:
            continue
        if needle in json.dumps(payload.get("headers") or {}):
            return payload
    return None


def _ssl_context(verify):
    """The TLS trust ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _attempt_handshake(ctx, ws_url: str, extra_headers: dict, timeout_s=40.0) -> None:
    """Sends one raw WebSocket upgrade request carrying extra_headers. The response status is not
    the subject under test here -- only that the attempt reaches the integration's backend."""
    parsed = urlparse(ws_url)
    secure = parsed.scheme == "wss"
    host = parsed.hostname
    port = parsed.port or (443 if secure else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    raw_sock = socket.create_connection((host, port), timeout=timeout_s)
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
    for name, value in extra_headers.items():
        header_lines.append(f"{name}: {value}")
    request = "\r\n".join(header_lines) + "\r\n\r\n"
    sock.sendall(request.encode("utf-8"))
    sock.settimeout(timeout_s)
    try:
        sock.recv(4096)
    except OSError:
        pass
    sock.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
