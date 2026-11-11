"""quick-create-lambda-target-invoked-directly-delivers-v2-event."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-create-lambda-target-invoked-directly-delivers-v2-event"

GROUP = "invoke"

SERVICES = ["apigatewayv2"]

#: Echoes the whole event back as JSON so the HTTP response IS the delivered event.
_ECHO_HANDLER = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"], "event": event}),
    }
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Quick create with a Lambda ARN Target synthesizes an AWS_PROXY 2.0 integration and $default
    route that serve a real request: the Lambda receives a payload format 2.0 event with rawPath,
    rawQueryString, cookies, lowercased headers and requestContext.http fields.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    marker = ctx.unique_name("sim2real-behav-qc-")
    fn = _create_lambda(ctx, _ECHO_HANDLER, env={"MARKER": marker})

    v2 = ctx.client("apigatewayv2")
    created = v2.create_api(
        Name=_name(ctx, "httpapi-qcinvoke"),
        ProtocolType="HTTP",
        Tags=_resource_tags(),
        Target=fn["arn"],
    )
    api_id = created["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    integs = v2.get_integrations(ApiId=api_id).get("Items", [])
    assert len(integs) == 1, f"quick create must synthesize exactly 1 integration, got {integs}"
    integ = integs[0]
    assert integ.get("IntegrationType") == "AWS_PROXY", (
        f"a Lambda-ARN Target must yield an AWS_PROXY integration, got "
        f"{integ.get('IntegrationType')}"
    )
    assert integ.get("IntegrationUri") == fn["arn"], (
        f"synthesized IntegrationUri mismatch: {integ.get('IntegrationUri')}"
    )
    assert integ.get("PayloadFormatVersion") == "2.0", (
        f"AWS_PROXY quick create must use PayloadFormatVersion 2.0, got "
        f"{integ.get('PayloadFormatVersion')}"
    )

    routes = v2.get_routes(ApiId=api_id).get("Items", [])
    assert len(routes) == 1 and routes[0].get("RouteKey") == "$default", (
        f"quick create with no RouteKey must synthesize exactly one $default route, got {routes}"
    )

    # Quick create does NOT grant API Gateway permission to invoke the function -- that is a
    # separate, documented step the caller must take.
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
    )

    request_headers = {"Cookie": "c1=v1; c2=v2", "X-Sim2Real-Probe": marker}
    status, _, text = _poll_http(
        _invoke_url(ctx, created["ApiEndpoint"], "$default", "/some/path") + "?a=1&b=two",
        accept=lambda s: s == 200,
        headers=request_headers,
        description="GET /some/path on the quick-created $default stage",
    )
    assert status == 200, (
        f"expected 200 from the quick-created stack, got {status}: {text[:300]!r}"
    )
    body = json.loads(text)
    assert body.get("marker") == marker, (
        f"expected this check's marker {marker!r} in the response, got {body.get('marker')!r} -- "
        f"the response did not come from this check's Lambda"
    )
    event = body["event"]

    assert event.get("version") == "2.0", (
        f"quick create's AWS_PROXY integration must deliver a version '2.0' event, got "
        f"{event.get('version')!r}"
    )
    assert event.get("routeKey") == "$default", (
        f"the synthesized $default route must be the one that matched, got "
        f"{event.get('routeKey')!r}"
    )
    assert event.get("rawPath") == "/some/path", (
        f"expected rawPath '/some/path', got {event.get('rawPath')!r}"
    )
    assert event.get("rawQueryString") == "a=1&b=two", (
        f"expected the verbatim rawQueryString 'a=1&b=two', got {event.get('rawQueryString')!r}"
    )
    assert event.get("cookies") == ["c1=v1", "c2=v2"], (
        f"expected the Cookie header split into cookies ['c1=v1', 'c2=v2'], got "
        f"{event.get('cookies')!r}"
    )
    headers = event.get("headers") or {}
    assert headers.get("x-sim2real-probe") == marker, (
        f"format 2.0 lowercases request header names; expected headers['x-sim2real-probe'] == "
        f"{marker!r}, got {headers.get('x-sim2real-probe')!r} (keys: {sorted(headers)})"
    )

    http_ctx = (event.get("requestContext") or {}).get("http") or {}
    assert http_ctx.get("method") == "GET", (
        f"expected requestContext.http.method 'GET', got {http_ctx.get('method')!r}"
    )
    assert http_ctx.get("path") == "/some/path", (
        f"expected requestContext.http.path '/some/path', got {http_ctx.get('path')!r}"
    )
    assert http_ctx.get("protocol") == "HTTP/1.1", (
        f"expected requestContext.http.protocol 'HTTP/1.1', got {http_ctx.get('protocol')!r}"
    )
    source_ip = http_ctx.get("sourceIp") or ""
    assert source_ip.count(".") == 3, (
        f"expected requestContext.http.sourceIp to be a dotted-quad caller address, got "
        f"{source_ip!r}"
    )
    user_agent = http_ctx.get("userAgent") or ""
    assert "Python-urllib" in user_agent, (
        f"expected requestContext.http.userAgent to carry this check's own HTTP client's User-"
        f"Agent, got {user_agent!r}"
    )


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout — never returns the last
    value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
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


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout.

    A freshly created stage's execute-api DNS/TLS and deployment propagation are real and measured
    in seconds, so the first request is polled to a condition with a bounded deadline.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


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
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
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
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda whose role is scoped to logs plus `permissions`, retrying through the IAM
    role-propagation window, then wait for Active. Registers teardown for the role, the function
    and the auto-created /aws/lambda/<name> log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
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
            # A brand-new role is not yet assumable by Lambda: the documented propagation window.
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
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
    ctx.on_cleanup(lambda: _cleanup_log_group(ctx, f"/aws/lambda/{name}"))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _cleanup_log_group(ctx, log_group_name, timeout_s=30.0, interval_s=2.0):
    """A Lambda's log group is created asynchronously by its first invocation and can still be
    materializing when teardown runs; ``delete_function`` never removes it. Retry the delete
    through a bounded window, tolerating a not-yet-created group; if it never appears within the
    window it may still appear later, out of this check's control."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                return
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
        # Create-or-adopt: a re-run against an account that already carries the statement.
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
