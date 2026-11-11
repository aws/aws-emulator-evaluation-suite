"""lambda-payload-format-1-0-and-2-0-envelopes-differ."""

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

# AWS behavior this check relies on: format 1.0 `queryStringParameters` keeps the LAST value of a
# repeated key, and its `headers` keep the request's original casing; format 2.0 splits the
# `Cookie` header into one `cookies` entry per cookie.

CHECK = "lambda-payload-format-1-0-and-2-0-envelopes-differ"

GROUP = "invoke"

SERVICES = ["apigatewayv2"]

#: One handler behind BOTH integrations. It echoes the event it was handed, so the only possible
#: explanation for a difference between the two responses is the integration's
#: PayloadFormatVersion — the handler, the API, the stage and the client request are identical.
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

_QUERY = "?p=1&p=2&single=s"
_COOKIE_HEADER = "c1=v1; c2=v2"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """One Lambda behind two integrations that differ only in PayloadFormatVersion receives the 1.0 envelope
    (httpMethod, path, multi-value maps, no rawPath or cookies) and the 2.0 envelope (rawPath, rawQueryString,
    cookies, no multi-value maps) for the same HTTP request."""
    marker = ctx.unique_name("sim2real-behav-pf-")
    fn = _create_lambda(ctx, _ECHO_HANDLER, env={"MARKER": marker})

    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=_name(ctx, "httpapi-payloadfmt"),
        ProtocolType="HTTP",
        Tags=_resource_tags(),
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    routes = {}
    for version, path in (("1.0", "/v1echo"), ("2.0", "/v2echo")):
        integration_id = v2.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            IntegrationMethod="POST",
            PayloadFormatVersion=version,
        )["IntegrationId"]
        v2.create_route(
            ApiId=api_id, RouteKey=f"GET {path}", Target=f"integrations/{integration_id}"
        )
        routes[version] = path

    v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
    )

    request_headers = {"Cookie": _COOKIE_HEADER, "X-Sim2Real-Probe": marker}
    events = {}
    for version, path in routes.items():
        status, _, text = _poll_http(
            _invoke_url(ctx, api_endpoint, "$default", path + _QUERY),
            accept=lambda s: s == 200,
            headers=request_headers,
            description=f"GET {path} on the PayloadFormatVersion={version} integration",
        )
        assert status == 200, (
            f"expected 200 from the PayloadFormatVersion={version} route {path}, got {status}: "
            f"{text[:300]!r}"
        )
        body = json.loads(text)
        assert body.get("marker") == marker, (
            f"expected the echo handler's marker {marker!r} in the {version} response, got "
            f"{body.get('marker')!r} — the response did not come from this check's Lambda"
        )
        events[version] = body["event"]

    v1, v2ev = events["1.0"], events["2.0"]

    # --- the version stamp itself
    assert v1.get("version") == "1.0", (
        f"expected event version '1.0' from the PayloadFormatVersion=1.0 integration, got "
        f"{v1.get('version')!r}"
    )
    assert v2ev.get("version") == "2.0", (
        f"expected event version '2.0' from the PayloadFormatVersion=2.0 integration, got "
        f"{v2ev.get('version')!r}"
    )

    # --- method and path live in different places
    assert v1.get("httpMethod") == "GET", (
        f"format 1.0 must carry a top-level httpMethod 'GET', got {v1.get('httpMethod')!r}"
    )
    assert v1.get("path") == "/v1echo", (
        f"format 1.0 must carry a top-level path '/v1echo', got {v1.get('path')!r}"
    )
    assert v1.get("resource") == "/v1echo", (
        f"format 1.0 must carry 'resource' (the matched route's path), expected '/v1echo', got "
        f"{v1.get('resource')!r}"
    )
    assert "rawPath" not in v1, (
        f"format 1.0 must NOT carry rawPath (that is the 2.0 field); event keys: {sorted(v1)}"
    )
    assert "httpMethod" not in v2ev, (
        f"format 2.0 must NOT carry a top-level httpMethod; event keys: {sorted(v2ev)}"
    )
    assert v2ev.get("rawPath") == "/v2echo", (
        f"format 2.0 must carry rawPath '/v2echo', got {v2ev.get('rawPath')!r}"
    )
    assert v2ev.get("rawQueryString") == _QUERY.lstrip("?"), (
        f"format 2.0 must carry the verbatim rawQueryString {_QUERY.lstrip('?')!r}, got "
        f"{v2ev.get('rawQueryString')!r}"
    )
    v2_http = (v2ev.get("requestContext") or {}).get("http") or {}
    assert v2_http.get("method") == "GET", (
        f"format 2.0 must carry requestContext.http.method 'GET', got {v2_http.get('method')!r}"
    )
    v1_rc = v1.get("requestContext") or {}
    assert v1_rc.get("httpMethod") == "GET", (
        f"format 1.0 must carry requestContext.httpMethod 'GET', got {v1_rc.get('httpMethod')!r}"
    )
    assert "http" not in v1_rc, (
        f"format 1.0 must NOT carry the 2.0 requestContext.http object; requestContext keys: "
        f"{sorted(v1_rc)}"
    )
    source_ip = ((v1_rc.get("identity") or {}).get("sourceIp")) or ""
    assert source_ip.count(".") == 3, (
        f"format 1.0 must carry requestContext.identity.sourceIp as the caller's dotted-quad "
        f"address, got {source_ip!r}"
    )

    # --- multi-value maps exist only in 1.0
    v1_mv_headers = v1.get("multiValueHeaders")
    assert isinstance(v1_mv_headers, dict), (
        f"format 1.0 must carry a multiValueHeaders map, got {type(v1_mv_headers).__name__} "
        f"({v1_mv_headers!r})"
    )
    assert v1_mv_headers.get("X-Sim2Real-Probe") == [marker], (
        f"format 1.0 multiValueHeaders must list each header value under the ORIGINAL request "
        f"casing (1.0 does not lowercase header names), expected "
        f"['X-Sim2Real-Probe'] == [{marker!r}], got {v1_mv_headers.get('X-Sim2Real-Probe')!r}"
    )
    assert "multiValueHeaders" not in v2ev, (
        f"format 2.0 must NOT carry multiValueHeaders; event keys: {sorted(v2ev)}"
    )
    v1_mv_qs = v1.get("multiValueQueryStringParameters")
    assert isinstance(v1_mv_qs, dict), (
        f"format 1.0 must carry multiValueQueryStringParameters for {_QUERY!r}, got "
        f"{v1_mv_qs!r}"
    )
    assert v1_mv_qs.get("p") == ["1", "2"], (
        f"format 1.0 multiValueQueryStringParameters['p'] must list both sent values ['1', '2'], "
        f"got {v1_mv_qs.get('p')!r}"
    )
    assert "multiValueQueryStringParameters" not in v2ev, (
        f"format 2.0 must NOT carry multiValueQueryStringParameters; event keys: {sorted(v2ev)}"
    )

    # --- the repeated query key collapses differently
    v1_qs = v1.get("queryStringParameters") or {}
    v2_qs = v2ev.get("queryStringParameters") or {}
    assert v1_qs.get("p") == "2", (
        f"format 1.0 queryStringParameters['p'] must hold a SINGLE value (the last one sent, "
        f"'2'), got {v1_qs.get('p')!r}"
    )
    assert v2_qs.get("p") == "1,2", (
        f"format 2.0 must comma-join the repeated query key: expected queryStringParameters['p'] "
        f"== '1,2', got {v2_qs.get('p')!r}"
    )
    assert v1_qs.get("single") == "s" and v2_qs.get("single") == "s", (
        f"both formats must pass the single-valued query parameter through unchanged, got "
        f"1.0={v1_qs.get('single')!r} 2.0={v2_qs.get('single')!r}"
    )

    # --- cookies are a 2.0-only field
    assert "cookies" not in v1, (
        f"format 1.0 must NOT carry a cookies field (the Cookie header stays in headers); "
        f"event keys: {sorted(v1)}"
    )
    assert (v1.get("headers") or {}).get("Cookie") == _COOKIE_HEADER, (
        f"format 1.0 must pass the Cookie header through verbatim under its original casing as "
        f"headers['Cookie'] == {_COOKIE_HEADER!r}, got {(v1.get('headers') or {}).get('Cookie')!r}"
    )
    assert v2ev.get("cookies") == ["c1=v1", "c2=v2"], (
        f"format 2.0 must split the Cookie header into the cookies list ['c1=v1', 'c2=v2'], got "
        f"{v2ev.get('cookies')!r}"
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
    """Poll probe() until predicate(result); return it. RAISES on timeout — never returns the
    last value, so a never-satisfied condition can never pass."""
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
    """Detach and delete the role's policies, then the role; only an already-absent role or
    policy is tolerated."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


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
    # LIFO: the function goes first so it cannot write its log group back after the delete.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _delete_log_group(ctx, log_group_name):
    """A function that never logged has no log group; that is the only error tolerated."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
