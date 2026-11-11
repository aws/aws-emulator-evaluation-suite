"""parameter-mapping-rewrites-a-real-request-and-response."""

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

CHECK = "parameter-mapping-rewrites-a-real-request-and-response"

GROUP = "routing"

SERVICES = ["apigatewayv2"]

#: The origin echoes what reached it: request mapping happens between client and backend, so only
#: the backend can observe it.
_ORIGIN_HANDLER = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "marker": os.environ["MARKER"],
                "headers": event.get("headers") or {},
                "query": event.get("queryStringParameters") or {},
                "rawPath": event.get("rawPath"),
            }
        ),
    }
"""

_CLIENT_HEADERS = {
    "X-Sim2Real-Client": "should-be-removed",
    "X-Sim2Real-Keep": "keep-me",
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """HTTP_PROXY parameter mapping injects, removes and appends request headers/query seen by the
    backend and rewrites the client-visible status 200->201 with an appended header; an unmapped
    twin route to the same backend shows none of these effects.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html
    """
    marker = ctx.unique_name("sim2real-behav-pm-")
    fn = _create_lambda(ctx, _ORIGIN_HANDLER, env={"MARKER": marker})
    agw = ctx.client("apigatewayv2")
    account = _account_id(ctx)

    # --- the origin API (an ordinary Lambda-backed HTTP API used as the HTTP_PROXY target)
    origin = agw.create_api(
        Name=_name(ctx, "httpapi-origin"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    origin_id, origin_endpoint = origin["ApiId"], origin["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=origin_id))
    origin_integration = agw.create_integration(
        ApiId=origin_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=origin_id,
        RouteKey="GET /origin",
        Target=f"integrations/{origin_integration}",
    )
    agw.create_stage(ApiId=origin_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=origin_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{origin_id}/*/*"
    )
    origin_url = _invoke_url(ctx, origin_endpoint, "$default", "/origin")

    status, _, text = _poll_http(
        origin_url,
        accept=lambda s: s == 200,
        description="the origin API serving GET /origin before it is proxied",
    )
    assert status == 200 and json.loads(text).get("marker") == marker, (
        f"precondition: the origin API must serve its echo backend (marker {marker!r}), got "
        f"{status}: {text[:300]!r}"
    )

    # --- the front API: one MAPPED route and one unmapped twin, both proxying the same origin
    front = agw.create_api(
        Name=_name(ctx, "httpapi-front"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    front_id, front_endpoint = front["ApiId"], front["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=front_id))
    mapped_integration = agw.create_integration(
        ApiId=front_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=origin_url,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
        RequestParameters={
            "overwrite:header.x-sim2real-injected": "$context.requestId",
            "remove:header.x-sim2real-client": "''",
            "append:querystring.injected": "static-q",
        },
        ResponseParameters={
            "200": {
                "overwrite:statuscode": "201",
                "append:header.x-sim2real-mapped": "mapped-static",
            }
        },
    )["IntegrationId"]
    plain_integration = agw.create_integration(
        ApiId=front_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=origin_url,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=front_id, RouteKey="GET /mapped", Target=f"integrations/{mapped_integration}"
    )
    agw.create_route(
        ApiId=front_id, RouteKey="GET /plain", Target=f"integrations/{plain_integration}"
    )
    agw.create_stage(ApiId=front_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=front_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=front_id, IntegrationId=mapped_integration)
    assert stored.get("RequestParameters", {}).get(
        "overwrite:header.x-sim2real-injected"
    ) == "$context.requestId", (
        f"the mapping must be stored as authored before it can be enforced; GetIntegration "
        f"reports RequestParameters {stored.get('RequestParameters')!r}"
    )

    # --- the unmapped twin: what the origin sees without any mapping
    plain_status, plain_headers, plain_text = _poll_http(
        _invoke_url(ctx, front_endpoint, "$default", "/plain"),
        accept=lambda s: s == 200,
        headers=dict(_CLIENT_HEADERS),
        description="GET /plain (the unmapped twin route)",
    )
    plain = json.loads(plain_text)
    assert plain_status == 200, (
        f"the unmapped twin must pass the origin's own 200 through unchanged, got {plain_status}: "
        f"{plain_text[:300]!r}"
    )
    assert _hdr(plain_headers, "x-sim2real-mapped") is None, (
        f"the unmapped twin must NOT carry the appended response header; got "
        f"{_hdr(plain_headers, 'x-sim2real-mapped')!r} (a target that appends it unconditionally "
        f"is not evaluating ResponseParameters)"
    )
    assert plain["headers"].get("x-sim2real-client") == "should-be-removed", (
        f"the unmapped twin must forward the client header verbatim, so the mapped route's removal "
        f"is attributable to the mapping; origin saw {plain['headers'].get('x-sim2real-client')!r}"
    )
    assert "x-sim2real-injected" not in plain["headers"], (
        f"the unmapped twin must NOT reach the origin with an injected header; origin saw "
        f"{sorted(plain['headers'])}"
    )
    assert "injected" not in plain["query"], (
        f"the unmapped twin must NOT reach the origin with an appended query parameter; origin saw "
        f"query {plain['query']!r}"
    )

    # --- the mapped route, in the same instant, same origin, same client headers
    mapped_status, mapped_headers, mapped_text = _poll_http(
        _invoke_url(ctx, front_endpoint, "$default", "/mapped"),
        accept=lambda s: s in (200, 201),
        headers=dict(_CLIENT_HEADERS),
        description="GET /mapped (the route carrying the parameter mapping)",
    )
    mapped = json.loads(mapped_text)
    assert mapped.get("marker") == marker, (
        f"the mapped route must still reach the same origin backend (marker {marker!r}), got "
        f"{mapped_text[:300]!r}"
    )

    # response mapping: status rewritten, header appended
    assert mapped_status == 201, (
        f"ResponseParameters['200']['overwrite:statuscode'] = '201' must rewrite the client-visible "
        f"status while the integration itself answered 200 (proved by the twin above), got "
        f"{mapped_status}"
    )
    assert _hdr(mapped_headers, "x-sim2real-mapped") == "mapped-static", (
        f"expected the appended response header x-sim2real-mapped == 'mapped-static', got "
        f"{_hdr(mapped_headers, 'x-sim2real-mapped')!r}"
    )

    # request mapping: injected, removed, appended — all observed at the ORIGIN
    injected = mapped["headers"].get("x-sim2real-injected")
    assert injected and len(injected) >= 8, (
        f"the origin must receive x-sim2real-injected populated from $context.requestId, got "
        f"{injected!r} (the client never sent this header)"
    )
    assert injected not in _CLIENT_HEADERS.values(), (
        f"the injected header must carry the gateway's request id, not a client-supplied value; "
        f"got {injected!r}"
    )
    assert "x-sim2real-client" not in mapped["headers"], (
        f"remove:header.x-sim2real-client must strip the header before the origin sees it; origin "
        f"received headers {sorted(mapped['headers'])}"
    )
    assert mapped["headers"].get("x-sim2real-keep") == "keep-me", (
        f"the removal must be scoped to the one named header: x-sim2real-keep must still arrive, "
        f"got {mapped['headers'].get('x-sim2real-keep')!r}"
    )
    assert mapped["query"].get("injected") == "static-q", (
        f"append:querystring.injected must add 'injected=static-q' to the request the origin "
        f"receives, got query {mapped['query']!r}"
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


def _hdr(headers, name):
    """The first value of a response header, or None. `headers` is a list of (name, value)."""
    for key, value in headers:
        if key == name:
            return value
    return None


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
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
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
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. Teardown registered for role, function and the
    auto-created /aws/lambda/<name> log group."""
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
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
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
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _delete_log_group_if_present(ctx, log_group_name):
    """Lambda creates its log group on the first logged invocation, so it can be absent."""
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
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
