"""lambda-proxy-status-keyed-response-mapping-rewrites-500-to-403."""

from __future__ import annotations

import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-proxy-status-keyed-response-mapping-rewrites-500-to-403"

GROUP = "routing"

SERVICES = ["apigatewayv2", "lambda"]

#: Always answers 500, with a body the client could never confuse with the gateway's own text.
_HANDLER = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 500,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"origin": "lambda", "note": "deliberate-500"}),
    }
"""


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
    """A status-keyed ResponseParameters entry on an AWS_PROXY Lambda integration rewrites the
    client-visible status 500->403 and appends a header, while an unmapped twin route to the
    same Lambda still shows the Lambda's own 500 with no appended header.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html
    """
    fn = _create_lambda(ctx, _HANDLER)
    agw = ctx.client("apigatewayv2")
    account = ctx.account

    created_api = agw.create_api(
        Name=_name(ctx, "httpapi-statusmap"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    mapped_integration = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
        ResponseParameters={
            "500": {
                "overwrite:statuscode": "403",
                "append:header.x-sim2real-mapped": "$context.requestId",
            }
        },
    )["IntegrationId"]
    plain_integration = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=api_id, RouteKey="GET /mapped", Target=f"integrations/{mapped_integration}"
    )
    agw.create_route(
        ApiId=api_id, RouteKey="GET /plain", Target=f"integrations/{plain_integration}"
    )
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*")
    agw.create_stage(
        ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=mapped_integration)
    assert stored.get("ResponseParameters", {}).get("500", {}).get(
        "overwrite:statuscode"
    ) == "403", (
        f"the mapping must be stored as authored before it can be enforced; GetIntegration "
        f"reports ResponseParameters {stored.get('ResponseParameters')!r}"
    )

    # --- the unmapped twin: the Lambda's own 500, unaltered
    plain_status, plain_headers, plain_text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", "/plain"),
        verify=ctx.http_verify,
        budget_s=lambda want: _budget_s(ctx, want),
        accept=_is_lambda_500,
        description="GET /plain (the unmapped twin route)",
    )
    assert plain_status == 500, (
        f"the unmapped twin must pass the Lambda's own 500 through unchanged, got {plain_status}: "
        f"{plain_text[:300]!r}"
    )
    assert json.loads(plain_text).get("note") == "deliberate-500", (
        f"the unmapped twin must reach the same Lambda, got body {plain_text[:300]!r}"
    )
    assert _hdr(plain_headers, "x-sim2real-mapped") is None, (
        f"the unmapped twin must NOT carry the appended response header; got "
        f"{_hdr(plain_headers, 'x-sim2real-mapped')!r} (a target that appends it unconditionally "
        f"is not evaluating the status-keyed ResponseParameters)"
    )

    # --- the mapped route: same Lambda, same instant, status and header rewritten
    mapped_status, mapped_headers, mapped_text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", "/mapped"),
        verify=ctx.http_verify,
        budget_s=lambda want: _budget_s(ctx, want),
        accept=lambda r: r[0] == 403,
        description="GET /mapped (the route carrying the status-keyed response mapping)",
    )
    assert mapped_status == 403, (
        f"ResponseParameters['500']['overwrite:statuscode'] = '403' must rewrite the "
        f"client-visible status while the Lambda itself answered 500 (proved by the twin above), "
        f"got {mapped_status}: {mapped_text[:300]!r}"
    )
    assert json.loads(mapped_text) == json.loads(plain_text), (
        f"the status-keyed mapping rewrites the status code and header only; the response body "
        f"must still be the Lambda's own unmodified body {plain_text[:300]!r}, got "
        f"{mapped_text[:300]!r}"
    )
    injected = _hdr(mapped_headers, "x-sim2real-mapped")
    assert injected and len(injected) >= 8, (
        f"expected the appended response header x-sim2real-mapped populated from "
        f"$context.requestId, got {injected!r}"
    )


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _budget_s(ctx, want):
    """`want` seconds, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _is_lambda_500(result):
    """A 500 whose body is the Lambda's own JSON (not the gateway's pre-propagation 500)."""
    status, _, text = result
    if status != 500:
        return False
    try:
        return json.loads(text).get("note") == "deliberate-500"
    except (ValueError, AttributeError):
        return False


def _hdr(headers, name):
    """The first value of a response header, or None. `headers` is a list of (name, value)."""
    for key, value in headers:
        if key == name:
            return value
    return None


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition", budget_s=None
):
    """Poll probe() until predicate(result); return it. Raises TimeoutError on timeout."""
    if budget_s is not None:
        timeout_s = budget_s(timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20, *, verify=True):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=timeout_s, context=_ssl_context(verify)
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
    verify=True,
    budget_s=None,
):
    """Poll an invoke URL until accept((status, headers, text)); return it.

    Raises TimeoutError on timeout.
    """
    if budget_s is not None:
        timeout_s = budget_s(timeout_s)
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, verify=verify)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
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
        Tags=[{"Key": k, "Value": v} for k, v in _resource_tags().items()],
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
        budget_s=lambda want: _budget_s(ctx, want),
    )
    # LIFO: the function is deleted first, then the log group it can no longer write to.
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
        budget_s=lambda want: _budget_s(ctx, want),
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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
