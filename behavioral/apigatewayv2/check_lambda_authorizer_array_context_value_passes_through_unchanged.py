"""lambda-authorizer-array-context-value-passes-through-unchanged."""

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

CHECK = "lambda-authorizer-array-context-value-passes-through-unchanged"

GROUP = "authorizers"

SERVICES = ["apigatewayv2"]

#: Returns isAuthorized=True with a `context` map carrying a JSON ARRAY value.
_ARRAY_CONTEXT_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    return {"isAuthorized": True, "context": {"roles": ["admin", "user"]}}
"""

#: The contrasting control: the same shape of authorizer, but every context value is a primitive.
_PRIMITIVE_CONTEXT_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    return {"isAuthorized": True, "context": {"role": "admin"}}
"""

_ECHO_BACKEND_CODE = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["MARKER"],
            "authorizer": (event.get("requestContext") or {}).get("authorizer"),
        }),
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
    """A 2.0 simple-response authorizer context holding a JSON array reaches the backend unchanged.

    The docs restrict context values to primitives, but HTTP APIs pass the array through verbatim;
    a primitive-only context on the same API is the contrast.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    """
    marker = ctx.unique_name("sim2real-behav-authctx2-")
    array_authz_fn = _create_lambda(ctx, _ARRAY_CONTEXT_AUTHORIZER_CODE)
    primitive_authz_fn = _create_lambda(ctx, _PRIMITIVE_CONTEXT_AUTHORIZER_CODE)
    backend_fn = _create_lambda(ctx, _ECHO_BACKEND_CODE, env={"MARKER": marker})

    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=_name(ctx, "httpapi-authbad"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    integ_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=backend_fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]

    account = _account_id(ctx)
    routes = {}
    for label, authz_fn in (
        ("array", array_authz_fn),
        ("primitive", primitive_authz_fn),
    ):
        authorizer_uri = (
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{authz_fn['arn']}/invocations"
        )
        authorizer_id = v2.create_authorizer(
            ApiId=api_id,
            Name=ctx.unique_name(f"sim2real-behav-authz-{label}-"),
            AuthorizerType="REQUEST",
            AuthorizerUri=authorizer_uri,
            IdentitySource=["$request.header.Authorization"],
            AuthorizerPayloadFormatVersion="2.0",
            EnableSimpleResponses=True,
            AuthorizerResultTtlInSeconds=0,
        )["AuthorizerId"]
        route_key = f"GET /{label}"
        v2.create_route(
            ApiId=api_id,
            RouteKey=route_key,
            Target=f"integrations/{integ_id}",
            AuthorizationType="CUSTOM",
            AuthorizerId=authorizer_id,
        )
        _allow_apigw_invoke(
            ctx,
            authz_fn["name"],
            f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{authorizer_id}",
            statement_id=f"apigw-invoke-authz-{label}",
        )
        routes[label] = f"/{label}"

    v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx,
        backend_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
        statement_id="apigw-invoke-backend",
    )

    # --- contrast: a primitive-only context reaches the backend unchanged
    status, _, text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", routes["primitive"]),
        accept=lambda s: s == 200,
        headers={"Authorization": "whatever"},
        description="GET /primitive with a primitive-only authorizer context",
    )
    assert status == 200, (
        f"expected 200 from the primitive-context authorizer's route, got {status}: "
        f"{text[:300]!r}"
    )
    body = json.loads(text)
    assert body.get("marker") == marker, (
        f"expected this check's marker {marker!r} from the backend, got {text[:300]!r}"
    )
    assert (body.get("authorizer") or {}).get("lambda") == {"role": "admin"}, (
        f"expected requestContext.authorizer.lambda == {{'role': 'admin'}}, got "
        f"{body.get('authorizer')!r}"
    )

    # --- the array-valued context: accepted, request let through, array delivered unchanged
    status, _, text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", routes["array"]),
        accept=lambda s: s == 200,
        headers={"Authorization": "whatever"},
        description="GET /array with an array-valued authorizer context",
    )
    assert status == 200, (
        f"an authorizer context map with an array value must still let the request through "
        f"(real AWS does not enforce the documented primitives-only restriction for HTTP APIs), "
        f"got {status}: {text[:300]!r}"
    )
    body = json.loads(text)
    assert body.get("marker") == marker, (
        f"expected this check's marker {marker!r} from the backend, got {text[:300]!r}"
    )
    assert (body.get("authorizer") or {}).get("lambda") == {"roles": ["admin", "user"]}, (
        f"expected requestContext.authorizer.lambda.roles to arrive as the JSON array "
        f"['admin', 'user'] UNCHANGED, got {body.get('authorizer')!r}"
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
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout.

    A fresh stage's execute-api DNS/TLS and deployment take seconds to propagate.
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
    """Create a Lambda (role: logs plus `permissions`) through IAM propagation; wait for Active.

    Registers teardown for the role, the function and its /aws/lambda/<name> log group.
    """
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
    """Delete a Lambda's log group, retrying while it may still be materializing.

    The group is created asynchronously on first invocation and delete_function never removes it.
    """
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
