"""lambda-authorizer-payload-format-2-0-iam-policy-response."""

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

CHECK = "lambda-authorizer-payload-format-2-0-iam-policy-response"

GROUP = "authorizers"

SERVICES = ["apigatewayv2", "iam", "lambda", "logs"]

_PREFIX = "sim2real-behav-"

_ROLE_NOT_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)

_VALID_TOKEN = "sim2real-let-me-in"
_DENY_TOKEN = "sim2real-deny-me"

# AuthorizerPayloadFormatVersion 2.0 with EnableSimpleResponses absent (so not True) still
# requires the Lambda to return an IAM-policy-style decision, with the policy's Resource set
# from the 2.0 event's own `routeArn` field (there is no `methodArn` under 2.0), plus a
# `context` map of key-value pairs carried alongside the policy.
_IAM_POLICY_AUTHORIZER_CODE = f"""
def lambda_handler(event, context):
    headers = event.get("headers") or {{}}
    token = headers.get("authorization", "")
    effect = "Allow" if token == "{_VALID_TOKEN}" else "Deny"
    return {{
        "principalId": "sim2real-user",
        "policyDocument": {{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event["routeArn"],
                }}
            ],
        }},
        "context": {{"tenant": "sim2real-acme", "decision": effect}},
    }}
"""

_ECHO_BACKEND_CODE = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "marker": os.environ["MARKER"],
                "authorizer": (event.get("requestContext") or {}).get("authorizer"),
            }
        ),
    }
"""


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy):
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return resp["Role"]["Arn"]


def _cleanup_log_group(ctx, log_group_name, timeout_s=60.0, interval_s=2.0):
    """A Lambda's log group is created asynchronously by its first invocation and can still be
    materializing when teardown runs; delete_function never removes it. Retry the delete through
    a bounded window, tolerating a not-yet-created group."""
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


def _create_lambda(ctx, handler_code, env=None, timeout=15):
    """Create a Lambda whose role is scoped to logs, retrying through the IAM role-propagation
    window, then wait for Active. Registers teardown for the role, the function and the
    auto-created /aws/lambda/<name> log group."""
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
    ctx.on_cleanup(lambda: _cleanup_log_group(ctx, f"/aws/lambda/{name}"))
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


def _invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.api_url(api_id, stage or '$default')}/{p}"


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _poll_http(url, *, accept, headers=None, timeout_s=150.0, interval_s=3.0, description="invoke URL"):
    """Poll an invoke URL until accept(status); return (status, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while True:
        try:
            last = _http("GET", url, headers=headers)
        except OSError as exc:
            last = (None, f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[1][:300]!r}"
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A payload-format-2.0 REQUEST authorizer with no simple response still accepts an IAM
    policy keyed on the 2.0 event's own routeArn, plus a context map alongside it: Allow reaches
    the backend with the context in requestContext.authorizer.lambda, Deny gives 403 Forbidden.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    """
    marker = ctx.unique_name("sim2real-behav-authz20iam-")
    authz_fn = _create_lambda(ctx, _IAM_POLICY_AUTHORIZER_CODE)
    backend_fn = _create_lambda(ctx, _ECHO_BACKEND_CODE, env={"MARKER": marker})

    v2 = ctx.client("apigatewayv2")
    api_id = v2.create_api(
        Name=_name(ctx, "httpapi-authz20iam"), ProtocolType="HTTP", Tags=_resource_tags()
    )["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    integ_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=backend_fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{authz_fn['arn']}/invocations"
    )
    authorizer_id = v2.create_authorizer(
        ApiId=api_id,
        Name=_name(ctx, "authz-2-0-iampolicy"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        AuthorizerResultTtlInSeconds=0,
    )["AuthorizerId"]
    got_authorizer = v2.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    assert got_authorizer.get("AuthorizerPayloadFormatVersion") == "2.0", (
        f"expected AuthorizerPayloadFormatVersion '2.0', got "
        f"{got_authorizer.get('AuthorizerPayloadFormatVersion')!r}"
    )

    v2.create_route(
        ApiId=api_id,
        RouteKey="GET /secure",
        Target=f"integrations/{integ_id}",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )
    v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx,
        backend_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
        statement_id="apigw-invoke-backend",
    )
    _allow_apigw_invoke(
        ctx,
        authz_fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/authorizers/{authorizer_id}",
        statement_id="apigw-invoke-authorizer",
    )

    url = _invoke_url(ctx, api_id, "$default", "/secure")

    _, allow_body = _poll_http(
        url, accept=lambda s: s == 200, headers={"Authorization": _VALID_TOKEN},
        description="GET /secure with a valid token",
    )
    data = json.loads(allow_body)
    assert data.get("marker") == marker, (
        f"expected this check's marker {marker!r}, got {data.get('marker')!r} -- the response "
        f"did not come from this check's backend Lambda"
    )
    authorizer_ctx = (data.get("authorizer") or {}).get("lambda") or {}
    assert authorizer_ctx.get("tenant") == "sim2real-acme", (
        f"expected requestContext.authorizer.lambda.tenant 'sim2real-acme', got "
        f"{authorizer_ctx.get('tenant')!r}"
    )
    assert authorizer_ctx.get("decision") == "Allow", (
        f"expected requestContext.authorizer.lambda.decision 'Allow', got "
        f"{authorizer_ctx.get('decision')!r}"
    )

    deny_status, deny_body = _http("GET", url, headers={"Authorization": _DENY_TOKEN})
    assert deny_status == 403, (
        f"expected 403 Forbidden for a Deny-effect 2.0-format IAM policy, got {deny_status}: "
        f"{deny_body[:300]!r}"
    )
    deny_payload = json.loads(deny_body)
    assert deny_payload == {"message": "Forbidden"}, (
        f"expected the exact default-gateway-response body {{'message': 'Forbidden'}} for a "
        f"policy Deny, got {deny_payload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
