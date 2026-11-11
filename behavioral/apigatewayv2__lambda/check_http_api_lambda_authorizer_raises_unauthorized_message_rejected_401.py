"""http-api-lambda-authorizer-raises-unauthorized-message-rejected-401."""
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

CHECK = "http-api-lambda-authorizer-raises-unauthorized-message-rejected-401"
GROUP = "authorizers"
SERVICES = ["apigatewayv2", "lambda"]

#: Raises with the exact message "Unauthorized" — the contrast raises with an unrelated message.
_UNAUTHORIZED_AUTHORIZER = """
def lambda_handler(event, context):
    raise Exception("Unauthorized")
"""

_OTHER_ERROR_AUTHORIZER = """
def lambda_handler(event, context):
    raise Exception("boom")
"""

_ALLOW_AUTHORIZER = """
def lambda_handler(event, context):
    return {"isAuthorized": True}
"""

_ECHO_BACKEND = """
import json
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"]}),
    }
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A simple-response Lambda authorizer raising exactly 'Unauthorized' gets a 401 (observed
    AWS behavior; the docs cover only response formats); raising any other message gets 500,
    and neither reaches the backend.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    """
    marker = ctx.unique_name("sim2real-behav-authraise-")
    allow_fn = _create_lambda(ctx, _ALLOW_AUTHORIZER)
    unauth_fn = _create_lambda(ctx, _UNAUTHORIZED_AUTHORIZER)
    other_fn = _create_lambda(ctx, _OTHER_ERROR_AUTHORIZER)
    backend_fn = _create_lambda(ctx, _ECHO_BACKEND, env={"MARKER": marker})

    v2 = ctx.client("apigatewayv2")
    created_api = v2.create_api(
        Name=_xname(ctx, "httpapi-authraise"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(_tolerant(lambda: v2.delete_api(ApiId=api_id), "NotFoundException"))

    integ_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=backend_fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]

    account = _account_id(ctx)
    routes = {}
    for label, authz_fn in (("allow", allow_fn), ("unauthorized", unauth_fn), ("other", other_fn)):
        authorizer_uri = (
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{authz_fn['arn']}/invocations"
        )
        authorizer_id = v2.create_authorizer(
            ApiId=api_id,
            Name=_xname(ctx, f"authz-{label}"),
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

    _allow_apigw_invoke(
        ctx, backend_fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*", statement_id="apigw-invoke-backend"
    )
    v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=_xsvc_resource_tags())
    ctx.on_cleanup(
        _tolerant(lambda: v2.delete_stage(ApiId=api_id, StageName="$default"), "NotFoundException")
    )

    # --- positive control first, polled until the stage serves it: an authorizer that allows
    # lets the request through to the backend, whose marker comes back.
    _status, _h, text = _poll_http(
        ctx,
        _invoke_url(ctx, api_endpoint, routes["allow"]),
        accept=lambda s: s == 200,
        headers={"Authorization": "whatever"},
        description="GET /allow behind the allowing authorizer returning 200",
    )
    assert json.loads(text) == {"marker": marker}, f"expected the backend's own marker, got {text[:300]!r}"

    # --- the exact message "Unauthorized" gets a 401, not the backend's response; polled to the
    # 401, since a 500 also answers while this authorizer's invoke permission propagates.
    _status, _h, text = _poll_http(
        ctx,
        _invoke_url(ctx, api_endpoint, routes["unauthorized"]),
        accept=lambda s: s == 401,
        headers={"Authorization": "whatever"},
        description="GET /unauthorized behind the authorizer raising 'Unauthorized' returning 401",
    )
    assert text == '{"message":"Unauthorized"}', (
        f'expected the exact body \'{{"message":"Unauthorized"}}\', got {text[:300]!r}'
    )

    # --- contrast: the SAME shape of failure, a different message, gets 500 instead
    status, _h, text = _poll_http(
        ctx,
        _invoke_url(ctx, api_endpoint, routes["other"]),
        accept=lambda s: s is not None and s != 404,
        headers={"Authorization": "whatever"},
        description="GET /other behind the authorizer raising 'boom'",
    )
    assert status == 500, (
        f"the same authorizer raising a message other than 'Unauthorized' must produce 500, "
        f"got {status}: {text[:300]!r}"
    )
    assert text == '{"message":"Internal Server Error"}', (
        f'expected the generic 500 body \'{{"message":"Internal Server Error"}}\', got {text[:300]!r}'
    )


_XSVC_PREFIX = "sim2real-behav-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _tolerant(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises except on its not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_http(ctx, url, *, accept, method="GET", headers=None, timeout_s=150.0, interval_s=3.0, description="invoke URL"):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, headers=headers, verify=ctx.http_verify)
        except OSError as exc:
            last = (None, {}, f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(f"{description} ({url}) never reached an accepted status within {timeout_s:.0f}s. Last: {last!r}")


def _http(method, url, headers=None, *, verify=True):
    """(status, headers, text); a 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_ssl_context(verify)) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def _invoke_url(ctx, api_endpoint, path):
    return f"{ctx.stage_url(api_endpoint, '$default')}/{path.lstrip('/')}"


def _delete_role(ctx, role_name):
    """Delete the role and its inline policies; a role already gone is the only tolerated miss."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _reap_log_group(ctx, name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete the log group until several consecutive reads find it absent."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise TimeoutError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _create_lambda(ctx, handler_code, env=None):
    """Execution role (logs only) + python3.12 function; waits for Active."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )

    name = _xname(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": 15,
        "MemorySize": 128,
        "Tags": _xsvc_resource_tags(),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300) // 2))}
    )
    return {"name": name, "arn": arn}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


def _budget_s(ctx, want):
    """``want`` seconds, capped by the time the runner has left for this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
