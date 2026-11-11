"""apigw-lambda-authorizer-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-authorizer-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["apigateway", "dynamodb", "lambda"]

BOOTSTRAP_DDB_PERMISSIONS = [
    {
        "Action": [
            "dynamodb:CreateTable",
            "dynamodb:DescribeTable",
            "dynamodb:PutItem",
            "dynamodb:GetItem",
            "dynamodb:DeleteItem",
            "dynamodb:UpdateTable",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:GetRecords",
            "dynamodb:GetShardIterator",
            "dynamodb:DescribeStream",
            "dynamodb:ListStreams",
            "dynamodb:TransactWriteItems",
        ],
        "Resource": "*",
    },
    {
        "Action": [
            "apigateway:GET",
            "apigateway:POST",
            "apigateway:PUT",
            "apigateway:DELETE",
            "apigateway:PATCH",
        ],
        "Resource": "*",
    },
    # The setup Lambda grants API Gateway the right to invoke the handler Lambda
    # (lambda.add_permission). Without lambda:AddPermission on the setup role that
    # call is AccessDenied and the whole proxy wiring fails.
    # Grant the resource-policy mutation verbs.
    {
        "Action": [
            "lambda:AddPermission",
            "lambda:RemovePermission",
            "lambda:GetPolicy",
        ],
        "Resource": "*",
    },
]


def _http(
    method: str, url: str, body: bytes | None = None, headers: dict | None = None
):
    """Make an HTTP request and return (status_code, headers, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _apigw_url(ctx, api_id: str, stage: str, path: str) -> str:
    """Invoke URL for the deployed API: the real-AWS execute-api host, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """API Gateway cannot invoke authorizer Lambda without permission; must return 500/403,
    and granting the missing permission afterward must make the identical call succeed."""
    auth_fn = _create_lambda(
        ctx,
        handler_code="""
import json
def lambda_handler(event, context):
    return {"principalId": "user", "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [{"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "*"}]}}
""",
        permissions=[],
    )
    backend_fn = _create_lambda(
        ctx,
        handler_code='import json\ndef lambda_handler(e, c): return {"statusCode": 200, "body": json.dumps({"ok": True})}',
        permissions=[],
    )

    auth_arn = auth_fn["arn"]
    backend_arn = backend_fn["arn"]
    backend_name = backend_fn["name"]

    # Create the API Gateway REST API via a setup Lambda
    apigw_setup_code = f"""
import json, boto3, os
def lambda_handler(event, context):
    region = os.environ["AWS_REGION"]
    apigw = boto3.client("apigateway", region_name=region)
    api_name = event["api_name"]
    api = apigw.create_rest_api(name=api_name)
    api_id = api["id"]
    resources = apigw.get_resources(restApiId=api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")
    res = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")
    resource_id = res["id"]
    auth_uri = (f"arn:aws:apigateway:{{region}}:lambda:path/2015-03-31/functions/"
                f"{auth_arn}/invocations")
    authorizer = apigw.create_authorizer(
        restApiId=api_id, name="auth", type="TOKEN",
        authorizerUri=auth_uri, identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                     authorizationType="CUSTOM", authorizerId=authorizer["id"])
    backend_uri = (f"arn:aws:apigateway:{{region}}:lambda:path/2015-03-31/functions/"
                   f"{backend_arn}/invocations")
    apigw.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                          type="AWS_PROXY", integrationHttpMethod="POST", uri=backend_uri)
    apigw.create_deployment(restApiId=api_id, stageName="test")
    # Grant invoke on backend ONLY (NOT on authorizer)
    lam = boto3.client("lambda", region_name=region)
    account_id = context.invoked_function_arn.split(":")[4]
    try:
        lam.add_permission(
            FunctionName="{backend_name}", StatementId="backend-invoke",
            Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
            SourceArn=f"arn:aws:execute-api:{{region}}:{{account_id}}:{{api_id}}/*/GET/secure",
        )
    except Exception as e:
        if "already exists" not in str(e).lower():
            raise
    return {{"statusCode": 200, "body": json.dumps(
        {{"api_id": api_id, "authorizer_id": authorizer["id"]}}
    )}}
"""
    setup_fn = _create_lambda(
        ctx, handler_code=apigw_setup_code, permissions=BOOTSTRAP_DDB_PERMISSIONS
    )
    api_name = ctx.unique_name("api")
    result = _invoke_lambda(ctx, setup_fn["name"], {"api_name": api_name})
    payload = (
        result["payload"]
        if isinstance(result["payload"], dict)
        else json.loads(result["payload"])
    )
    if result.get("error"):
        raise RuntimeError(f"Authorizer API setup failed: {result}")
    setup_body = json.loads(payload.get("body", "{}"))
    api_id = setup_body["api_id"]
    authorizer_id = setup_body["authorizer_id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    url = _apigw_url(ctx, api_id, "test", "/secure")
    status, headers, body = _http("GET", url, headers={"Authorization": "Bearer token123"})

    # API Gateway cannot invoke the authorizer, so it answers its documented authorizer
    # configuration error rather than a client-side refusal or the backend's response.
    error_type = {k.lower(): v for k, v in headers.items()}.get("x-amzn-errortype")
    assert (status, error_type) == (500, "AuthorizerConfigurationException"), (
        f"expected 500 AuthorizerConfigurationException (missing authorizer invoke permission), "
        f"got {status} {error_type!r}: {body}"
    )
    assert json.loads(body) == {"message": None}, (
        f"expected the authorizer configuration error body, got {body!r}"
    )

    # Restore: grant API Gateway permission to invoke the authorizer, and demand the
    # identical call now succeeds. Without this leg, a target whose proxy wiring is simply
    # broken (and always answers 403/500 regardless of authorizer permission) would pass
    # this check identically to one that correctly enforces the missing grant.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ctx.client("lambda").add_permission(
        FunctionName=auth_fn["name"],
        StatementId="authorizer-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=(
            f"arn:aws:execute-api:{ctx.region}:{account_id}:"
            f"{api_id}/authorizers/{authorizer_id}"
        ),
    )

    def _probe_restored():
        return _http("GET", url, headers={"Authorization": "Bearer token123"})

    restored_status, _, restored_body = _poll_until(
        _probe_restored,
        lambda r: r[0] == 200,
        timeout_s=30.0,
        interval_s=3.0,
        description="request succeeds once the authorizer invoke permission is granted",
    )
    assert restored_status == 200, (
        f"Expected 200 once the authorizer invoke permission is granted, "
        f"got {restored_status}: {restored_body}"
    )
    assert json.loads(restored_body).get("ok") is True, (
        f"Backend must be reachable once the authorizer invoke permission is granted: "
        f"{restored_body}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
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
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
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
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too; a function that never logged has no group to delete.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
