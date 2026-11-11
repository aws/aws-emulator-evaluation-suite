"""apigw-wrong-lambda-arn-integration-negative."""

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

CHECK = "apigw-wrong-lambda-arn-integration-negative"

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
    # call is AccessDenied and the whole proxy wiring fails — so every positive
    # APIGW proxy check errored at setup. Grant the resource-policy mutation verbs.
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
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """API Gateway pointing to non-existent Lambda ARN must return 500/502/403, not 200 -- while an
    adjacent integration on the same API pointed at a real Lambda still succeeds (positive control)."""
    region = ctx.region
    fake_arn = f"arn:aws:lambda:{region}:111122223333:function:does-not-exist"

    real_fn = _create_lambda(
        ctx,
        handler_code="""
import json
def lambda_handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"real": True})}
""",
        permissions=[],
    )
    real_fn_arn = real_fn["arn"]
    real_fn_name = real_fn["name"]

    # Create the API Gateway REST API via a setup Lambda
    setup_code = f"""
import json, boto3, os
def lambda_handler(event, context):
    region = os.environ["AWS_REGION"]
    apigw = boto3.client("apigateway", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    api_name = event["api_name"]
    api = apigw.create_rest_api(name=api_name)
    api_id = api["id"]
    resources = apigw.get_resources(restApiId=api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")
    account_id = context.invoked_function_arn.split(":")[4]

    real_res = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="real")
    real_resource_id = real_res["id"]
    apigw.put_method(restApiId=api_id, resourceId=real_resource_id, httpMethod="GET",
                     authorizationType="NONE")
    real_uri = (f"arn:aws:apigateway:{{region}}:lambda:path/2015-03-31/functions/"
                f"{real_fn_arn}/invocations")
    apigw.put_integration(restApiId=api_id, resourceId=real_resource_id, httpMethod="GET",
                          type="AWS_PROXY", integrationHttpMethod="POST", uri=real_uri)
    source_arn = f"arn:aws:execute-api:{{region}}:{{account_id}}:{{api_id}}/*/GET/real"
    lam.add_permission(
        FunctionName="{real_fn_name}",
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    ghost_res = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="ghost")
    ghost_resource_id = ghost_res["id"]
    apigw.put_method(restApiId=api_id, resourceId=ghost_resource_id, httpMethod="GET",
                     authorizationType="NONE")
    fake_arn = "{fake_arn}"
    ghost_uri = (f"arn:aws:apigateway:{{region}}:lambda:path/2015-03-31/functions/"
                 f"{{fake_arn}}/invocations")
    apigw.put_integration(restApiId=api_id, resourceId=ghost_resource_id, httpMethod="GET",
                          type="AWS_PROXY", integrationHttpMethod="POST", uri=ghost_uri)

    apigw.create_deployment(restApiId=api_id, stageName="test")
    return {{"statusCode": 200, "body": json.dumps({{"api_id": api_id}})}}
"""
    setup_fn = _create_lambda(
        ctx, handler_code=setup_code, permissions=BOOTSTRAP_DDB_PERMISSIONS
    )
    api_name = ctx.unique_name("api")
    result = _invoke_lambda(ctx, setup_fn["name"], {"api_name": api_name})
    payload = (
        result["payload"]
        if isinstance(result["payload"], dict)
        else json.loads(result["payload"])
    )
    if result.get("error"):
        raise RuntimeError(f"Ghost API setup failed: {result}")
    api_id = json.loads(payload.get("body", "{}"))["api_id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    real_url = _apigw_url(ctx, api_id, "test", "/real")
    real_status, _, real_body = _http("GET", real_url)
    assert real_status == 200, (
        f"Positive control failed: expected 200 from the adjacent real Lambda "
        f"integration, got {real_status}: {real_body}"
    )
    assert json.loads(real_body) == {"real": True}, (
        f"Positive control returned an unexpected payload: {real_body}"
    )

    ghost_url = _apigw_url(ctx, api_id, "test", "/ghost")
    ghost_status, ghost_headers, ghost_body = _http("GET", ghost_url)
    error_type = {k.lower(): v for k, v in ghost_headers.items()}.get("x-amzn-errortype")
    assert (ghost_status, error_type) == (500, "InternalServerErrorException"), (
        f"Expected 500 InternalServerErrorException for a non-existent Lambda ARN, got "
        f"{ghost_status} {error_type!r}: {ghost_body}"
    )
    assert json.loads(ghost_body) == {"message": "Internal server error"}, (
        f"Expected API Gateway's integration failure body for a non-existent Lambda, got "
        f"{ghost_body!r}"
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
