"""apigw-authorizer-deny-integration-not-invoked."""

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

CHECK = "apigw-authorizer-deny-integration-not-invoked"

GROUP = "overly-permissive"

SERVICES = ["apigateway", "dynamodb", "lambda"]


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A TOKEN authorizer returning Deny answers 403 and the backend never runs (no DynamoDB item),
    while the allowed token returns 200 and the item appears."""
    backend_code = """
import json, os, boto3
def lambda_handler(event, context):
    ddb = boto3.client('dynamodb')
    ddb.put_item(TableName=os.environ['TABLE'], Item={
        'pk': {'S': 'invoked'},
        'path': {'S': str(event.get('path') or event.get('rawPath') or '/')},
    })
    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
"""
    authorizer_code = """
import json
def lambda_handler(event, context):
    token = event.get('authorizationToken', '')
    effect = 'Allow' if token == 'let-me-in' else 'Deny'
    return {
        'principalId': 'probe-user',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': event.get('methodArn', '*'),
            }],
        },
    }
"""

    ddb = ctx.client("dynamodb")
    table = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=table))
    _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"table {table} ACTIVE",
    )

    backend = _create_lambda(
        ctx,
        handler_code=backend_code,
        permissions=[
            {
                "Action": ["dynamodb:PutItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table}",
            }
        ],
        env={"TABLE": table},
    )
    authorizer = _create_lambda(ctx, handler_code=authorizer_code)

    # Every ARN/name the bootstrap needs arrives in the invocation payload, so no check-side value
    # is ever interpolated into this handler's source.
    setup_code = """
import json, os, boto3
def lambda_handler(event, context):
    region = os.environ["AWS_REGION"]
    apigw = boto3.client("apigateway", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    account_id = context.invoked_function_arn.split(":")[4]
    prefix = "arn:aws:apigateway:" + region + ":lambda:path/2015-03-31/functions/"
    api_id = apigw.create_rest_api(name=event["api_name"])["id"]
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    res_id = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="guarded"
    )["id"]
    authz = apigw.create_authorizer(
        restApiId=api_id, name="tokenauth", type="TOKEN",
        authorizerUri=prefix + event["authorizer_arn"] + "/invocations",
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    apigw.put_method(
        restApiId=api_id, resourceId=res_id, httpMethod="GET",
        authorizationType="CUSTOM", authorizerId=authz["id"],
    )
    apigw.put_integration(
        restApiId=api_id, resourceId=res_id, httpMethod="GET",
        type="AWS_PROXY", integrationHttpMethod="POST",
        uri=prefix + event["backend_arn"] + "/invocations",
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")
    # Both the authorizer AND the backend are made invocable, so a missing lambda:InvokeFunction
    # grant can never be the reason the backend does not run.
    api_prefix = "arn:aws:execute-api:" + region + ":" + account_id + ":" + api_id
    grants = [
        (event["authorizer_name"], "authz-invoke",
         api_prefix + "/authorizers/" + authz["id"]),
        (event["backend_name"], "backend-invoke", api_prefix + "/*/GET/guarded"),
    ]
    for fname, sid, source_arn in grants:
        try:
            lam.add_permission(
                FunctionName=fname, StatementId=sid, Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com", SourceArn=source_arn,
            )
        except lam.exceptions.ResourceConflictException:
            pass
    return {"statusCode": 200, "body": json.dumps({"api_id": api_id})}
"""
    setup_fn = _create_lambda(
        ctx,
        handler_code=setup_code,
        permissions=[
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
            {
                "Action": [
                    "lambda:AddPermission",
                    "lambda:RemovePermission",
                    "lambda:GetPolicy",
                ],
                "Resource": "*",
            },
        ],
    )
    result = _invoke_lambda(
        ctx,
        setup_fn["name"],
        {
            "api_name": _xname(ctx, "api"),
            "authorizer_arn": authorizer["arn"],
            "authorizer_name": authorizer["name"],
            "backend_arn": backend["arn"],
            "backend_name": backend["name"],
        },
    )
    assert not result.get("error"), f"API Gateway bootstrap failed: {result}"
    payload = result["payload"]
    api_id = json.loads(payload["body"])["api_id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    url = _apigw_url(ctx, api_id, "test", "/guarded")

    def _marker_item():
        return ddb.get_item(
            TableName=table, Key={"pk": {"S": "invoked"}}, ConsistentRead=True
        ).get("Item")

    # Control: the allowed token must reach the integration AND leave the side effect behind.
    status, _, body = _http("GET", url, headers={"Authorization": "let-me-in"})
    assert status == 200, (
        f"control: an Allow policy from the authorizer must let the request through, got "
        f"{status}: {body}"
    )
    item = _poll_until(
        _marker_item,
        lambda i: i is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="backend wrote its invocation marker",
    )
    assert item["pk"]["S"] == "invoked", f"unexpected marker item: {item}"

    # Remove the side effect so its reappearance can only come from a new invocation.
    ddb.delete_item(TableName=table, Key={"pk": {"S": "invoked"}})
    assert _marker_item() is None, (
        "failed to clear the invocation marker before the negative leg"
    )

    # Negative: a Deny must produce 403 AND no invocation.
    status, _, body = _http("GET", url, headers={"Authorization": "keep-me-out"})
    assert status == 403, (
        f"a Deny policy from the authorizer must produce 403, got {status}: {body}"
    )
    leaked = _collect_marker(ctx, _marker_item, window_s=45.0)
    assert leaked is None, (
        "the backend integration ran even though the authorizer returned Deny -- it wrote "
        f"{leaked!r}; API Gateway must not invoke the integration for a denied request"
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
    # IAM role trust/permission propagation before a service assumes it is waited out as
    # a bounded retry in _create_function_with_retry (the only consumer of this role's
    # arn), not with a sleep here.
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
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


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
    return f"{ctx.rest_api_url(api_id, stage)}{path}"


def _invoke_lambda(ctx, name: str, payload: dict) -> dict:
    """Invoke a Lambda synchronously; return {payload, error}."""
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, InvocationType="RequestResponse", Payload=json.dumps(payload)
    )
    raw = resp["Payload"].read().decode()
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        parsed = raw
    return {"payload": parsed, "error": resp.get("FunctionError")}


def _collect_marker(ctx, probe, *, window_s=45.0):
    """Watch a side-effect probe over a bounded window and return the first non-None result.
    The NEGATIVE observable: None means the effect never happened. Only meaningful because the
    control leg above already proved the same probe does return an item when the path runs."""
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        got = probe()
        if got is not None:
            return got
        time.sleep(3.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
