"""apigw-lambda-ddb-pipeline-positive."""

from __future__ import annotations

import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-ddb-pipeline-positive"

GROUP = "event-propagation"

SERVICES = ["apigateway", "dynamodb", "lambda"]

def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(
    method: str, url: str, body: bytes | None = None, headers: dict | None = None, *, verify=True
):
    """Make an HTTP request (TLS per ``ctx.http_verify``) and return (status_code, headers, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context(verify)))
    try:
        with opener.open(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _apigw_url(ctx, api_id: str, stage: str, path: str) -> str:
    """Invoke URL for the deployed API: the real-AWS execute-api host, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _deploy_lambda_api(
    ctx,
    handler_code: str,
    http_method: str,
    resource_path: str,
    stage: str,
    permissions: list,
    env: dict,
    add_invoke_permission: bool = True,
) -> tuple:
    """Create the handler Lambda and a REST API proxying ``http_method /resource_path`` to it.

    Returns (fn_info, api_id). Every API Gateway and Lambda permission call is made by the runner.
    """
    fn = _create_lambda(
        ctx, handler_code=handler_code, permissions=permissions, env=env or {}
    )
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=_xname(ctx, "api"), tags=_xsvc_resource_tags())["id"]
    ctx.on_cleanup(_tolerant(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=resource_path)["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE"
    )
    uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=uri,
    )
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    if add_invoke_permission:
        ctx.client("lambda").add_permission(
            FunctionName=fn["name"],
            StatementId="apigw-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/{http_method}/{resource_path}",
        )
    return fn, api_id


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """HTTP POST -> API Gateway -> Lambda -> DynamoDB PutItem: the item persists and the function's
    log group carries its STORED line and a REPORT line; then every resource, the log group
    included, is deleted and proven gone."""
    ddb = ctx.client("dynamodb")
    table_name = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=table_name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table = {"name": table_name, "arn": ddb.describe_table(TableName=table_name)["Table"]["TableArn"]}

    item_id = ctx.unique_name("item-")
    handler_code = f"""
import json, boto3, os
def lambda_handler(event, context):
    ddb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
    body = json.loads(event.get("body") or "{{}}")
    ddb.put_item(TableName="{table["name"]}", Item={{"pk": {{"S": body["id"]}}, "data": {{"S": body["data"]}}}})
    print("SIM2REAL-STORED " + body["id"])
    return {{"statusCode": 200, "body": json.dumps({{"stored": True}})}}
"""
    fn, api_id = _deploy_lambda_api(
        ctx,
        handler_code=handler_code,
        http_method="POST",
        resource_path="items",
        stage="prod",
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
        env={},
        add_invoke_permission=True,
    )

    url = _apigw_url(ctx, api_id, "prod", "/items")
    try:
        status, _, resp_body = _http(
            "POST",
            url,
            body=json.dumps({"id": item_id, "data": "pipeline-value"}).encode(),
            headers={"Content-Type": "application/json"},
            verify=ctx.http_verify,
        )
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the deployed stage's execute-api URL {url} could not be "
            f"reached, so the POST never entered the pipeline: {type(exc).__name__}: {exc}"
        ) from exc
    assert status == 200, f"Expected 200, got {status}: {resp_body}"

    # Independent read at the consumer: the runner's own strongly consistent GetItem.
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": item_id}}, ConsistentRead=True).get("Item")
    assert item, f"item {item_id} not found in DynamoDB after the API call"
    assert item.get("data", {}).get("S") == "pipeline-value", f"data.S wrong: {item}"

    # The invocation's own log lines reach /aws/lambda/<fn> (bounded poll).
    log_group = f"/aws/lambda/{fn['name']}"
    stored_line = f"SIM2REAL-STORED {item_id}"
    messages = _poll_until(
        lambda: _log_messages(ctx, log_group),
        lambda ms: any(stored_line in m for m in ms) and any(m.startswith("REPORT ") for m in ms),
        timeout_s=_LOG_WAIT_S,
        interval_s=3.0,
        description=f"{log_group} holding {stored_line!r} and a REPORT line",
    )
    assert messages, f"{log_group} holds no events"

    # Tear down in reverse dependency order and prove each resource gone.
    apigw = ctx.client("apigateway")
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    _gone_rest_api(ctx, api_id, root_id)
    _gone_lambda(ctx, fn["name"])
    _gone_log_group(ctx, log_group)
    _gone_role(ctx, fn["role"], path="/sim2real/")
    _gone_table(ctx, table_name, {"pk": {"S": "gone"}})


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
    # IAM role trust/permission propagation is bounded downstream instead of slept
    # here: _create_function_with_retry retries CreateFunction against exactly this
    # delay (catching "cannot be assumed" / "InvalidParameterValue") for up to 30s.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion; only NoSuchEntity
    (the body already proved the role gone) is tolerated."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc)[0] != "NoSuchEntity":
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
            ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too; a group that was never created (or is already proven gone) is not a failure.
            ctx.on_cleanup(
                _tolerant(
                    lambda: ctx.client("logs").delete_log_group(
                        logGroupName=f"/aws/lambda/{name}"
                    ),
                    "ResourceNotFoundException",
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
    Returns {name,arn,role}."""
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
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    fn["role"] = role["name"]
    return fn


# ===== teardown proofs (GONE: three beats per family) =====
#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, a non-empty message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while on AWS, so it converges like GetFunction.
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}")
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}")


#: Bounded wait for an invocation's log lines to be readable.
_LOG_WAIT_S = 120.0


def _log_messages(ctx, group: str) -> list[str]:
    """Every event message in ``group``; a group the function has not created yet reads empty."""
    logs = ctx.client("logs")
    out: list[str] = []
    kw: dict[str, Any] = {"logGroupName": group}
    try:
        while True:
            page = logs.filter_log_events(**kw)
            out.extend((e.get("message") or "").strip() for e in page.get("events", []))
            token = page.get("nextToken")
            if not token or token == kw.get("nextToken"):
                return out
            kw["nextToken"] = token
    except ClientError as exc:
        if _err(exc)[0] != "ResourceNotFoundException":
            raise
        return out


def _gone_log_group(ctx, group: str) -> None:
    logs = ctx.client("logs")
    logs.delete_log_group(logGroupName=group)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: logs.filter_log_events(logGroupName=group), nf, 400, f"FilterLogEvents {group}")
    listed = {g["logGroupName"] for g in _paged(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=group)}
    assert group not in listed, f"DescribeLogGroups still lists deleted log group {group}"


def _gone_rest_api(ctx, api_id: str, root_id: str) -> None:
    apigw = ctx.client("apigateway")
    apigw.delete_rest_api(restApiId=api_id)
    nf = ("NotFoundException",)
    _poll_refused(lambda: apigw.get_rest_api(restApiId=api_id), nf, 404, f"GetRestApi {api_id}")
    listed = {a["id"] for a in _paged(apigw, "get_rest_apis", "items")}
    assert api_id not in listed, f"GetRestApis still lists deleted API {api_id}"
    _refused(lambda: apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="gone"), nf, 404, f"CreateResource {api_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
