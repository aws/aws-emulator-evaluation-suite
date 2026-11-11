"""apigw-lambda-event-invocation-returns-200-empty-and-runs-async."""
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

CHECK = "apigw-lambda-event-invocation-returns-200-empty-and-runs-async"
GROUP = "integration-invocation"
SERVICES = ["apigateway", "dynamodb", "lambda"]

#: A non-proxy backend: it receives the passed-through request body as its event and writes
#: a DynamoDB item keyed by the marker it was given, proving it actually ran.
_HANDLER = """
import boto3
import os


def lambda_handler(event, context):
    ddb = boto3.client("dynamodb", region_name=os.environ["AWS_REGION"])
    ddb.put_item(
        TableName=os.environ["TABLE_NAME"],
        Item={"pk": {"S": event["marker"]}, "ran": {"S": "true"}},
    )
    return {"stored": True}
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
    """A non-proxy Lambda integration whose requestParameters set the invocation-type header to
    'Event' returns 200 with an empty body immediately, and the function still runs and writes
    its side effect.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-integrations.html
    """
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
    ddb.get_waiter("table_exists").wait(
        TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300) // 2))}
    )
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table_arn}],
        env={"TABLE_NAME": table_name},
    )

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, "event-invoke")
    resource_id = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="notify")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE")
    _c(
        ag.put_integration,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"),
        requestParameters={"integration.request.header.X-Amz-Invocation-Type": "'Event'"},
        passthroughBehavior="WHEN_NO_TEMPLATES",
    )
    _c(ag.put_method_response, restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200")
    _c(
        ag.put_integration_response,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )
    account = _account_id(ctx)
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*")
    _deploy_stage(ctx, api_id, "prod")

    marker = ctx.unique_name("sim2real-behav-evt-")
    url = _rest_invoke_url(ctx, api_id, "prod", "/notify")
    body = json.dumps({"marker": marker}).encode()
    status, _h, text = _poll(
        ctx,
        lambda: _raw_request("POST", url, body=body, verify=ctx.http_verify),
        lambda r: r[0] == 200,
        "POST /notify through the Event-invocation-type integration returning 200",
    )
    assert text == "", f"an Event-invocation integration's method response must be empty, got {text[:300]!r}"

    item = _poll(
        ctx,
        lambda: ddb.get_item(TableName=table_name, Key={"pk": {"S": marker}}, ConsistentRead=True).get("Item"),
        lambda i: i is not None,
        f"DynamoDB item {marker!r} written by the asynchronously invoked function",
    )
    assert item.get("ran", {}).get("S") == "true", (
        f"the function must have actually run and written its side effect, got {item!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


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


def _c(fn, **kw):
    """Call an apigateway control-plane op, retrying only its per-account mutation throttle."""
    for attempt in range(10):
        try:
            return fn(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 9:
                raise
            time.sleep(min(4.0, 0.3 * (2**attempt)))
    raise RuntimeError("unreachable")


def _poll(ctx, probe, predicate, description, timeout_s=150.0, interval_s=3.0):
    """Poll probe() to a condition, tolerating connection errors while execute-api DNS settles."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = (None, {}, repr(exc))
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{description}: condition not met within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _raw_request(method, url, body=None, headers=None, *, verify=True):
    """(status, headers, text) over raw HTTP; a 4xx/5xx is a result, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25, context=_ssl_context(verify)) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def _rest_invoke_url(ctx, api_id, stage, path):
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _create_rest_api(ctx, kind):
    ag = ctx.client("apigateway")
    api_id = _c(
        ag.create_rest_api,
        name=_xname(ctx, kind),
        description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
    )["id"]
    ctx.on_cleanup(_tolerant(lambda: _c(ag.delete_rest_api, restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage):
    ag = ctx.client("apigateway")
    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    _c(ag.create_stage, restApiId=api_id, stageName=stage, deploymentId=dep_id, tags=_xsvc_resource_tags())
    ctx.on_cleanup(_tolerant(lambda: _c(ag.delete_stage, restApiId=api_id, stageName=stage), "NotFoundException"))


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


def _create_lambda(ctx, handler_code, permissions=None, env=None):
    """Execution role (logs + ``permissions``) + python3.12 function; waits for Active."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        statements.append({"Effect": "Allow", "Action": perm["Action"], "Resource": perm["Resource"]})
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
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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


def _allow_apigw_invoke(ctx, fn_name, source_arn):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
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
