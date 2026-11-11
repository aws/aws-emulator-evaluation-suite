"""test-invoke-method-lambda-proxy-round-trips-headers-query-body."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-method-lambda-proxy-round-trips-headers-query-body"
GROUP = "invoke"
SERVICES = ["apigateway"]

_HANDLER = """
import json

def lambda_handler(event, context):
    headers = event.get("headers") or {}
    qs = event.get("queryStringParameters") or {}
    return {
        "statusCode": 201,
        "headers": {"X-Sim2real-Echo": headers.get("X-Sim2real-Nonce", "missing")},
        "body": json.dumps({
            "header_seen": headers.get("X-Sim2real-Nonce"),
            "query_seen": qs.get("tag"),
            "body_seen": event.get("body"),
        }),
    }
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_lambda(ctx, handler_code):
    """A Python Lambda running `handler_code`, waiting through IAM propagation to Active."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-role-proxyrt-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
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
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"), "NoSuchEntity")
    )

    fn_name = ctx.unique_name("sim2real-behav-fn-proxyrt-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}"))

    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=30,
        MemorySize=128,
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 90.0
    created = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InvalidParameterValueException",):
                last_err = exc
                time.sleep(2.0)
                continue
            raise
    if created is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"))

    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return {"name": fn_name, "arn": created["FunctionArn"]}


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0):
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod builds the Lambda proxy event from the real headers, query string and
    body, and the method response is the function's own statusCode, headers and body unchanged.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """
    ag = ctx.client("apigateway")
    fn = _create_lambda(ctx, _HANDLER)

    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-proxyrt-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))

    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="echo"
    )["id"]
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )

    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )

    header_nonce = ctx.unique_name("sim2real-nonce-")
    query_tag = ctx.unique_name("sim2real-tag-")
    body_payload = json.dumps({"ping": ctx.unique_name("sim2real-ping-")})

    deadline = time.monotonic() + 90.0
    resp = None
    while time.monotonic() < deadline:
        resp = ag.test_invoke_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            pathWithQueryString=f"/echo?tag={query_tag}",
            headers={"X-Sim2real-Nonce": header_nonce},
            body=body_payload,
        )
        if resp.get("status") == 201:
            break
        time.sleep(2.0)

    assert resp is not None and resp.get("status") == 201, (
        f"expected statusCode 201 from the Lambda proxy response, got {resp and resp.get('status')!r}: "
        f"{resp and resp.get('body')!r}\nAPIGW LOG:\n{resp and resp.get('log')}"
    )
    assert resp["headers"].get("X-Sim2real-Echo") == header_nonce, (
        f"expected the method response header X-Sim2real-Echo to carry the function's own header "
        f"{header_nonce!r} unchanged, got {resp['headers']!r}"
    )
    data = json.loads(resp["body"])
    assert data == {"header_seen": header_nonce, "query_seen": query_tag, "body_seen": body_payload}, (
        f"expected the proxy event to have carried the real header, query string and body "
        f"through to the function unchanged, got {data!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
