"""apigw-authorizer-lambda-checks-cfn-stack-tag-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-authorizer-lambda-checks-cfn-stack-tag-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_AUTHORIZER_CODE = '''
import boto3

def handler(event, context):
    stack_name = event.get("authorizationToken", "")
    cfn = boto3.client("cloudformation")
    effect = "Deny"
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        tags = {t["Key"]: t["Value"] for t in resp["Stacks"][0].get("Tags", [])}
        if tags.get("sim2real-access") == "granted":
            effect = "Allow"
    except Exception:
        effect = "Deny"
    return {
        "principalId": "sim2real-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": event["methodArn"],
            }],
        },
    }
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """API Gateway invokes a TOKEN Lambda authorizer that calls cloudformation:DescribeStacks
    to check a stack tag, and the authorizer allows the request when the required tag is
    present on the stack it looked up."""
    apigw = ctx.client("apigateway")

    stack = _create_stack(
        ctx,
        template_body=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
        }),
        tags=[{"Key": "sim2real-access", "Value": "granted"}],
    )
    _wait_stack_status(ctx, stack["name"], "CREATE_COMPLETE")

    role_arn = _create_lambda_role(
        ctx,
        policy_statements=[{
            "Effect": "Allow",
            "Action": "cloudformation:DescribeStacks",
            "Resource": stack["id"],
        }],
    )
    fn = _create_function(ctx, _AUTHORIZER_CODE, role_arn)
    account_id = fn["arn"].split(":")[4]

    api_id = _create_rest_api(ctx)
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}"
    _add_invoke_permission(ctx, fn["name"], source_arn, "sim2real-apigw-invoke")

    resp = apigw.test_invoke_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        headers={"Authorization": stack["name"]},
    )
    policy = json.loads(resp["policy"])
    assert policy["Statement"][0]["Effect"] == "Allow", resp
    assert resp["principalId"] == "sim2real-user", (
        f"expected principalId 'sim2real-user', got {resp['principalId']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))

    if policy_statements:
        pol_name = ctx.unique_name("sim2real-lam-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=pol_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name))
    return role_arn


def _create_function(ctx, code: str, role_arn: str, timeout: int = 15) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)

    def _try_create():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    resp = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description=f"lambda {name} creatable (IAM role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _add_invoke_permission(ctx, function_name: str, source_arn: str, statement_id: str, qualifier: str | None = None) -> None:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = {
        "FunctionName": function_name,
        "StatementId": statement_id,
        "Action": "lambda:InvokeFunction",
        "Principal": "apigateway.amazonaws.com",
        "SourceArn": source_arn,
    }
    if qualifier:
        kwargs["Qualifier"] = qualifier
    lam.add_permission(**kwargs)

    def _cleanup():
        rem: dict[str, Any] = {"FunctionName": function_name, "StatementId": statement_id}
        if qualifier:
            rem["Qualifier"] = qualifier
        lam.remove_permission(**rem)

    ctx.on_cleanup(_cleanup)


def _create_stack(ctx, template_body: str, tags=None) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-stack-")
    kwargs: dict[str, Any] = {"StackName": name, "TemplateBody": template_body}
    if tags:
        kwargs["Tags"] = tags
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=name))
    return {"name": name, "id": stack_id}


def _wait_stack_status(ctx, stack_name: str, expected_status: str, timeout_s: float = 180.0) -> str:
    cfn = ctx.client("cloudformation")
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s == expected_status,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {stack_name} reaches {expected_status}",
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
