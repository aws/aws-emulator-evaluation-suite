"""lambda-sdk-cfn-list-stack-resources-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-cfn-list-stack-resources-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_HANDLER_CODE = """
import boto3

def handler(event, context):
    cfn = boto3.client("cloudformation")
    resp = cfn.list_stack_resources(StackName=event["stack_name"])
    resources = [r["LogicalResourceId"] for r in resp["StackResourceSummaries"]]
    return {"resources": resources}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role allows cloudformation:ListStackResources lists the logical resources
    of the deployed stack with boto3."""
    stack_name, logical_id = _create_minimal_stack(ctx)
    role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": "cloudformation:ListStackResources", "Resource": "*"}],
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE)

    result = _invoke(ctx, fn_name, {"stack_name": stack_name})
    assert "resources" in result, f"unexpected lambda result: {result}"
    assert logical_id in result["resources"], (
        f"expected {logical_id!r} in stack resources, got {result['resources']}"
    )


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


_TAG_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_TAG_MAP = {"sim2real:managed": "true"}


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfa-role-")
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG_KV
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    if statements:
        policy_name = ctx.unique_name("sim2real-cfa-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn: str, handler_code: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfa-fn-")
    code = _zip_code(handler_code)
    deadline = time.monotonic() + 60
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                Tags=_TAG_MAP,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"role never became assumable by lambda: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {body}")
    return body


def _create_minimal_stack(ctx) -> tuple[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfa-stack-")
    # A fixed logical id would let a target that ignores the template and returns a canned
    # "TestTopic" answer pass every run; derive it per-run so the assertion actually exercises
    # the deployed template's real content.
    logical_id = ctx.unique_name("TestTopic")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template), Tags=_TAG_KV)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})
    return stack_name, logical_id


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
