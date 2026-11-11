"""lambda-sdk-cfn-list-stack-resources-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-cfn-list-stack-resources-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    cfn = boto3.client("cloudformation")
    try:
        resp = cfn.list_stack_resources(StackName=event["stack_name"])
    except ClientError as exc:
        return {"error": exc.response["Error"]["Code"], "message": exc.response["Error"]["Message"]}
    resources = [r["LogicalResourceId"] for r in resp["StackResourceSummaries"]]
    return {"resources": resources}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without cloudformation:ListStackResources is refused with AccessDenied and returns no
    resource data; with the grant restored on the same role the identical call lists the stack's resources."""
    grant = [{"Effect": "Allow", "Action": "cloudformation:ListStackResources", "Resource": "*"}]
    stack_name, stack_id, logical_id = _create_minimal_stack(ctx)

    role_with, _ = _create_lambda_role(ctx, grant)
    fn_with = _create_function(ctx, role_with, _HANDLER_CODE)

    role_without, role_without_name = _create_lambda_role(ctx, [])
    fn_without = _create_function(ctx, role_without, _HANDLER_CODE)

    control = _invoke(ctx, fn_with, {"stack_name": stack_name})
    assert "error" not in control, f"positive control unexpectedly failed: {control}"
    assert logical_id in control["resources"], (
        f"expected {logical_id!r} in positive-control resources, got {control['resources']}"
    )

    denied = _invoke(ctx, fn_without, {"stack_name": stack_name})
    assert denied.get("error") == "AccessDenied", f"unexpected result: {denied}"
    want_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_without_name}/{fn_without} "
        f"is not authorized to perform: cloudformation:ListStackResources on resource: {stack_id} "
        "because no identity-based policy allows the cloudformation:ListStackResources action"
    )
    assert denied.get("message") == want_message, (
        f"expected message {want_message!r}, got {denied.get('message')!r}"
    )
    assert "resources" not in denied, f"denied call still returned stack data: {denied}"

    _grant_role_policy(ctx, role_without_name, grant)
    restored = _poll_invoke_until_no_error(ctx, fn_without, {"stack_name": stack_name})
    assert logical_id in restored["resources"], (
        f"expected {logical_id!r} in restored-call resources, got {restored['resources']}"
    )


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> tuple[str, str]:
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    if statements:
        _grant_role_policy(ctx, role_name, statements)
    return role_arn, role_name


def _grant_role_policy(ctx, role_name: str, statements: list[dict[str, Any]]) -> None:
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-cfa-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


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
                Tags={"sim2real:managed": "true"},
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


def _poll_invoke_until_no_error(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """IAM policy grants are eventually consistent, so the restored call is a bounded
    retry, not a single shot; it still raises if the grant never takes effect."""
    deadline = time.monotonic() + 90
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _invoke(ctx, function_name, payload)
        if "error" not in last:
            return last
        time.sleep(3)
    raise AssertionError(
        f"restored role never regained cloudformation:ListStackResources within 90s: {last!r}"
    )


def _create_minimal_stack(ctx) -> tuple[str, str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfa-stack-")
    logical_id = "TestTopic"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})
    return stack_name, stack_id, logical_id


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
