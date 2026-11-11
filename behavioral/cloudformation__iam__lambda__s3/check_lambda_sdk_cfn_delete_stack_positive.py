"""lambda-sdk-cfn-delete-stack-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-cfn-delete-stack-positive"
GROUP = "sdk-call"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role permitted cloudformation:DeleteStack deletes a live stack with boto3 from inside
    the handler, and DescribeStacks then reports the stack DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")

    lambda_statements = [
        {
            "Effect": "Allow",
            "Action": ["cloudformation:DeleteStack", "cloudformation:DescribeStacks"],
            "Resource": "*",
        },
    ]
    _, lambda_role_arn = _create_lambda_role(ctx, "delete-pos", lambda_statements)
    fn_name = _create_function_with_retry(ctx, lambda_role_arn, "delete-pos")

    stack_name = ctx.unique_name("sim2real-delstack-pos-")
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps({"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    status = _wait_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status}"

    result = _invoke(ctx, fn_name, {"action": "delete_stack", "stack_name": stack_name})
    assert result.get("ok") is True, f"delete_stack via Lambda failed: {result}"

    final_status = _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"})
    assert final_status == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {final_status}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NoSuchEntity", "ResourceNotFoundException")
            or (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


_HANDLER_CODE = """
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    cfn = boto3.client("cloudformation")
    action = event["action"]
    kwargs = {"StackName": event["stack_name"]}
    if "template_body" in event:
        kwargs["TemplateBody"] = event["template_body"]
    if "role_arn" in event:
        kwargs["RoleARN"] = event["role_arn"]
    if "capabilities" in event:
        kwargs["Capabilities"] = event["capabilities"]
    try:
        if action == "create_stack":
            cfn.create_stack(**kwargs)
        elif action == "update_stack":
            cfn.update_stack(**kwargs)
        elif action == "delete_stack":
            cfn.delete_stack(StackName=event["stack_name"])
        else:
            return {"ok": False, "error_code": "BadAction", "error_message": "unknown action"}
        return {"ok": True}
    except ClientError as e:
        return {
            "ok": False,
            "error_code": e.response["Error"]["Code"],
            "error_message": e.response["Error"].get("Message", ""),
        }
"""


def _create_lambda_role(ctx, name_suffix: str, extra_statements: list[dict[str, Any]]):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-lam-{name_suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        )
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline")))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if extra_statements:
        policy_doc = {"Version": "2012-10-17", "Statement": extra_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    return role_name, role_arn


def _create_function_with_retry(ctx, role_arn: str, name_suffix: str, timeout_s: float = 90):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-cfnlam-{name_suffix}-")
    zip_bytes = _zip_code(_HANDLER_CODE)
    deadline = time.monotonic() + timeout_s
    last_err = None
    created = False
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    if not created:
        raise AssertionError(f"lambda function never became creatable: {last_err}")
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function(FunctionName=fn_name)))
    _wait_function_active(ctx, fn_name)
    return fn_name


def _wait_function_active(ctx, fn_name: str, timeout_s: float = 60, interval_s: float = 3):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        state = cfg.get("State")
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function never became Active, last state={state}")


def _invoke(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode())
    assert "FunctionError" not in resp, f"lambda invocation errored: {resp.get('FunctionError')}"
    return json.loads(resp["Payload"].read())


def _wait_stack_status(ctx, stack_name: str, terminal_statuses: set[str], timeout_s: float = 180, interval_s: float = 5):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
            status = desc["StackStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError":
                return "DELETE_COMPLETE"
            raise
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached terminal status, last={status}")


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
