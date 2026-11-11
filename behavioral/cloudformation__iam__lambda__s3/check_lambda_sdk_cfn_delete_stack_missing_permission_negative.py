"""lambda-sdk-cfn-delete-stack-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-cfn-delete-stack-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteStack from a Lambda handler whose role lacks cloudformation:DeleteStack fails with
    AccessDenied naming that action and the stack stays CREATE_COMPLETE; granting the action on the
    same role lets the handler delete it to DELETE_COMPLETE (positive control)."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")

    # Lambda role deliberately has NO cloudformation permissions at all.
    role_name, lambda_role_arn = _create_lambda_role(ctx, "delete-neg", [])
    fn_name = _create_function_with_retry(ctx, lambda_role_arn, "delete-neg")

    stack_name = ctx.unique_name("sim2real-delstack-neg-")
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps({"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}),
        Tags=_tags_kv(),
    )
    status = _wait_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    assert status == "CREATE_COMPLETE", f"setup stack ended in {status}"

    result = _invoke(ctx, fn_name, {"action": "delete_stack", "stack_name": stack_name})
    assert result.get("ok") is False, f"delete_stack unexpectedly succeeded: {result}"
    assert result["error_code"] == "AccessDenied"
    assert "cloudformation:DeleteStack" in result["error_message"]

    # Effect absent: the stack is still there, untouched.
    still_there = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert still_there["StackStatus"] == "CREATE_COMPLETE"

    # Positive control: grant DeleteStack on the same role, then retry.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="deletestack",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["cloudformation:DeleteStack", "cloudformation:DescribeStacks"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deletestack")))

    control_result = _poll_until_ok(ctx, fn_name, {"action": "delete_stack", "stack_name": stack_name})
    assert control_result.get("ok") is True, f"positive control delete_stack never succeeded: {control_result}"
    final_status = _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"})
    assert final_status == "DELETE_COMPLETE"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NoSuchEntity", "ResourceNotFoundException")
            or (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())
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
                Tags={t["Key"]: t["Value"] for t in _tags_kv()},
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


def _poll_until_ok(ctx, fn_name: str, payload: dict[str, Any], timeout_s: float = 90, interval_s: float = 5):
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _invoke(ctx, fn_name, payload)
        if last.get("ok"):
            return last
        time.sleep(interval_s)
    return last


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
