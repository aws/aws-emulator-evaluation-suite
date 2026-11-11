"""lambda-sdk-cfn-update-stack-missing-capability-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-cfn-update-stack-missing-capability-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_MANAGED_TAG_KEY = "sim2real:managed"
_IAM_TAGS = [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]
_LAMBDA_TAGS = {_MANAGED_TAG_KEY: "true"}
_CFN_TAGS = _IAM_TAGS


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateStack from a Lambda handler without CAPABILITY_IAM, for a template declaring an IAM role,
    fails with InsufficientCapabilitiesException, leaving the role's Description "v1" and the stack
    CREATE_COMPLETE; with the capability the same update completes and sets "v2" (positive control)."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")

    stack_exec_statements = [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:GetRole",
                "iam:UpdateRole",
                "iam:UpdateRoleDescription",
                "iam:TagRole",
                "iam:UntagRole",
            ],
            "Resource": "*",
        }
    ]
    _, exec_role_arn = _create_stack_exec_role(ctx, "update-neg", stack_exec_statements)

    lambda_statements = [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackResources",
                "cloudformation:DeleteStack",
            ],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
    ]
    _, lambda_role_arn = _create_lambda_role(ctx, "update-neg", lambda_statements)
    fn_name = _create_function_with_retry(ctx, lambda_role_arn, "update-neg")

    def _template_for(description: str) -> str:
        return json.dumps(
            {
                "Resources": {
                    "NestedRole": {
                        "Type": "AWS::IAM::Role",
                        "Properties": {
                            "AssumeRolePolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"Service": "lambda.amazonaws.com"},
                                        "Action": "sts:AssumeRole",
                                    }
                                ],
                            },
                            "Description": description,
                        },
                    }
                }
            }
        )

    stack_name = ctx.unique_name("sim2real-nested-iam-upd-")
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))

    # Bootstrap the initial stack directly (not via Lambda) so this check
    # isolates the UpdateStack capability boundary.
    _retry_role_propagation(
        lambda: cfn.create_stack(
            StackName=stack_name,
            TemplateBody=_template_for("v1"),
            RoleARN=exec_role_arn,
            Capabilities=["CAPABILITY_IAM"],
            Tags=_CFN_TAGS,
        )
    )
    status = _wait_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    assert status == "CREATE_COMPLETE", f"bootstrap stack ended in {status}"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    role_physical_id = next(
        r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "NestedRole"
    )

    # Attempt the update WITHOUT acknowledging CAPABILITY_IAM.
    result = _invoke(
        ctx,
        fn_name,
        {
            "action": "update_stack",
            "stack_name": stack_name,
            "template_body": _template_for("v2"),
            "role_arn": exec_role_arn,
        },
    )
    assert result.get("ok") is False, f"update_stack unexpectedly succeeded: {result}"
    assert result["error_code"] == "InsufficientCapabilitiesException", (
        f"expected InsufficientCapabilitiesException, got {result['error_code']!r}: {result}"
    )

    # Effect absent: the role's Description is unchanged and the stack is
    # still in its post-create terminal state (no update ever started).
    role_desc = iam.get_role(RoleName=role_physical_id)["Role"]
    assert role_desc.get("Description") == "v1", (
        f"expected the NestedRole Description to remain 'v1' after the rejected update, "
        f"got {role_desc.get('Description')!r}"
    )
    stack_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert stack_status == "CREATE_COMPLETE", (
        f"expected the stack to remain CREATE_COMPLETE after the rejected update, got {stack_status!r}"
    )

    # Positive control: same call, with the capability acknowledged.
    control_result = _poll_until_ok(
        ctx,
        fn_name,
        {
            "action": "update_stack",
            "stack_name": stack_name,
            "template_body": _template_for("v2"),
            "role_arn": exec_role_arn,
            "capabilities": ["CAPABILITY_IAM"],
        },
    )
    assert control_result.get("ok") is True, f"positive control update_stack never succeeded: {control_result}"
    final_status = _wait_stack_status(
        ctx,
        stack_name,
        {
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=420,
    )
    assert final_status == "UPDATE_COMPLETE", f"control update ended in {final_status}"
    updated_role_desc = iam.get_role(RoleName=role_physical_id)["Role"]
    assert updated_role_desc.get("Description") == "v2", (
        f"expected the NestedRole Description to become 'v2' after the acknowledged update, "
        f"got {updated_role_desc.get('Description')!r}"
    )


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


def _retry_role_propagation(fn, timeout_s: float = 60, interval_s: float = 5):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if "is invalid or cannot be assumed" in msg or "Unable to assume role" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS
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


def _create_stack_exec_role(ctx, name_suffix: str, statements: list[dict[str, Any]]):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-cfnexec-{name_suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline")))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
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
                Tags=_LAMBDA_TAGS,
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


def _wait_stack_status(ctx, stack_name: str, terminal_statuses: set[str], timeout_s: float = 300, interval_s: float = 5):
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
