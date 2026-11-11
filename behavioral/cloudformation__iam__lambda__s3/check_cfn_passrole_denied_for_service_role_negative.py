"""cfn-passrole-denied-for-service-role-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-passrole-denied-for-service-role-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal explicitly denied iam:PassRole deploys a stack whose Lambda function passes a role:
    the stack reaches ROLLBACK_COMPLETE naming PassRole and GetFunction fails ResourceNotFoundException;
    the same template deployed by a principal with iam:PassRole creates the function (positive control)."""
    iam = ctx.client("iam")
    ctx.client("sts")

    user_name = _xname(ctx, "user")
    iam.create_user(UserName=user_name, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudformation:*",
                    "iam:CreateRole",
                    "iam:DeleteRole",
                    "iam:GetRole",
                    "iam:TagRole",
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:GetRolePolicy",
                    "iam:ListRolePolicies",
                    "iam:ListAttachedRolePolicies",
                    "lambda:CreateFunction",
                    "lambda:DeleteFunction",
                    "lambda:GetFunction",
                    "lambda:TagResource",
                    "sts:GetCallerIdentity",
                ],
                "Resource": "*",
            },
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName="limited", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName="limited"))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    limited_creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    limited_sts = ctx.client("sts", creds=limited_creds)
    # new IAM credentials + policy are eventually consistent; poll until usable
    _poll_until(
        lambda: _credentials_usable(limited_sts),
        lambda usable: usable,
        timeout_s=30.0,
        interval_s=2.0,
        description="new IAM credentials usable",
    )

    limited_cfn = ctx.client("cloudformation", creds=limited_creds)

    function_name = _xname(ctx, "fn")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
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
                    },
                },
                "Function": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": function_name,
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 10,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": "def handler(event, context):\n    return {'ok': True}\n"
                        },
                    },
                },
            },
        }
    )

    stack_name = _xname(ctx, "stk")
    limited_cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_IAM"]
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    cfn = ctx.client("cloudformation")
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack {stack_name} terminal",
    )
    # exact expected outcome: PassRole denial fails Function creation, triggering the default
    # automatic rollback, which succeeds because the only other resource (the role) is deletable.
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected stack {stack_name} to roll back after the denied PassRole, got {final_status!r}"
    )

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == "Function" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert reasons and any("PassRole" in r for r in reasons), reasons

    # effect absent: the Lambda function was never created
    lam = ctx.client("lambda")
    missing_code, missing_message = _error_code(lambda: lam.get_function(FunctionName=function_name))
    assert missing_code == "ResourceNotFoundException", (
        f"expected get_function({function_name!r}) to fail with ResourceNotFoundException, "
        f"got {missing_code!r}"
    )
    expected_missing = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    )
    assert missing_message == expected_missing, (
        f"get_function message {missing_message!r} != {expected_missing!r}"
    )

    # positive control: identical template, deployed with full (admin) credentials, succeeds
    control_function_name = _xname(ctx, "fn-ctrl")
    control_template = template.replace(function_name, control_function_name)
    _deploy_cfn(ctx, control_template, capabilities=["CAPABILITY_IAM"])
    control = lam.get_function(FunctionName=control_function_name)
    assert control["Configuration"]["FunctionName"] == control_function_name, (
        f"expected the admin-deployed control function {control_function_name!r} to exist, "
        f"got {control['Configuration'].get('FunctionName')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _credentials_usable(sts) -> bool:
    try:
        sts.get_caller_identity()
    except ClientError:
        return False
    return True


def _error_code(fn):
    """Return ``(code, message)`` of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
