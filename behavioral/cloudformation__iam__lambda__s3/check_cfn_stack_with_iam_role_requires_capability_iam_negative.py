"""cfn-stack-with-iam-role-requires-capability-iam-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-with-iam-role-requires-capability-iam-negative"
GROUP = "capability-gating"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack rejects a template defining AWS::IAM::Role without CAPABILITY_IAM, and no
    stack or role is left behind; the identical template succeeds once the capability is granted."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    name = _xname(ctx, "stk")

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
                }
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}}},
        }
    )

    # negative: no Capabilities passed at all
    code, message = _error_code(lambda: cfn.create_stack(StackName=name, TemplateBody=template))
    assert code == "InsufficientCapabilitiesException", (
        f"CreateStack with an undeclared AWS::IAM::Role must be rejected with "
        f"InsufficientCapabilitiesException when no Capabilities are supplied; got {code!r}"
    )
    expected_message = "Requires capabilities : [CAPABILITY_IAM]"
    assert message == expected_message, f"message {message!r} != {expected_message!r}"

    # effect absent: the stack was never actually created
    not_found_code, not_found_message = _error_code(lambda: cfn.describe_stacks(StackName=name))
    assert not_found_code == "ValidationError", (
        f"the rejected CreateStack must not register a stack at all; describe_stacks for "
        f"{name!r} should report ValidationError (not found), got {not_found_code!r}"
    )
    expected_not_found_message = f"Stack with id {name} does not exist"
    assert not_found_message == expected_not_found_message, f"message {not_found_message!r} != {expected_not_found_message!r}"

    # positive control: the identical call succeeds once CAPABILITY_IAM is granted, and the role
    # it declares is real at the consumer (IAM), not just a CFN-reported CREATE_COMPLETE.
    result = _deploy_cfn(ctx, template, stack_name=name, capabilities=["CAPABILITY_IAM"])
    role_arn = result["outputs"]["RoleArn"]
    role_name = role_arn.split("/")[-1]
    role = iam.get_role(RoleName=role_name)
    assert role["Role"]["Arn"] == role_arn, (
        f"the role CloudFormation reported creating must be readable via IAM's own GetRole with "
        f"the same ARN; expected {role_arn!r}, IAM reported {role['Role']['Arn']!r}"
    )

    # deletes prove gone and unusable: tear down the stack now (ahead of ctx.on_cleanup, which
    # tolerates an already-gone stack) and assert the role IAM just confirmed real is now absent.
    _delete_stack_and_wait(ctx, name)
    gone_code, gone_message = _error_code(lambda: iam.get_role(RoleName=role_name))
    assert gone_code == "NoSuchEntity", (
        f"deleting the stack must remove the role CFN created for it; expected IAM GetRole to "
        f"report NoSuchEntity for {role_name!r}, got {gone_code!r}"
    )
    expected_gone_message = f"The role with name {role_name} cannot be found."
    assert gone_message == expected_gone_message, f"message {gone_message!r} != {expected_gone_message!r}"


# ===== helpers =====
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
    """Delete a CFN stack and wait for DELETE_COMPLETE or for the stack to no longer exist."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return "GONE"
            raise

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


def _error_code(fn):
    """Call fn(); return its botocore error ``(code, message)``. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available
    and must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
