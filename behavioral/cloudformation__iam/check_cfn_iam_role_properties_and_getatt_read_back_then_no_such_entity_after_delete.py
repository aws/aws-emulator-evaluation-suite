"""cfn-iam-role-properties-and-getatt-read-back-then-no-such-entity-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-properties-and-getatt-read-back-then-no-such-entity-after-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "iam"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks by stack id (resolves through DELETE_COMPLETE, unlike
    the bare name) until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::IAM::Role is real at IAM: its trust policy, the properties it
    declared and every Fn::GetAtt attribute match IAM's own answer, and deleting the stack removes
    the role from IAM, not just from CFN."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    stack_name = ctx.unique_name("sim2real-behav-cfn-iamrl-")
    description = ctx.unique_name("sim2real-desc-")

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Description": description,
                    "MaxSessionDuration": 7200,
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "RoleId": {"Value": {"Fn::GetAtt": ["Role", "RoleId"]}},
        },
    })

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    created = _wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    role_name = _physical_id(cfn, stack_id, "Role")

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}

    # Independent read at the destination: IAM's own role record must carry the
    # properties the template declared, and Arn/RoleId must match the GetAtt outputs.
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Description"] == description, (
        f"expected Description {description!r}, got {role.get('Description')!r}"
    )
    assert role["AssumeRolePolicyDocument"] == trust, (
        f"expected the declared trust policy {trust!r}, got {role['AssumeRolePolicyDocument']!r}"
    )
    assert role["MaxSessionDuration"] == 7200, (
        f"expected MaxSessionDuration 7200, got {role['MaxSessionDuration']!r}"
    )
    assert outputs["RoleArn"] == role["Arn"], (
        f"GetAtt Role.Arn was {outputs['RoleArn']!r}, IAM's own Arn is {role['Arn']!r}"
    )
    assert outputs["RoleId"] == role["RoleId"], (
        f"GetAtt Role.RoleId was {outputs['RoleId']!r}, IAM's own RoleId is {role['RoleId']!r}"
    )

    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack(cfn, stack_id)
    assert deleted == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {deleted!r}"

    code, message = _wait_gone(lambda: iam.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity after stack delete, got {code!r}"
    expected_message = f"The role with name {role_name} cannot be found."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _wait_gone(call, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll ``call`` until it raises IAM's not-found error; the physical delete may
    lag DELETE_COMPLETE. Returns ``(code, message)``."""
    deadline = time.monotonic() + timeout_s
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"]["Message"]
            if last_code == "NoSuchEntity":
                return last_code, last_message
        else:
            last_code, last_message = None, None
        time.sleep(interval_s)
    raise AssertionError(
        f"role still answering after {timeout_s}s of polling "
        f"(last_code={last_code!r}, last_message={last_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
