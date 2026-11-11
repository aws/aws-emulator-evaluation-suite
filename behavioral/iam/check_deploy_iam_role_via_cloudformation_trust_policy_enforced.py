"""deploy-iam-role-via-cloudformation-trust-policy-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-role-via-cloudformation-trust-policy-enforced"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::IAM::Role persists its trust policy exactly and accepts a managed policy
    attachment post-deploy; a role with an attached managed policy cannot be deleted until
    detached."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    role_name = ctx.unique_name("sim2real-behav-role-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    template = {
        "Resources": {
            "TestRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                },
            }
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["TestRole", "Arn"]}}},
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    stack = _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"})
    outputs = _stack_outputs(stack)

    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == outputs["RoleArn"], (role["Arn"], outputs["RoleArn"])
    statement = role["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Effect"] == "Allow", statement["Effect"]
    assert statement["Principal"]["Service"] == "ec2.amazonaws.com", statement["Principal"]
    assert statement["Action"] == "sts:AssumeRole", statement["Action"]

    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert any(p["PolicyArn"] == policy_arn for p in attached), attached

    # Negative: the CFN-managed role has an attached managed policy, so a direct
    # DeleteRole is rejected -- the role must remain intact until detached.
    code, code_msg = _client_error(lambda: iam.delete_role(RoleName=role_name))
    assert code == "DeleteConflict", code
    assert code_msg == "Cannot delete entity, must detach all policies first.", f"unexpected error message {code_msg!r}"
    still_there = iam.get_role(RoleName=role_name)["Role"]
    assert still_there["RoleId"] == role["RoleId"], "role must remain intact until detached"

    # Positive control (a separate, freely-destroyable role): the identical
    # attach -> conflict -> detach -> delete sequence succeeds once unblocked.
    control_role = ctx.unique_name("sim2real-behav-role-ctrl-")
    iam.create_role(
        RoleName=control_role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=control_role)))
    iam.attach_role_policy(RoleName=control_role, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=control_role, PolicyArn=policy_arn)))
    ctrl_code, ctrl_code_msg = _client_error(lambda: iam.delete_role(RoleName=control_role))
    assert ctrl_code == "DeleteConflict", ctrl_code
    assert ctrl_code_msg == "Cannot delete entity, must detach all policies first.", f"unexpected error message {ctrl_code_msg!r}"
    iam.detach_role_policy(RoleName=control_role, PolicyArn=policy_arn)
    iam.delete_role(RoleName=control_role)
    gone_code, gone_code_msg = _client_error(lambda: iam.get_role(RoleName=control_role))
    assert gone_code == "NoSuchEntity", gone_code
    assert gone_code_msg == f"The role with name {control_role} cannot be found.", f"unexpected error message {gone_code_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in ok_statuses:
            return stacks[0]
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


def _wait_stack_deleted(ctx, stack_name, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _delete_stack_and_wait(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(ctx, stack_name)


def _stack_outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
