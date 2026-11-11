"""deploy-iam-role-cloudformation-stack-update-changes-trust-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-iam-role-cloudformation-stack-update-changes-trust-policy"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN stack UPDATE of an AWS::IAM::Role's AssumeRolePolicyDocument is persisted exactly and
    applies in place: RoleId and Arn are stable across the update (the role is not replaced)."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfnroleupd-")
    role_name = f"{stack_name}-role"

    def _template_for(service_principal: str) -> str:
        return json.dumps(
            {
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
                                        "Principal": {"Service": service_principal},
                                        "Action": ["sts:AssumeRole"],
                                    }
                                ],
                            },
                        },
                    }
                }
            }
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template_for("lambda.amazonaws.com"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    role_before = iam.get_role(RoleName=role_name)["Role"]
    role_id = role_before["RoleId"]
    before_principal = role_before["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"]
    assert before_principal == "lambda.amazonaws.com", (
        f"expected initial trust principal lambda.amazonaws.com, got {before_principal!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_template_for("ec2.amazonaws.com"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    role_after = iam.get_role(RoleName=role_name)["Role"]
    assert role_after["RoleId"] == role_id, (
        f"update-in-place must not replace the role: expected RoleId {role_id!r}, "
        f"got {role_after['RoleId']!r}"
    )
    statement = role_after["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Principal"]["Service"] == "ec2.amazonaws.com", (
        f"expected updated trust principal ec2.amazonaws.com, got {statement['Principal']['Service']!r}"
    )
    # IAM returns a single-element Action array as a bare string; the policy grammar treats
    # both forms alike, so either is accepted.
    assert statement["Action"] == "sts:AssumeRole" or statement["Action"] == ["sts:AssumeRole"], (
        f"expected Action 'sts:AssumeRole' (bare or one-element list), got {statement['Action']!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
