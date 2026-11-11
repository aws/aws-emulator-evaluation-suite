"""deploy-iam-managed-policy-cloudformation-stack-delete-cascades."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-iam-managed-policy-cloudformation-stack-delete-cascades"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a stack whose AWS::IAM::ManagedPolicy is attached to its AWS::IAM::Role removes both:
    CloudFormation detaches the policy first instead of leaving a DeleteConflict orphan."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfnpolydel-")
    role_name = f"{stack_name}-role"
    policy_name = f"{stack_name}-policy"

    template = json.dumps(
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
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": ["sts:AssumeRole"],
                                }
                            ],
                        },
                    },
                },
                "TestPolicy": {
                    "Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {
                        "ManagedPolicyName": policy_name,
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": ["*"]}
                            ],
                        },
                        "Roles": [{"Ref": "TestRole"}],
                    },
                },
            },
            "Outputs": {"PolicyArn": {"Value": {"Ref": "TestPolicy"}}},
        }
    )

    cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_NAMED_IAM"]
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    policy_arn = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}["PolicyArn"]

    # Confirm the attachment is real before tearing it down.
    attachment_count = iam.get_policy(PolicyArn=policy_arn)["Policy"]["AttachmentCount"]
    assert attachment_count == 1, (
        f"expected policy {policy_arn} attached to exactly 1 entity before delete, "
        f"got AttachmentCount={attachment_count}"
    )

    _delete_stack(cfn, stack_name)

    policy_code, policy_code_msg = _client_error(lambda: iam.get_policy(PolicyArn=policy_arn))
    assert policy_code == "NoSuchEntity", (
        f"expected NoSuchEntity reading deleted policy {policy_arn}, got {policy_code}"
    )
    assert policy_code_msg == f"Policy {policy_arn} was not found.", f"unexpected error message {policy_code_msg!r}"
    role_code, role_code_msg = _client_error(lambda: iam.get_role(RoleName=role_name))
    assert role_code == "NoSuchEntity", (
        f"expected NoSuchEntity reading deleted role {role_name}, got {role_code}"
    )
    assert role_code_msg == f"The role with name {role_name} cannot be found.", f"unexpected error message {role_code_msg!r}"

    # A mutation against the now-gone identities must also fail, not just a read.
    tag_policy_code, tag_policy_code_msg = _client_error(
        lambda: iam.tag_policy(PolicyArn=policy_arn, Tags=[{"Key": "probe", "Value": "post-delete"}])
    )
    assert tag_policy_code == "NoSuchEntity", (
        f"expected NoSuchEntity tagging deleted policy {policy_arn}, got {tag_policy_code}"
    )
    assert tag_policy_code_msg == f"Policy {policy_arn} was not found.", f"unexpected error message {tag_policy_code_msg!r}"
    tag_role_code, tag_role_code_msg = _client_error(
        lambda: iam.tag_role(RoleName=role_name, Tags=[{"Key": "probe", "Value": "post-delete"}])
    )
    assert tag_role_code == "NoSuchEntity", (
        f"expected NoSuchEntity tagging deleted role {role_name}, got {tag_role_code}"
    )
    assert tag_role_code_msg == f"The role with name {role_name} cannot be found.", f"unexpected error message {tag_role_code_msg!r}"


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
