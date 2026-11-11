"""deploy-iam-user-cloudformation-stack-update-replaces-inline-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-iam-user-cloudformation-stack-update-replaces-inline-policy"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN stack UPDATE of an AWS::IAM::User's inline Policies overwrites the existing document in
    place (PutUserPolicy semantics): the old document is gone and no second inline policy
    appears."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfnuserupd-")
    user_name = f"{stack_name}-user"
    inline_policy_name = "InlinePolicy1"

    def _template_for(action: str) -> str:
        return json.dumps(
            {
                "Resources": {
                    "TestUser": {
                        "Type": "AWS::IAM::User",
                        "Properties": {
                            "UserName": user_name,
                            "Policies": [
                                {
                                    "PolicyName": inline_policy_name,
                                    "PolicyDocument": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": [action],
                                                "Resource": ["*"],
                                            }
                                        ],
                                    },
                                }
                            ],
                        },
                    }
                }
            }
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template_for("s3:ListAllMyBuckets"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    before = iam.get_user_policy(UserName=user_name, PolicyName=inline_policy_name)
    before_actions = before["PolicyDocument"]["Statement"][0]["Action"]
    assert before_actions == ["s3:ListAllMyBuckets"], (
        f"expected the just-created inline policy to grant s3:ListAllMyBuckets, got {before_actions!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_template_for("ec2:DescribeInstances"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    after = iam.get_user_policy(UserName=user_name, PolicyName=inline_policy_name)
    after_actions = after["PolicyDocument"]["Statement"][0]["Action"]
    assert after_actions == ["ec2:DescribeInstances"], (
        f"expected the stack update to overwrite the inline policy with ec2:DescribeInstances, got {after_actions!r}"
    )

    policy_names = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    assert policy_names == [inline_policy_name], (
        f"update must overwrite the inline policy in place, not duplicate it: {policy_names!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
