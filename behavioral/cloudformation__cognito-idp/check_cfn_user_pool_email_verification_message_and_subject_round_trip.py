"""cfn-user-pool-email-verification-message-and-subject-round-trip."""

from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "cfn-user-pool-email-verification-message-and-subject-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::Cognito::UserPool stores its EmailVerificationMessage and
    EmailVerificationSubject properties verbatim, and DescribeUserPool echoes them back.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogemailverif-")
    pool_name = ctx.unique_name("sim2real-behav-cogemailverifpool-")
    email_message = "Your verification code is {####}. Use it to confirm your email address."
    email_subject = "Confirm your email address"

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": pool_name,
                        "AutoVerifiedAttributes": ["email"],
                        "EmailVerificationMessage": email_message,
                        "EmailVerificationSubject": email_subject,
                    },
                },
            },
            "Outputs": {"PoolRef": {"Value": {"Ref": "Pool"}}},
        }
    )
    cfn.create_stack(
        StackName=stack_name, TemplateBody=template_body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )
    pool_id = _outputs(cfn, stack_name)["PoolRef"]

    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert pool["EmailVerificationMessage"] == email_message, (
        f"expected EmailVerificationMessage {email_message!r}, got "
        f"{pool['EmailVerificationMessage']!r}"
    )
    assert pool["EmailVerificationSubject"] == email_subject, (
        f"expected EmailVerificationSubject {email_subject!r}, got "
        f"{pool['EmailVerificationSubject']!r}"
    )


def _outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
