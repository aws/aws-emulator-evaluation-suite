"""deploy-user-pool-cfn-enforces-configured-password-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-user-pool-cfn-enforces-configured-password-policy"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed UserPool reports its strict PasswordPolicy; AdminSetUserPassword rejects a
    weak password with InvalidPasswordException (status unchanged) and a compliant one CONFIRMs."""
    pool_name = ctx.unique_name("sim2real-cog-pwpolicy-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": pool_name,
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 14,
                            "RequireUppercase": True,
                            "RequireLowercase": True,
                            "RequireNumbers": True,
                            "RequireSymbols": True,
                            "TemporaryPasswordValidityDays": 7,
                        }
                    },
                },
            }
        },
        "Outputs": {"UserPoolId": {"Value": {"Ref": "UserPool"}}},
    }
    outputs = _deploy_cfn_stack(ctx, template)
    pool_id = outputs["UserPoolId"]

    cognito = ctx.client("cognito-idp")

    policy = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["Policies"]["PasswordPolicy"]
    assert policy["MinimumLength"] == 14, f"expected MinimumLength=14, got {policy['MinimumLength']!r}"
    assert policy["RequireUppercase"] is True, f"expected RequireUppercase=True, got {policy['RequireUppercase']!r}"
    assert policy["RequireLowercase"] is True, f"expected RequireLowercase=True, got {policy['RequireLowercase']!r}"
    assert policy["RequireNumbers"] is True, f"expected RequireNumbers=True, got {policy['RequireNumbers']!r}"
    assert policy["RequireSymbols"] is True, f"expected RequireSymbols=True, got {policy['RequireSymbols']!r}"
    assert policy["TemporaryPasswordValidityDays"] == 7, (
        f"expected TemporaryPasswordValidityDays=7, got {policy['TemporaryPasswordValidityDays']!r}"
    )

    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Tmp9!Passw0rd123",  # compliant: satisfies policy so create succeeds
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))

    # Negative: a weak password (too short, no symbol/number/case mix) is rejected.
    code, message = _error(
        lambda: cognito.admin_set_user_password(
            UserPoolId=pool_id, Username=username, Password="weakpass", Permanent=True
        )
    )
    assert code == "InvalidPasswordException", f"expected InvalidPasswordException, got {code!r}"
    expected_message = "Password does not conform to policy: Password not long enough"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    status_after_reject = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_after_reject == "FORCE_CHANGE_PASSWORD", (
        f"expected status FORCE_CHANGE_PASSWORD after rejected AdminSetUserPassword, "
        f"got {status_after_reject!r}"
    )

    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="Str0ng#Passw0rd2024", Permanent=True
    )
    status_after_accept = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_after_accept == "CONFIRMED", (
        f"expected status CONFIRMED after compliant AdminSetUserPassword, got {status_after_accept!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deploy_cfn_stack(ctx, template: dict) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cog-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
