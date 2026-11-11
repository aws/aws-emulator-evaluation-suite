"""deploy-user-pool-password-policy-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-user-pool-password-policy-enforced"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed UserPool reports its strict PasswordPolicy and SignUp with a violating
    password fails with InvalidPasswordException, leaving no user; a compliant SignUp succeeds."""
    stack_name = ctx.unique_name("sim2real-cog-pwpolicy-")
    declared_policy = {
        "MinimumLength": 12,
        "RequireUppercase": True,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
        "TemporaryPasswordValidityDays": 7,
    }
    template = json.dumps(
        {
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": stack_name + "-pool",
                        "DeletionProtection": "INACTIVE",
                        "Policies": {"PasswordPolicy": declared_policy},
                    },
                },
                "PoolClient": {
                    "Type": "AWS::Cognito::UserPoolClient",
                    "Properties": {
                        "ClientName": stack_name + "-client",
                        "UserPoolId": {"Ref": "Pool"},
                        "ExplicitAuthFlows": [
                            "ALLOW_USER_PASSWORD_AUTH",
                            "ALLOW_REFRESH_TOKEN_AUTH",
                        ],
                        "GenerateSecret": False,
                    },
                },
            },
            "Outputs": {
                "UserPoolId": {"Value": {"Ref": "Pool"}},
                "UserPoolClientId": {"Value": {"Ref": "PoolClient"}},
            },
        }
    )
    outputs = _deploy_cfn(ctx, stack_name, template)
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserPoolClientId"]

    cognito = ctx.client("cognito-idp")
    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    policy = pool["Policies"]["PasswordPolicy"]
    assert policy["MinimumLength"] == declared_policy["MinimumLength"], (
        f"policy.MinimumLength: expected {declared_policy['MinimumLength']!r}, got {policy['MinimumLength']!r}"
    )
    assert policy["RequireUppercase"] == declared_policy["RequireUppercase"], (
        f"policy.RequireUppercase: expected {declared_policy['RequireUppercase']!r}, got {policy['RequireUppercase']!r}"
    )
    assert policy["RequireLowercase"] == declared_policy["RequireLowercase"], (
        f"policy.RequireLowercase: expected {declared_policy['RequireLowercase']!r}, got {policy['RequireLowercase']!r}"
    )
    assert policy["RequireNumbers"] == declared_policy["RequireNumbers"], (
        f"policy.RequireNumbers: expected {declared_policy['RequireNumbers']!r}, got {policy['RequireNumbers']!r}"
    )
    assert policy["RequireSymbols"] == declared_policy["RequireSymbols"], (
        f"policy.RequireSymbols: expected {declared_policy['RequireSymbols']!r}, got {policy['RequireSymbols']!r}"
    )
    assert policy["TemporaryPasswordValidityDays"] == declared_policy["TemporaryPasswordValidityDays"], (
        "policy.TemporaryPasswordValidityDays: expected "
        f"{declared_policy['TemporaryPasswordValidityDays']!r}, got {policy['TemporaryPasswordValidityDays']!r}"
    )

    weak_username = ctx.unique_name("sim2real-cog-weak-")
    code, message = _error(
        lambda: cognito.sign_up(ClientId=client_id, Username=weak_username, Password="short1")
    )
    assert code == "InvalidPasswordException", f"expected InvalidPasswordException, got {code!r}"
    expected_message = "Password did not conform with policy: Password not long enough"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    absent_code, absent_message = _error(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=weak_username)
    )
    assert absent_code == "UserNotFoundException", (
        f"expected UserNotFoundException for the rejected signup, got {absent_code!r}"
    )
    expected_absent_message = "User does not exist."
    assert absent_message == expected_absent_message, f"expected message {expected_absent_message!r}, got {absent_message!r}"

    strong_username = ctx.unique_name("sim2real-cog-strong-")
    resp = cognito.sign_up(
        ClientId=client_id, Username=strong_username, Password="Str0ng!Passw0rd987"
    )
    assert resp["UserSub"], "expected a UserSub for the compliant SignUp, got none"
    described = cognito.admin_get_user(UserPoolId=pool_id, Username=strong_username)
    assert described["Username"] == strong_username, (
        f"expected admin_get_user to find {strong_username!r}, got {described['Username']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deploy_cfn(ctx, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"):
            raise AssertionError(f"stack {stack_name} failed to create: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE (last status={status})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return
        if desc["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
