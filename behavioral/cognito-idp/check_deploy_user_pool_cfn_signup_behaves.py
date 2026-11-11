"""deploy-user-pool-cfn-signup-behaves."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-user-pool-cfn-signup-behaves"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed UserPool enforces its PasswordPolicy on SignUp: a weak password fails with
    InvalidPasswordException and creates no user; a compliant one creates an UNCONFIRMED user."""
    idp = ctx.client("cognito-idp")

    pool_name = ctx.unique_name("sim2real-cfn-pool-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"PoolName": {"Type": "String"}},
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": {"Ref": "PoolName"},
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 12,
                            "RequireUppercase": True,
                            "RequireLowercase": True,
                            "RequireNumbers": True,
                            "RequireSymbols": False,
                        }
                    },
                },
            },
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": {"Fn::Sub": "${PoolName}-client"},
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": [
                        "ALLOW_USER_PASSWORD_AUTH",
                        "ALLOW_REFRESH_TOKEN_AUTH",
                    ],
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "ClientId": {"Value": {"Ref": "Client"}},
        },
    }
    outputs = _deploy_cfn_stack(ctx, template, {"PoolName": pool_name})
    user_pool_id = outputs["UserPoolId"]
    client_id = outputs["ClientId"]

    weak_username = ctx.unique_name("sim2real-weakuser-")
    weak_password = "abc123"  # too short, no uppercase -> violates deployed policy

    def _weak_signup():
        return idp.sign_up(ClientId=client_id, Username=weak_username, Password=weak_password)

    code, message = _error(_weak_signup)
    assert code == "InvalidPasswordException", f"expected InvalidPasswordException, got {code}"
    expected_message = "Password did not conform with policy: Password not long enough"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listing = idp.list_users(UserPoolId=user_pool_id, Filter=f'username = "{weak_username}"')
    assert listing["Users"] == [], "rejected SignUp must not have created a user"

    good_username = ctx.unique_name("sim2real-gooduser-")
    good_password = "Str0ngPassword"  # meets MinimumLength=12, upper/lower/number
    resp = idp.sign_up(ClientId=client_id, Username=good_username, Password=good_password)
    assert resp["UserSub"], "policy-compliant SignUp against the deployed client must return a UserSub"
    described = idp.admin_get_user(UserPoolId=user_pool_id, Username=good_username)
    assert described["UserStatus"] == "UNCONFIRMED", (
        f"expected UNCONFIRMED after compliant SignUp, got {described['UserStatus']}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _deploy_cfn_stack(ctx, template: dict, parameters: dict[str, str]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-cognito-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
