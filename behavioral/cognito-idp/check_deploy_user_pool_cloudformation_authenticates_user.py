"""deploy-user-pool-cloudformation-authenticates-user."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-user-pool-cloudformation-authenticates-user"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed user pool and client authenticate a user through AdminInitiateAuth
    with a Bearer AccessToken that GetUser accepts."""
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")

    stack_name = ctx.unique_name("sim2real-cfn-pool-")
    template = {
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": stack_name,
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 8,
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
                    "ClientName": f"{stack_name}-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "ExplicitAuthFlows": [
                        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                        "ALLOW_REFRESH_TOKEN_AUTH",
                    ],
                    "GenerateSecret": False,
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "ClientId": {"Value": {"Ref": "Client"}},
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = _stack_outputs(cfn, stack_name)
    pool_id = outputs["UserPoolId"]
    client_id = outputs["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real123"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = resp.get("AuthenticationResult")
    assert result is not None, f"expected direct auth success, got {resp}"
    assert result.get("AccessToken"), "AuthenticationResult missing AccessToken"
    assert result.get("TokenType") == "Bearer", f"expected TokenType Bearer, got {result.get('TokenType')!r}"

    # The issued access token must actually be valid against the deployed pool.
    who = cognito.get_user(AccessToken=result["AccessToken"])
    assert who["Username"] == username, f"expected GetUser to resolve to {username!r}, got {who['Username']!r}"


def _stack_outputs(cfn: Any, stack_name: str) -> dict[str, str]:
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(cfn: Any, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
