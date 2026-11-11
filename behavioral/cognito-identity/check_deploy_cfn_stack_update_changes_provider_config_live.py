"""deploy-cfn-stack-update-changes-provider-config-live."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-update-changes-provider-config-live"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack update that adds a user-pool provider to the identity pool changes
    GetId in place: a signed user-pool ID token is refused with the exact error before the update
    and accepted after it, for the same IdentityPoolId."""
    cognito_idp = ctx.client("cognito-idp")
    cog = ctx.client("cognito-identity")

    # --- provision a real Cognito user pool + confirmed user + real ID token ---
    user_pool_name = ctx.unique_name("sim2real-cup-")
    password = "Sim2Real123!"
    pool = cognito_idp.create_user_pool(
        PoolName=user_pool_name,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": CHECK},
    )
    user_pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito_idp.delete_user_pool(UserPoolId=user_pool_id))

    client = cognito_idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-cupc-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    client_id = client["UserPoolClient"]["ClientId"]

    username = "sim2real-testuser"
    cognito_idp.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito_idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
    )
    auth = cognito_idp.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_key = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    # --- deploy the identity pool WITHOUT this user pool registered ---
    pool_name = ctx.unique_name("sim2real-cip-")
    stack_name = ctx.unique_name("sim2real-cfn-cip-")

    template_v1 = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "IdentityPool": {
                    "Type": "AWS::Cognito::IdentityPool",
                    "Properties": {
                        "IdentityPoolName": pool_name,
                        "AllowUnauthenticatedIdentities": True,
                    },
                }
            },
            "Outputs": {"IdentityPoolId": {"Value": {"Ref": "IdentityPool"}}},
        }
    )
    outputs = _deploy_stack(ctx, stack_name, template_v1)
    identity_pool_id = outputs["IdentityPoolId"]

    desc_before = cog.describe_identity_pool(IdentityPoolId=identity_pool_id)
    providers_before = desc_before.get("CognitoIdentityProviders", [])
    assert not providers_before, f"expected no providers before the update, got {providers_before!r}"

    err = _error(
        lambda: cog.get_id(IdentityPoolId=identity_pool_id, Logins={provider_key: id_token})
    )
    expected = (
        "NotAuthorizedException",
        f"Identity pool - {identity_pool_id} does not have identity providers configured.",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # --- update the SAME stack to register the user pool as a provider ---
    template_v2 = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "IdentityPool": {
                    "Type": "AWS::Cognito::IdentityPool",
                    "Properties": {
                        "IdentityPoolName": pool_name,
                        "AllowUnauthenticatedIdentities": True,
                        "CognitoIdentityProviders": [
                            {
                                "ProviderName": provider_key,
                                "ClientId": client_id,
                                "ServerSideTokenCheck": False,
                            }
                        ],
                    },
                }
            },
            "Outputs": {"IdentityPoolId": {"Value": {"Ref": "IdentityPool"}}},
        }
    )
    updated_outputs = _update_stack(ctx, stack_name, template_v2)
    # same identity pool id => in-place update, not a replacement/recreation
    assert updated_outputs["IdentityPoolId"] == identity_pool_id, (
        f"stack update replaced the pool instead of updating it in place: "
        f"before={identity_pool_id!r} after={updated_outputs['IdentityPoolId']!r}"
    )

    desc_after = cog.describe_identity_pool(IdentityPoolId=identity_pool_id)
    providers = desc_after.get("CognitoIdentityProviders", [])
    assert any(
        p["ProviderName"] == provider_key and p["ClientId"] == client_id for p in providers
    ), providers

    resp = cog.get_id(IdentityPoolId=identity_pool_id, Logins={provider_key: id_token})
    identity_id = resp["IdentityId"]
    assert re.match(r"^[\w-]+:[0-9a-f-]+$", identity_id), identity_id


def _wait_stack(cfn, stack_name: str, waiter_name: str) -> None:
    waiter = cfn.get_waiter(waiter_name)
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _stack_outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    if not stacks:
        raise AssertionError(f"stack {stack_name} not found")
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")


def _deploy_stack(ctx, stack_name: str, template_body: str, capabilities=None) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": CHECK}],
        **({"Capabilities": capabilities} if capabilities else {}),
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")
    return _stack_outputs(cfn, stack_name)


def _update_stack(ctx, stack_name: str, template_body: str, capabilities=None) -> dict:
    cfn = ctx.client("cloudformation")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.update_stack(**kwargs)
    _wait_stack(cfn, stack_name, "stack_update_complete")
    return _stack_outputs(cfn, stack_name)


def _error(fn):
    """Call fn(); return its ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
