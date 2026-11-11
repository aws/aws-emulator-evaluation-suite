"""deploy-user-pool-client-cfn-oauth-token-exchange-works."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-user-pool-client-cfn-oauth-token-exchange-works"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed OAuth client describes with the templated code flow and scopes,
    authenticates a user through InitiateAuth with an access, ID and refresh token, and the refresh
    token yields a new access token."""
    idp = ctx.client("cognito-idp")

    pool_name = ctx.unique_name("sim2real-cfn-oauth-pool-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"PoolName": {"Type": "String"}},
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": {"Ref": "PoolName"}},
            },
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": {"Fn::Sub": "${PoolName}-client"},
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": [
                        "ALLOW_USER_PASSWORD_AUTH",
                        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                        "ALLOW_REFRESH_TOKEN_AUTH",
                    ],
                    "AllowedOAuthFlows": ["code"],
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "AllowedOAuthScopes": ["openid", "email", "profile"],
                    "CallbackURLs": ["https://example.com/callback"],
                    "SupportedIdentityProviders": ["COGNITO"],
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

    # Prove the OAuth config landed (not just an ignored/cosmetic field on the client).
    client_desc = idp.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert client_desc["AllowedOAuthFlows"] == ["code"], (
        f"expected AllowedOAuthFlows ['code'], got {client_desc['AllowedOAuthFlows']!r}"
    )
    assert client_desc["AllowedOAuthFlowsUserPoolClient"] is True, (
        f"expected AllowedOAuthFlowsUserPoolClient True, got "
        f"{client_desc['AllowedOAuthFlowsUserPoolClient']!r}"
    )
    assert set(client_desc["AllowedOAuthScopes"]) == {"openid", "email", "profile"}, (
        f"expected scopes {{openid, email, profile}}, got {client_desc['AllowedOAuthScopes']!r}"
    )

    username = ctx.unique_name("sim2real-oauthuser-")
    password = "Str0ng!Passw0rd"
    idp.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
    )

    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "ChallengeName" not in resp, f"unexpected challenge: {resp.get('ChallengeName')}"
    result = resp["AuthenticationResult"]
    # AccessToken/IdToken are JWTs (three dot-separated segments); RefreshToken is an
    # opaque Cognito-issued token (not JWT-formatted) but must be a substantial string.
    for key in ("AccessToken", "IdToken"):
        token = result[key]
        assert isinstance(token, str) and len(token.split(".")) == 3, f"{key} not a JWT: {token!r}"
    refresh_token = result["RefreshToken"]
    assert isinstance(refresh_token, str) and len(refresh_token) > 20, (
        f"RefreshToken not a substantial token: {refresh_token!r}"
    )
    assert result["TokenType"] == "Bearer", f"expected TokenType Bearer, got {result['TokenType']!r}"

    # The refresh token issued by the deployed client must itself work through
    # InitiateAuth's REFRESH_TOKEN_AUTH flow (proves ALLOW_REFRESH_TOKEN_AUTH landed).
    refresh_resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )
    refreshed = refresh_resp["AuthenticationResult"]
    refreshed_token = refreshed["AccessToken"]
    assert isinstance(refreshed_token, str) and len(refreshed_token.split(".")) == 3, (
        f"AccessToken from REFRESH_TOKEN_AUTH not a JWT: {refreshed_token!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
