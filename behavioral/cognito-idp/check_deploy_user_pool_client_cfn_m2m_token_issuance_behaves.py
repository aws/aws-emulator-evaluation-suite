"""deploy-user-pool-client-cfn-m2m-token-issuance-behaves."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "deploy-user-pool-client-cfn-m2m-token-issuance-behaves"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed client_credentials client, resource server and domain describe as
    templated, and GetClientToken issues a Bearer access token whose client_id and scope claims
    match the template."""
    resource_server_id = "m2m-api"
    scope_name = "read"
    full_scope = f"{resource_server_id}/{scope_name}"
    domain_prefix = ctx.unique_name("sim2real-cog-dom-").lower()[:63].rstrip("-")
    client_name = ctx.unique_name("sim2real-cog-client-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": ctx.unique_name("sim2real-cog-m2m-pool-")},
            },
            "ResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "UserPoolId": {"Ref": "UserPool"},
                    "Identifier": resource_server_id,
                    "Name": "M2M API",
                    "Scopes": [{"ScopeName": scope_name, "ScopeDescription": "Read access"}],
                },
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "DependsOn": "ResourceServer",
                "Properties": {
                    "UserPoolId": {"Ref": "UserPool"},
                    "ClientName": client_name,
                    "GenerateSecret": True,
                    # ALLOW_CLIENT_TOKEN_AUTH must be the app client's ONLY explicit auth flow --
                    # it is mutually exclusive with user-authentication flows (AWS docs:
                    # "Obtaining M2M access tokens with GetClientToken").
                    "ExplicitAuthFlows": ["ALLOW_CLIENT_TOKEN_AUTH"],
                    "AllowedOAuthFlows": ["client_credentials"],
                    "AllowedOAuthScopes": [full_scope],
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "SupportedIdentityProviders": ["COGNITO"],
                },
            },
            "UserPoolDomain": {
                "Type": "AWS::Cognito::UserPoolDomain",
                "Properties": {"Domain": domain_prefix, "UserPoolId": {"Ref": "UserPool"}},
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "ClientId": {"Value": {"Ref": "UserPoolClient"}},
        },
    }
    outputs = _deploy_cfn_stack(ctx, template)
    pool_id = outputs["UserPoolId"]
    client_id = outputs["ClientId"]

    cognito = ctx.client("cognito-idp")

    client_desc = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert client_desc["AllowedOAuthScopes"] == [full_scope], (
        f"expected CFN-declared scope {full_scope!r}, describe_user_pool_client reported "
        f"{client_desc['AllowedOAuthScopes']!r}"
    )
    assert client_desc["AllowedOAuthFlows"] == ["client_credentials"], (
        f"expected AllowedOAuthFlows ['client_credentials'], got {client_desc['AllowedOAuthFlows']!r}"
    )
    secret = client_desc["ClientSecret"]

    token_resp = cognito.get_client_token(ClientId=client_id, Secret=secret, Scopes=[full_scope])
    result = token_resp["ClientAuthenticationResult"]
    assert result["TokenType"] == "Bearer", f"expected token_type Bearer, got {result['TokenType']!r}"
    assert result["ExpiresIn"] > 0, f"expected ExpiresIn > 0, got {result['ExpiresIn']!r}"

    claims = _decode_jwt_payload(result["AccessToken"])
    assert claims["token_use"] == "access", f"expected token_use 'access', got {claims.get('token_use')!r}"
    assert claims["client_id"] == client_id, (
        f"expected client_id claim {client_id!r}, got {claims.get('client_id')!r}"
    )
    assert full_scope in claims["scope"].split(), (
        f"expected scope {full_scope!r} in token scope claim, got {claims.get('scope')!r}"
    )


def _decode_jwt_payload(token: str) -> dict:
    payload_segment = token.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


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
