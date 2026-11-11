"""get-client-token-rejects-wrong-secret-and-undeclared-scope."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-client-token-rejects-wrong-secret-and-undeclared-scope"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClientToken rejects a wrong secret and a declared-but-ungranted scope with
    NotAuthorizedException; the correct secret with the granted scope issues a token with
    exactly that scope.
    """
    resource_server_id = "m2m-api"
    granted_scope_name = "read"
    ungranted_scope_name = "write"
    granted_scope = f"{resource_server_id}/{granted_scope_name}"
    ungranted_scope = f"{resource_server_id}/{ungranted_scope_name}"
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
                    "Scopes": [
                        {"ScopeName": granted_scope_name, "ScopeDescription": "Read access"},
                        {"ScopeName": ungranted_scope_name, "ScopeDescription": "Write access"},
                    ],
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
                    # Only the "read" scope is granted to this client, even though the
                    # resource server also declares "write".
                    "AllowedOAuthScopes": [granted_scope],
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "SupportedIdentityProviders": ["COGNITO"],
                },
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
    assert client_desc["AllowedOAuthScopes"] == [granted_scope], (
        f"expected AllowedOAuthScopes=[{granted_scope!r}], got {client_desc['AllowedOAuthScopes']!r}"
    )
    correct_secret = client_desc["ClientSecret"]
    wrong_secret = correct_secret[:-1] + ("A" if correct_secret[-1] != "A" else "B")

    # Boundary 1: wrong client secret must be rejected, no token issued.
    code_wrong_secret = _error(
        lambda: cognito.get_client_token(ClientId=client_id, Secret=wrong_secret, Scopes=[granted_scope])
    )
    assert code_wrong_secret == ("NotAuthorizedException", "Invalid client or secret"), (
        f"got {code_wrong_secret!r}"
    )

    # Boundary 2: correct secret but a scope that exists on the resource server yet
    # was never granted to THIS client must also be rejected, no token issued.
    # Cognito returns NotAuthorizedException here too, not InvalidParameterException.
    code_undeclared_scope = _error(
        lambda: cognito.get_client_token(ClientId=client_id, Secret=correct_secret, Scopes=[ungranted_scope])
    )
    assert code_undeclared_scope == ("NotAuthorizedException", "Client is not allowed to request these scopes"), (
        f"got {code_undeclared_scope!r}"
    )

    # Positive control: correct secret + the actually-granted scope succeeds against
    # the SAME deployed client, proving neither rejection above was a blanket-deny.
    token_resp = cognito.get_client_token(ClientId=client_id, Secret=correct_secret, Scopes=[granted_scope])
    result = token_resp["ClientAuthenticationResult"]
    assert result["TokenType"] == "Bearer", f"expected TokenType=Bearer, got {result['TokenType']!r}"
    claims = _decode_jwt_payload(result["AccessToken"])
    assert claims["client_id"] == client_id, f"expected client_id={client_id!r}, got {claims['client_id']!r}"
    assert claims["scope"].split() == [granted_scope], (
        f"expected token scope=[{granted_scope!r}], got {claims['scope'].split()!r}"
    )


def _error(fn):
    """Call fn() and return its error (Code, Message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _decode_jwt_payload(token: str) -> dict:
    import base64

    payload_segment = token.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _deploy_cfn_stack(ctx, template: dict) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cog-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
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
