"""deploy-identity-provider-cfn-federation-resolves."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-identity-provider-cfn-federation-resolves"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed OIDC UserPoolIdentityProvider resolves via GetIdentityProviderByIdentifier,
    supports AdminLinkProviderForUser linking, and an unknown identifier fails with
    ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")

    pool_name = ctx.unique_name("sim2real-cfn-idp-pool-")
    # ProviderName is capped at 32 chars and rejects underscores/spaces; IdpIdentifier is
    # capped at 40 -- keep well under with short prefixes and a safe charset.
    provider_name = ctx.unique_name("s2p-")[:32].replace("_", "-")
    idp_identifier = ctx.unique_name("s2idpid-")[:40]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "PoolName": {"Type": "String"},
            "ProviderName": {"Type": "String"},
            "IdpIdentifier": {"Type": "String"},
        },
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": {"Ref": "PoolName"}},
            },
            "Idp": {
                "Type": "AWS::Cognito::UserPoolIdentityProvider",
                "Properties": {
                    "UserPoolId": {"Ref": "Pool"},
                    "ProviderName": {"Ref": "ProviderName"},
                    "ProviderType": "OIDC",
                    "ProviderDetails": {
                        "client_id": "sim2real-oidc-client-id",
                        "client_secret": "sim2real-oidc-client-secret",
                        "attributes_request_method": "GET",
                        "oidc_issuer": "https://auth.example.com",
                        "authorize_scopes": "openid profile email",
                        "authorize_url": "https://auth.example.com/authorize",
                        "token_url": "https://auth.example.com/token",
                        "attributes_url": "https://auth.example.com/userInfo",
                        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                    },
                    "AttributeMapping": {"email": "email"},
                    "IdpIdentifiers": [{"Ref": "IdpIdentifier"}],
                },
            },
        },
        "Outputs": {"UserPoolId": {"Value": {"Ref": "Pool"}}},
    }
    outputs = _deploy_cfn_stack(
        ctx,
        template,
        {
            "PoolName": pool_name,
            "ProviderName": provider_name,
            "IdpIdentifier": idp_identifier,
        },
    )
    user_pool_id = outputs["UserPoolId"]

    # Resolvable by its IdpIdentifier, with the CFN-supplied config intact.
    resolved = idp.get_identity_provider_by_identifier(
        UserPoolId=user_pool_id, IdpIdentifier=idp_identifier
    )["IdentityProvider"]
    assert resolved["ProviderName"] == provider_name
    assert resolved["ProviderType"] == "OIDC"
    assert resolved["ProviderDetails"]["oidc_issuer"] == "https://auth.example.com"

    # Usable for federation linking: link a real local user to a synthetic source identity
    # from the deployed IdP.
    username = ctx.unique_name("sim2real-linkeduser-")
    idp.admin_create_user(UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))

    fed_sub = ctx.unique_name("fed-sub-")
    idp.admin_link_provider_for_user(
        UserPoolId=user_pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": username},
        SourceUser={
            "ProviderName": provider_name,
            "ProviderAttributeName": "sub",
            "ProviderAttributeValue": fed_sub,
        },
    )

    # Cognito records each linked federated identity in the user's "identities" attribute.
    identities = _linked_identities(idp, user_pool_id, username)
    assert any(
        i.get("providerName") == provider_name and i.get("userId") == fed_sub
        for i in identities
    ), f"expected {provider_name}/{fed_sub} in identities after linking, got {identities}"

    bogus_identifier = ctx.unique_name("sim2real-nonexistent-idpid-")[:40]

    def _resolve_bogus_identifier():
        return idp.get_identity_provider_by_identifier(
            UserPoolId=user_pool_id,
            IdpIdentifier=bogus_identifier,
        )

    code, message = _error(_resolve_bogus_identifier)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Identity provider {bogus_identifier} for tenantId {user_pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _linked_identities(idp, user_pool_id: str, username: str) -> list[dict]:
    attrs = idp.admin_get_user(UserPoolId=user_pool_id, Username=username)["UserAttributes"]
    raw = next((a["Value"] for a in attrs if a["Name"] == "identities"), None)
    return json.loads(raw) if raw is not None else []


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
