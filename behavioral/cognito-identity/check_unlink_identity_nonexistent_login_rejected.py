"""unlink-identity-nonexistent-login-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-nonexistent-login-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity removing a linked login while supplying a bogus token for that provider is
    rejected with NotAuthorizedException and leaves Logins unchanged; the same unlink with the
    valid token succeeds and Logins reads back as the "DISABLED" sentinel."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    identity = ctx.client("cognito-identity")

    pool_id, client_id, username, password = _create_confirmed_user_pool_user(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    auth = cidp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]

    ci_pool_id = identity.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-cipool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=ci_pool_id))

    logins = {provider_name: id_token}
    identity_id = identity.get_id(IdentityPoolId=ci_pool_id, Logins=logins)["IdentityId"]

    described = identity.describe_identity(IdentityId=identity_id)
    assert described["Logins"] == [provider_name], (
        f"expected the real IdP login to be linked, got Logins={described['Logins']!r}"
    )

    # negative: try to unlink the linked provider while supplying a bogus/unverifiable
    # token for it in Logins -- UnlinkIdentity must validate the token before honoring
    # the removal, not treat the request as a harmless no-op
    code, message = _error(
        lambda: identity.unlink_identity(
            IdentityId=identity_id,
            Logins={provider_name: "not-a-valid-jwt-token"},
            LoginsToRemove=[provider_name],
        )
    )
    assert code == "NotAuthorizedException", f"CODE={code}"
    assert message == "Invalid login token. Not a valid OpenId Connect identity token.", (
        f"MESSAGE={message!r}"
    )

    described_after = identity.describe_identity(IdentityId=identity_id)
    assert described_after["Logins"] == [provider_name], (
        "the rejected unlink must not touch existing logins"
    )

    # positive control: removing the login that is actually linked succeeds, and the
    # removal actually takes effect -- an independent read at the destination, not the
    # mutating call's own response. Real Cognito does not empty Logins on unlink: it
    # replaces the provider name with the sentinel "DISABLED".
    identity.unlink_identity(
        IdentityId=identity_id, Logins=logins, LoginsToRemove=[provider_name]
    )
    described_final = identity.describe_identity(IdentityId=identity_id)
    assert described_final.get("Logins") == ["DISABLED"], (
        f"the valid-token unlink did not orphan the login as the sentinel "
        f"['DISABLED'], got Logins={described_final.get('Logins')!r}"
    )


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_confirmed_user_pool_user(ctx, cidp: Any) -> tuple[str, str, str, str]:
    pool_id = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-userpool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-userpool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))

    client_id = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2realuser")
    password = "TestPassw0rd1"
    cidp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    cidp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    return pool_id, client_id, username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
