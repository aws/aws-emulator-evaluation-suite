"""get-id-logins-provider-token-mismatch-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-logins-provider-token-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetId with a forged token for a declared user-pool provider is rejected with
    NotAuthorizedException and mints no identity; unauthenticated GetId works before and after."""
    cip = ctx.client("cognito-identity")
    provider_name, client_id = _user_pool_provider(ctx)
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_id}],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    unauth_identity = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert unauth_identity.startswith(f"{ctx.region}:"), (
        f"expected an identity id prefixed with region {ctx.region!r}, got {unauth_identity!r}"
    )

    before_ids = {
        i["IdentityId"]
        for i in cip.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]
    }
    assert unauth_identity in before_ids, (
        f"expected {unauth_identity!r} in ListIdentities {before_ids!r}"
    )

    code, message = _refusal(
        lambda: cip.get_id(
            IdentityPoolId=pool_id,
            Logins={provider_name: "forged.not-a-real.user-pool-id-token"},
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a forged token against a declared "
        f"provider, got {code!r}: {message!r}"
    )
    assert message == "Invalid login token. Not a valid OpenId Connect identity token.", message

    after_ids = {
        i["IdentityId"]
        for i in cip.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]
    }
    assert after_ids == before_ids, (
        f"forged-token GetId must not mint an identity: before={before_ids!r} after={after_ids!r}"
    )

    another_unauth_identity = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert another_unauth_identity.startswith(f"{ctx.region}:"), (
        f"expected an identity id prefixed with region {ctx.region!r}, got {another_unauth_identity!r}"
    )



def _user_pool_provider(ctx):
    """Create a Cognito user pool and app client; return ``(provider_name, client_id)``.

    The provider name is built from CreateUserPool's answer, so no third-party IdP is contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    return f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}", client_id


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
