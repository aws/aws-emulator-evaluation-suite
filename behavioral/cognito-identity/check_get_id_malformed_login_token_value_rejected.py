"""get-id-malformed-login-token-value-rejected."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-id-malformed-login-token-value-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected GetId to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically invalid (non-JWT) token for an otherwise-configured login provider
    is rejected as an authentication failure, distinct from an unconfigured-provider or
    unauthenticated-disallowed rejection."""
    idp = ctx.client("cognito-idp")
    cip = ctx.client("cognito-identity")

    user_pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-up-"))["UserPool"][
        "Id"
    ]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id, ClientName=ctx.unique_name("sim2real-behav-upc-")
    )["UserPoolClient"]["ClientId"]

    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_id}],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    def _bad_call():
        return cip.get_id(
            IdentityPoolId=pool_id,
            Logins={provider_name: "this-is-not-a-jwt-token-value"},
        )

    code, message = _refusal(_bad_call)
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == "Invalid login token. Not a valid OpenId Connect identity token.", message

    # effect absent: the malformed-login attempt created no identity in the pool
    before = cip.list_identities(IdentityPoolId=pool_id, MaxResults=60)
    assert before["Identities"] == [], "malformed login attempt must not create an identity"

    # positive control: the pool and GetId call itself work fine for a plain unauthenticated request
    identity_id = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]
    after = cip.list_identities(IdentityPoolId=pool_id, MaxResults=60)
    assert [i["IdentityId"] for i in after["Identities"]] == [identity_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
