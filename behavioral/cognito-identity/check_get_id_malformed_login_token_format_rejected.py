"""get-id-malformed-login-token-format-rejected."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-malformed-login-token-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetId with a Logins value that is not a JWT is refused with NotAuthorizedException "Invalid
    login token. Not a valid OpenId Connect identity token." and adds no identity, while an
    unauthenticated GetId on the pool issues one that ListIdentities shows."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    identity = ctx.client("cognito-identity")

    pool_id, client_id = _create_user_pool_client(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    ci_pool_id = identity.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-cipool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"owner": "fidelity-check"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=ci_pool_id))

    before = len(
        identity.list_identities(IdentityPoolId=ci_pool_id, MaxResults=60).get("Identities", [])
    )

    code, message = _refusal(
        lambda: identity.get_id(
            IdentityPoolId=ci_pool_id, Logins={provider_name: "not-a-jwt-token"}
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == "Invalid login token. Not a valid OpenId Connect identity token.", message

    after = len(
        identity.list_identities(IdentityPoolId=ci_pool_id, MaxResults=60).get("Identities", [])
    )
    assert after == before, "malformed-token GetId must not silently create an identity"

    # positive control: the same pool still issues an unauthenticated identity, and that
    # identity is independently visible via ListIdentities (not just the mutating call's
    # own response)
    resp = identity.get_id(IdentityPoolId=ci_pool_id)
    identity_id = resp["IdentityId"]
    assert identity_id, f"expected GetId to return an IdentityId, got {resp!r}"

    control_ids = [
        i["IdentityId"]
        for i in identity.list_identities(IdentityPoolId=ci_pool_id, MaxResults=60).get(
            "Identities", []
        )
    ]
    assert control_ids == [identity_id], (
        f"expected ListIdentities to show exactly the unauthenticated identity "
        f"{identity_id!r} and nothing minted by the rejected call, got {control_ids!r}"
    )


def _refusal(fn) -> tuple[str, str]:
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected GetId to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool_client(ctx, cidp: Any) -> tuple[str, str]:
    pool_id = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-userpool-"),
        UserPoolTags={"owner": "fidelity-check"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    client_id = cidp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
