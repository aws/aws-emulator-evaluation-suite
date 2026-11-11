"""get-open-id-token-for-developer-identity-missing-identity-and-provider-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-missing-identity-and-provider-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with neither IdentityId nor Logins is refused with
    InvalidParameterException "Please specify at least one login provider" and mints no identity,
    while a call with a developer login creates exactly one."""
    identity = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-provider-")

    pool_id = identity.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-pool-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=pool_id))

    before = len(
        identity.list_identities(IdentityPoolId=pool_id, MaxResults=60).get("Identities", [])
    )

    code, message = _refusal(
        lambda: identity.get_open_id_token_for_developer_identity(IdentityPoolId=pool_id, Logins={})
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code!r}: {message!r}"
    )
    assert message == "Please specify at least one login provider", message

    after = len(
        identity.list_identities(IdentityPoolId=pool_id, MaxResults=60).get("Identities", [])
    )
    assert after == before, "rejected request must not create an identity"

    # positive control: a real developer-user Logins entry succeeds
    dev_user = ctx.unique_name("sim2real-devuser-")
    resp = identity.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )
    assert resp["IdentityId"] and resp["Token"], (
        f"expected a minted identity and token, got {resp!r}"
    )

    after_positive = len(
        identity.list_identities(IdentityPoolId=pool_id, MaxResults=60).get("Identities", [])
    )
    assert after_positive == before + 1, (
        f"expected exactly one new identity after the real Logins entry, "
        f"before={before} after_positive={after_positive}"
    )


def _refusal(fn) -> tuple[str, str]:
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
