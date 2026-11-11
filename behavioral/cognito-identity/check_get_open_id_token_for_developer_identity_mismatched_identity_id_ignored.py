"""get-open-id-token-for-developer-identity-mismatched-identity-id-ignored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-mismatched-identity-id-ignored"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with a login already bound to one identity and another
    identity's IdentityId returns the bound identity, LookupDeveloperIdentity still resolves to it,
    and the other identity gains no developer login."""
    cip = ctx.client("cognito-identity")

    developer_provider = ctx.unique_name("sim2real.behav.dev.")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user_id = ctx.unique_name("sim2real-behav-devuser-")

    # register a developer identity for dev_user_id -> creates identity A
    identity_a = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: dev_user_id}
    )["IdentityId"]

    # a second, unrelated identity B, created via a plain unauthenticated GetId
    identity_b = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_b != identity_a, (
        f"expected the unauthenticated GetId identity {identity_b} to differ from "
        f"the developer-bound identity {identity_a}"
    )

    # The already-registered developer login with identity B's IdentityId raises no conflict:
    # Cognito ignores the requested IdentityId and returns the identity the login is bound to (A).
    result = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=identity_b,
        Logins={developer_provider: dev_user_id},
    )
    assert result["IdentityId"] == identity_a, (
        f"expected the canonical identity {identity_a} to be returned despite "
        f"requesting mismatched IdentityId {identity_b}, got {result['IdentityId']}"
    )

    # effect absent: dev_user_id is still linked to identity A, not identity B, and
    # identity B remains untouched by this developer login
    lookup = cip.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=1
    )
    assert lookup["IdentityId"] == identity_a, (
        f"expected {dev_user_id} to still map to {identity_a}, got {lookup['IdentityId']}"
    )

    # positive control: the correct pairing (IdentityId=A) succeeds and returns A unchanged
    result_a = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=identity_a,
        Logins={developer_provider: dev_user_id},
    )
    assert result_a["IdentityId"] == identity_a, (
        f"expected the correct pairing to still succeed and return {identity_a}, "
        f"got {result_a['IdentityId']}"
    )

    # terminal independent read at the destination: identity_b itself must remain
    # untouched by the mismatched request -- no developer login was ever attached to it.
    desc_b = cip.describe_identity(IdentityId=identity_b)
    assert developer_provider not in desc_b.get("Logins", []), (
        f"identity_b {identity_b} should have no developer-provider login, "
        f"got Logins={desc_b.get('Logins')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
