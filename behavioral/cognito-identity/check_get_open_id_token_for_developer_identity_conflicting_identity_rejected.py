"""get-open-id-token-for-developer-identity-conflicting-identity-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-conflicting-identity-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Requesting a dev identity token for a user already registered under a different IdentityId fails."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    user_a = ctx.unique_name("sim2real-user-a-")
    user_b = ctx.unique_name("sim2real-user-b-")

    identity_a = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )["IdentityId"]
    identity_b = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )["IdentityId"]
    assert identity_a != identity_b, (
        f"expected distinct identities for user_a and user_b, got {identity_a!r} for both"
    )

    # user_a is already registered to identity_a; requesting it explicitly under identity_b
    # (a different, already-existing identity) must be rejected as a conflicting registration.
    code, message = _refusal(
        lambda: ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            IdentityId=identity_b,
            Logins={dev_provider: user_a},
        )
    )
    # Real AWS treats the explicit IdentityId as an assertion that the caller is authenticating
    # as that identity; since user_a's login is not (and cannot be) associated with identity_b,
    # the request fails authorization rather than surfacing as a resource-conflict error.
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == (
        "Logins don't match. Please include at least one valid login for this identity or "
        "identity pool."
    ), message

    # Effect absent: the rejected call must not have re-linked user_a's login onto identity_b.
    still = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_a, MaxResults=10
    )
    assert still["IdentityId"] == identity_a, (
        f"expected {user_a} to still map to {identity_a}, got {still['IdentityId']!r}"
    )

    # Restore: the identical login, paired with its own (correct) identity, still succeeds.
    restored = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_a, Logins={dev_provider: user_a}
    )["IdentityId"]
    assert restored == identity_a, (
        f"expected the correctly-paired call to still succeed and return {identity_a}, "
        f"got {restored!r}"
    )


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
