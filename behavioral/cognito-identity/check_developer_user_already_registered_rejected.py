"""developer-user-already-registered-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "developer-user-already-registered-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-registering a developer user under an explicit, DIFFERENT IdentityId must be rejected, not silently re-linked."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user = ctx.unique_name("user-")
    first_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[first_identity]))

    other_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: ctx.unique_name("other-user-")}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[other_identity]))

    # Positive control: re-registering dev_user under its OWN identity succeeds, so a
    # failure below is specific to the cross-identity conflict, not a broken pool/provider.
    same = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, IdentityId=first_identity, Logins={dev_provider: dev_user}
    )
    assert same["IdentityId"] == first_identity, (
        f"expected re-registration under its own identity to succeed and return "
        f"{first_identity!r}, got {same['IdentityId']!r}"
    )

    # dev_user is already registered to first_identity; explicitly requesting it be
    # linked under other_identity instead must fail.
    err = _client_error(
        lambda: ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            IdentityId=other_identity,
            Logins={dev_provider: dev_user},
        )
    )
    # Real AWS rejects this as an authorization failure (the caller isn't authorized to
    # re-link a developer user that's already registered to a different identity), not with
    # DeveloperUserAlreadyRegisteredException as the docs might suggest.
    assert err == ("NotAuthorizedException", "Logins don't match. Please include at least one valid login for this identity or identity pool."), f"got {err!r}"

    # Effect absent: the rejected call must not have moved dev_user's mapping.
    lookup = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user, MaxResults=10
    )
    assert lookup["IdentityId"] == first_identity, (
        f"expected {dev_user!r} to still map to {first_identity!r} after the rejected "
        f"call, got {lookup['IdentityId']!r}"
    )


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the ClientError's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
