"""get-open-id-token-for-developer-identity-duplicate-registration-conflict."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-duplicate-registration-conflict"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"owner": "fidelity-check"},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Supplying an explicit IdentityId together with a developer Logins entry already linked to a
    DIFFERENT identity MUST be rejected (NotAuthorizedException), not silently re-linked, and the
    original mapping must be untouched."""
    ev = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("dev-provider-")
    pool_id = _create_pool(ev, ctx, allow_unauth=False, DeveloperProviderName=dev_provider)

    user_a = ctx.unique_name("user-a-")
    user_b = ctx.unique_name("user-b-")

    identity_a = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )
    identity_b = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )

    # Try to register user_a's login onto identity_b's IdentityId explicitly.
    code, message = _refusal(
        lambda: ev.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            IdentityId=identity_b["IdentityId"],
            Logins={dev_provider: user_a},
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected re-linking an already-registered developer user to a different identity "
        f"to be rejected with NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == (
        "Logins don't match. Please include at least one valid login for this identity or "
        "identity pool."
    ), message

    # And the original mapping must be untouched.
    still = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_a, MaxResults=10
    )
    assert still["IdentityId"] == identity_a["IdentityId"], (
        f"expected {user_a} to still map to {identity_a['IdentityId']}, got {still['IdentityId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
