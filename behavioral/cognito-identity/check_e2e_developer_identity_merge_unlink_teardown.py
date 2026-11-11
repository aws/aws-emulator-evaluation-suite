"""e2e-developer-identity-merge-unlink-teardown."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-developer-identity-merge-unlink-teardown"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Merge two developer identities, unlink one login, then delete the pool and confirm teardown."""
    cog = ctx.client("cognito-identity")

    dev_provider = ctx.unique_name("sim2real-devprov-")
    pool = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-devmerge-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    pool_deleted = False

    def _cleanup_pool():
        if not pool_deleted:
            cog.delete_identity_pool(IdentityPoolId=pool_id)

    ctx.on_cleanup(_cleanup_pool)

    user_a = ctx.unique_name("sim2real-usera-")
    user_b = ctx.unique_name("sim2real-userb-")

    identity_a = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_a}
    )["IdentityId"]
    identity_b = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_b}
    )["IdentityId"]
    assert identity_a != identity_b, "distinct developer users must get distinct identities"

    # Merge: source (userB) is folded into destination (userA). Real AWS is free to keep
    # either the source or destination IdentityId as the survivor (implementation detail),
    # so read back which one actually won rather than assuming a fixed direction.
    merge_result = cog.merge_developer_identities(
        SourceUserIdentifier=user_b,
        DestinationUserIdentifier=user_a,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    survivor_identity = merge_result["IdentityId"]
    assert survivor_identity in (identity_a, identity_b), (
        f"merge survivor {survivor_identity!r} must be one of the two pre-merge identities "
        f"({identity_a!r}, {identity_b!r})"
    )

    # Both login mappings now resolve to the same survivor identity end-to-end.
    lookup_a = cog.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_a, MaxResults=1
    )
    lookup_b = cog.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_b, MaxResults=1
    )
    assert lookup_a["IdentityId"] == survivor_identity, (
        f"user_a should resolve to survivor {survivor_identity!r}, got {lookup_a['IdentityId']!r}"
    )
    assert lookup_b["IdentityId"] == survivor_identity, (
        f"user_b should resolve to survivor {survivor_identity!r}, got {lookup_b['IdentityId']!r}"
    )

    # Unlink userA's login mapping from the merged (survivor) identity.
    cog.unlink_developer_identity(
        IdentityId=survivor_identity,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=user_a,
    )

    # Per the UnlinkDeveloperIdentity contract, an unlinked developer user is treated as a brand-new
    # identity the next time it authenticates — re-registering userA now must mint a *different*
    # IdentityId rather than resolving back to the (former) survivor. This propagates asynchronously
    # on real AWS, so poll instead of asserting on the first read.
    identity_a_after_unlink = _poll_until(
        lambda: cog.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={dev_provider: user_a}
        )["IdentityId"],
        lambda iid: iid != survivor_identity,
        timeout_s=30,
        interval_s=2.0,
        description="userA minted as a new identity after unlink",
    )
    assert identity_a_after_unlink != survivor_identity, (
        f"re-registering unlinked user_a should mint a new identity, still got survivor "
        f"{survivor_identity!r}"
    )

    # ... while userB's mapping (untouched by the unlink) still resolves to the survivor.
    lookup_b_after = cog.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_b, MaxResults=1
    )
    assert lookup_b_after["IdentityId"] == survivor_identity, (
        f"user_b's untouched mapping should still resolve to survivor {survivor_identity!r}, "
        f"got {lookup_b_after['IdentityId']!r}"
    )

    # Teardown: deleting the pool removes it end-to-end (DescribeIdentityPool 404s afterward).
    cog.delete_identity_pool(IdentityPoolId=pool_id)
    pool_deleted = True

    err_after_delete = _client_error(lambda: cog.describe_identity_pool(IdentityPoolId=pool_id))
    assert err_after_delete == ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found."), (
        f"expected DescribeIdentityPool on the deleted pool to 404, got {err_after_delete!r}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
