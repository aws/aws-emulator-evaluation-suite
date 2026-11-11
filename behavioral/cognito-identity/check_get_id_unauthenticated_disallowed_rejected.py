"""get-id-unauthenticated-disallowed-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-id-unauthenticated-disallowed-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Anonymous GetId on a pool that disallows unauthenticated identities is refused with
    NotAuthorizedException and leaves the identity list unchanged, while a developer login on the
    pool still gets an identity; enabling the flag makes the identical call succeed."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    developer_provider = ctx.unique_name("sim2real-behav-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    ids_before = _identity_ids(ci, pool_id)

    _rejects(
        lambda: ci.get_id(IdentityPoolId=pool_id),
        "NotAuthorizedException",
        "anonymous GetId on a pool with unauthenticated identities disallowed",
    )

    ids_after_reject = _identity_ids(ci, pool_id)
    assert ids_after_reject == ids_before, (
        f"the rejected anonymous GetId must allocate nothing, but the pool gained "
        f"{sorted(ids_after_reject - ids_before)!r}"
    )

    # Positive control: an authenticated login on the SAME pool still works, so the rejection
    # above is specific to the anonymous path and not a pool- or account-wide outage.
    dev_user_id = ctx.unique_name("sim2real-behav-devuser-")
    dev_identity_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: dev_user_id}
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[dev_identity_id]))
    ids_after_login = _identity_ids(ci, pool_id)
    assert ids_after_login - ids_before == {dev_identity_id}, (
        f"the developer login must be the only new identity on the pool, got "
        f"{sorted(ids_after_login - ids_before)!r}"
    )

    # Restore leg: flip the flag and demand the identical anonymous call now succeeds.
    ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
    )
    restored_identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[restored_identity_id]))
    assert restored_identity_id not in ids_after_login, (
        f"GetId after enabling unauthenticated identities returned the pre-existing identity "
        f"{restored_identity_id!r} instead of allocating a new one"
    )

    # Terminal read at an independent operation: the newly-allocated identity must actually be
    # visible in the pool's listing, not just echoed back in GetId's own response.
    ids_after_restore = _identity_ids(ci, pool_id)
    assert restored_identity_id in ids_after_restore, (
        f"GetId reported {restored_identity_id!r} as allocated, but ListIdentities does not "
        f"show it: {sorted(ids_after_restore)!r}"
    )


def _identity_ids(ci: Any, pool_id: str) -> set[str]:
    """Every identity currently in the pool, paginated — the independent read the rejection is
    checked against."""
    ids: set[str] = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 50:
            return ids


def _rejects(fn: Any, expected_code: str, description: str) -> None:
    """Call fn(); an unexpected SUCCESS raises, and a mismatched refusal names both codes."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == expected_code, (
            f"expected {expected_code!r} for {description}, got {code!r}"
        )
        return
    raise AssertionError(f"{description} must be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
