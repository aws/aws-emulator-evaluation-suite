"""list-identities-dedup-across-pagination-with-deleted-identities."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identities-dedup-across-pagination-with-deleted-identities"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentities pagination stays disjoint and consistent even after an
    intervening DeleteIdentities call: deleted identity ids never reappear on a
    later listing, and every remaining identity is still listed exactly once."""
    cognito = ctx.client("cognito-identity")

    pool_id = _create_pool(ctx)
    identity_ids = [cognito.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(8)]

    remaining = set(identity_ids)

    def _cleanup_remaining() -> None:
        ids = list(remaining)
        if ids:
            cognito.delete_identities(IdentityIdsToDelete=ids)

    ctx.on_cleanup(_cleanup_remaining)

    before = _list_all_identities(cognito, pool_id)
    for identity_id in identity_ids:
        count = before.count(identity_id)
        assert count == 1, f"identity {identity_id} appeared {count} times before deletion (expected 1)"

    to_delete = identity_ids[:3]
    resp = cognito.delete_identities(IdentityIdsToDelete=to_delete)
    unprocessed = {u["IdentityId"] for u in resp.get("UnprocessedIdentityIds", [])}
    assert not unprocessed, f"identities failed to delete: {unprocessed}"
    remaining.difference_update(to_delete)

    after = _list_all_identities(cognito, pool_id)
    for identity_id in to_delete:
        assert identity_id not in after, f"deleted identity {identity_id} still appears in ListIdentities"
    for identity_id in identity_ids[3:]:
        count = after.count(identity_id)
        assert count == 1, f"identity {identity_id} appeared {count} times after deletion (expected 1)"


def _create_pool(ctx, allow_unauth: bool = True) -> str:
    cognito = ctx.client("cognito-identity")
    resp = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool"),
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _list_all_identities(cognito, pool_id: str) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    next_token = None
    pages = 0
    while True:
        kwargs: dict = {"IdentityPoolId": pool_id, "MaxResults": 3}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cognito.list_identities(**kwargs)
        page_ids = [i["IdentityId"] for i in resp.get("Identities", [])]

        overlap = seen_set.intersection(page_ids)
        assert not overlap, f"list_identities pagination re-listed id(s) from an earlier page: {overlap}"

        seen.extend(page_ids)
        seen_set.update(page_ids)
        pages += 1
        next_token = resp.get("NextToken")
        if not next_token:
            break
        assert pages < 1000, "pagination did not terminate within a sane number of pages"
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
