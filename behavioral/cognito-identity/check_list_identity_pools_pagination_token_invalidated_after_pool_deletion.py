"""list-identity-pools-pagination-token-invalidated-after-pool-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-identity-pools-pagination-token-invalidated-after-pool-deletion"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A NextToken obtained from ListIdentityPools remains usable, and pagination continues to
    make forward progress, even after a pool that was already returned on an earlier page gets
    deleted mid-pagination."""
    cog = ctx.client("cognito-identity")

    pool_a_name = ctx.unique_name("sim2real_cid_pgA_")
    pool_b_name = ctx.unique_name("sim2real_cid_pgB_")
    pool_a = cog.create_identity_pool(
        IdentityPoolName=pool_a_name,
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_a)))
    pool_b = cog.create_identity_pool(
        IdentityPoolName=pool_b_name,
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_b)))

    # Which of the two lands on an earlier page than the other is unspecified by the API and
    # depends on how many other pools already exist in the account -- so find the boundary by
    # construction (see _find_page_boundary) rather than assuming pool_a gets there first or
    # that a page break exists between them at all.
    victim, survivor, token_after_victim = _find_page_boundary(cog, pool_a, pool_b)

    # `victim` has already been returned to us on an earlier page; deleting it now must not
    # break the NextToken captured for the page after it.
    cog.delete_identity_pool(IdentityPoolId=victim)

    resp_after = cog.list_identity_pools(MaxResults=60, NextToken=token_after_victim)
    ids_after = {p["IdentityPoolId"] for p in resp_after.get("IdentityPools", [])}
    assert victim not in ids_after, (
        f"deleted pool {victim} still appears in the page fetched with the pre-deletion "
        f"NextToken; got {ids_after!r}"
    )

    # keep paging (bounded) to confirm listing stays consistent and the sibling still surfaces
    seen_after: set[str] = set(ids_after)
    next_token = resp_after.get("NextToken")
    for _ in range(60):
        if survivor in seen_after or next_token is None:
            break
        resp_more = cog.list_identity_pools(MaxResults=60, NextToken=next_token)
        seen_after |= {p["IdentityPoolId"] for p in resp_more.get("IdentityPools", [])}
        next_token = resp_more.get("NextToken")

    assert survivor in seen_after, f"listing never surfaced the still-existing sibling pool {survivor}"
    assert victim not in seen_after, f"deleted pool {victim} resurfaced in a later page"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _find_page_boundary(cog, pool_a: str, pool_b: str) -> tuple[str, str, str]:
    """Locate a NextToken boundary that separates one of the two freshly-created pools (the
    victim, already returned on an earlier page) from the other (the survivor, not yet
    returned). Tries a cheap large-page scan first. If both pools land on the same terminal
    page -- the common case in a near-empty account, where everything fits in one
    MaxResults=60 page -- falls back to a MaxResults=1 rescan: with exactly one item per page,
    the first of the two encountered can never be on the terminal page, because the second one
    (known to still exist, since neither has been deleted yet) must surface on some later page.
    """
    for max_results, budget in ((60, 60), (1, 1500)):
        seen: set[str] = set()
        next_token = None
        for _ in range(budget):
            kwargs = {"MaxResults": max_results}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cog.list_identity_pools(**kwargs)
            for p in resp.get("IdentityPools", []):
                seen.add(p["IdentityPoolId"])
            next_token = resp.get("NextToken")
            found = seen & {pool_a, pool_b}
            if len(found) == 1 and next_token is not None:
                victim = found.pop()
                survivor = pool_b if victim == pool_a else pool_a
                return victim, survivor, next_token
            if pool_a in seen and pool_b in seen:
                break  # both bundled on/before a terminal page -- retry with a smaller page
            if next_token is None:
                break

    raise AssertionError(
        f"could not find a NextToken boundary separating {pool_a} from {pool_b} in "
        "ListIdentityPools, even with MaxResults=1; either one of them never appeared in the "
        "listing, or both keep landing on the same terminal page with nothing after them."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
