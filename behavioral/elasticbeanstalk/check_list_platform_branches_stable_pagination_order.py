"""list-platform-branches-stable-pagination-order."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "list-platform-branches-stable-pagination-order"
GROUP = "ordering"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlatformBranches pagination is stable: repeating the first page returns the same branches, and two full
    NextToken walks return the same sequence with no duplicates."""
    eb = ctx.client("elasticbeanstalk")

    page_size = 5
    first_page = eb.list_platform_branches(MaxRecords=page_size)["PlatformBranchSummaryList"]
    if len(first_page) < page_size:
        # Too few platform branches in the region to paginate; a short list proves nothing.
        raise AssertionError(
            f"expected at least {page_size} platform branches to test pagination, got "
            f"{len(first_page)}; AWS publishes many public platform branches so this is "
            "unexpected on real AWS"
        )

    first_keys = [_branch_key(b) for b in first_page]

    # Re-issuing the identical first-page request must return the identical order.
    repeat_page = eb.list_platform_branches(MaxRecords=page_size)["PlatformBranchSummaryList"]
    repeat_keys = [_branch_key(b) for b in repeat_page]
    assert repeat_keys == first_keys, (
        f"repeating the identical first-page request changed the order: expected {first_keys}, "
        f"got {repeat_keys}"
    )

    def _walk_all(seed_first_keys: list[str]) -> list[str]:
        seen: list[str] = list(seed_first_keys)
        seen_set = set(seed_first_keys)
        token = eb.list_platform_branches(MaxRecords=page_size).get("NextToken")
        pages_walked = 0
        max_pages = 200  # safety cap; real AWS platform-branch counts are far below this
        while token:
            pages_walked += 1
            if pages_walked > max_pages:
                raise AssertionError("pagination never terminated (NextToken kept being returned)")
            resp = eb.list_platform_branches(MaxRecords=page_size, NextToken=token)
            page_keys = [_branch_key(b) for b in resp["PlatformBranchSummaryList"]]
            for key in page_keys:
                assert key not in seen_set, f"duplicate platform branch {key!r} returned across pages"
                seen_set.add(key)
            seen.extend(page_keys)
            token = resp.get("NextToken")
        return seen

    # Walk the full branch list via NextToken twice, independently, and require the exact
    # same sequence both times — the real stability guarantee (ordering is consistent across
    # repeated pagination), rather than comparing against a differently-sized unpaginated call
    # (which real AWS is not documented to keep byte-for-byte identical in order to a
    # small-page-size walk).
    walk_one = _walk_all(first_keys)
    walk_two = _walk_all([_branch_key(b) for b in eb.list_platform_branches(MaxRecords=page_size)["PlatformBranchSummaryList"]])
    assert walk_one == walk_two, (
        f"two independent full NextToken walks disagreed on order: {walk_one!r} != {walk_two!r}"
    )
    assert len(walk_one) == len(set(walk_one)), "duplicate platform branches within a single walk"


def _branch_key(branch: dict[str, Any]) -> str:
    return f"{branch['PlatformName']}|{branch['BranchName']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
