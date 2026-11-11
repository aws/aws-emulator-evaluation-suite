"""search-listings-default-sortorder-matches-explicit-descending."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-default-sortorder-matches-explicit-descending"
GROUP = "search-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Omitting sortBy/sortOrder yields the same page as the documented defaults (RELEVANCE/DESCENDING),
    and sortOrder is actually honored (ASCENDING differs from DESCENDING) so this is not a false match
    against a target that ignores sort parameters entirely."""
    client = ctx.client("marketplace-discovery")
    default_resp = client.search_listings(maxResults=5)
    explicit_resp = client.search_listings(maxResults=5, sortBy="RELEVANCE", sortOrder="DESCENDING")
    ascending_resp = client.search_listings(maxResults=5, sortBy="RELEVANCE", sortOrder="ASCENDING")

    default_ids = [s["listingId"] for s in default_resp["listingSummaries"]]
    explicit_ids = [s["listingId"] for s in explicit_resp["listingSummaries"]]
    ascending_ids = [s["listingId"] for s in ascending_resp["listingSummaries"]]

    assert len(explicit_ids) >= 2, (
        "fewer than 2 listings returned; cannot verify sortOrder is honored on this catalog"
    )
    assert ascending_ids != explicit_ids, (
        "sortOrder=ASCENDING must yield a different page than sortOrder=DESCENDING for the same "
        f"sortBy=RELEVANCE query ({ascending_ids} == {explicit_ids}); the target may be ignoring "
        "sortOrder entirely"
    )
    assert default_ids == explicit_ids, (
        "default SearchListings ordering must match explicit sortBy=RELEVANCE/"
        f"sortOrder=DESCENDING (the documented defaults) ({default_ids} != {explicit_ids})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
