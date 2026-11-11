"""search-listings-pagination-no-duplicate-ids."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pagination-no-duplicate-ids"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating SearchListings never repeats a listingId across consecutive pages."""
    client = ctx.client("marketplace-discovery")
    page1 = client.search_listings(maxResults=5)
    total = page1["totalResults"]
    if total <= 5:
        raise AssertionError(
            "catalog has <=5 total results visible to this account; cannot exercise multi-page pagination"
        )

    token = page1.get("nextToken")
    assert token, "expected nextToken when totalResults exceeds maxResults"

    ids1 = {s["listingId"] for s in page1["listingSummaries"]}
    page2 = client.search_listings(maxResults=5, nextToken=token)
    ids2 = [s["listingId"] for s in page2["listingSummaries"]]
    assert ids2, "second page returned no results"
    assert not (ids1 & set(ids2)), "pagination returned duplicate listingIds across consecutive pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
