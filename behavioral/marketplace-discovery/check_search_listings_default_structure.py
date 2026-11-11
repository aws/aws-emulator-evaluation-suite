"""search-listings-default-structure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-default-structure"
GROUP = "discovery"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings with no filters returns a well-formed, non-empty public-catalog page."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings()
    total = resp["totalResults"]
    summaries = resp["listingSummaries"]
    assert isinstance(total, int) and total >= 0, f"expected non-negative int totalResults, got {total!r}"
    # The AWS Marketplace buyer catalog is a large public catalog visible to any caller.
    assert total > 0, "expected the public AWS Marketplace catalog to be non-empty"
    assert len(summaries) > 0, f"expected at least one listingSummary, got {len(summaries)}"
    assert len(summaries) <= 25, (
        f"expected <=25 summaries with maxResults omitted (documented default), got {len(summaries)}"
    )
    first = summaries[0]
    for key in (
        "listingId",
        "listingName",
        "catalog",
        "publisher",
        "categories",
        "pricingModels",
        "badges",
        "reviewSummary",
        "associatedEntities",
    ):
        assert key in first, f"missing expected field {key!r} in ListingSummary"
    assert first["listingId"] and isinstance(first["listingId"], str), (
        f"expected non-empty string listingId, got {first['listingId']!r}"
    )
    assert first["publisher"]["sellerProfileId"], "expected non-empty publisher.sellerProfileId"
    assert first["publisher"]["displayName"], "expected non-empty publisher.displayName"
    assert isinstance(first["reviewSummary"]["reviewSourceSummaries"], list), (
        f"expected reviewSummary.reviewSourceSummaries to be a list, got {type(first['reviewSummary']['reviewSourceSummaries'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
