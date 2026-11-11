"""search-listings-returns-nonempty-catalog."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-returns-nonempty-catalog"
GROUP = "smoke"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings with no filters returns a non-empty, well-formed page of the public catalog."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=10)
    total = resp["totalResults"]
    summaries = resp["listingSummaries"]
    if total == 0 or not summaries:
        raise AssertionError(
            "no listings are visible to this account/region in the AWS Marketplace catalog"
        )
    assert total >= len(summaries), (
        f"totalResults {total} is smaller than the returned page of {len(summaries)} summaries"
    )
    first = summaries[0]
    for field in ("listingId", "listingName", "catalog", "publisher", "shortDescription", "logoThumbnailUrl"):
        assert first.get(field), f"missing/empty field {field!r} in listing summary"
    assert first["publisher"]["sellerProfileId"], "listing publisher is missing a sellerProfileId"
    assert first["publisher"]["displayName"], "listing publisher is missing a displayName"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
