"""get-listing-matches-search-summary-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-matches-search-summary-fields"
GROUP = "consistency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetListing on a listingId discovered via SearchListings returns identical core fields as the search summary."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=10)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listings visible to this account to cross-check against GetListing")
    summary = summaries[0]

    detail = client.get_listing(listingId=summary["listingId"])

    assert detail["listingId"] == summary["listingId"], (
        f"GetListing id {detail['listingId']!r} != SearchListings summary id {summary['listingId']!r}"
    )
    assert detail["listingName"] == summary["listingName"], (
        f"GetListing name {detail['listingName']!r} != summary name {summary['listingName']!r}"
    )
    assert detail["catalog"] == summary["catalog"], (
        f"GetListing catalog {detail['catalog']!r} != summary catalog {summary['catalog']!r}"
    )
    assert detail["shortDescription"] == summary["shortDescription"], (
        f"GetListing shortDescription {detail['shortDescription']!r} != "
        f"summary shortDescription {summary['shortDescription']!r}"
    )
    assert detail["publisher"]["sellerProfileId"] == summary["publisher"]["sellerProfileId"], (
        f"GetListing publisher.sellerProfileId {detail['publisher']['sellerProfileId']!r} != "
        f"summary publisher.sellerProfileId {summary['publisher']['sellerProfileId']!r}"
    )
    assert detail["publisher"]["displayName"] == summary["publisher"]["displayName"], (
        f"GetListing publisher.displayName {detail['publisher']['displayName']!r} != "
        f"summary publisher.displayName {summary['publisher']['displayName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
