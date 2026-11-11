"""search-listings-then-get-listing-field-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-then-get-listing-field-consistency"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A listing surfaced by SearchListings resolves via GetListing to the identical identity fields."""
    md = ctx.client("marketplace-discovery")
    search_resp = md.search_listings(maxResults=5)
    summaries = search_resp["listingSummaries"]
    assert summaries, "expected at least one listing summary from the public catalog"
    summary = summaries[0]

    listing = md.get_listing(listingId=summary["listingId"])

    assert listing["listingId"] == summary["listingId"], (
        f"GetListing id {listing['listingId']!r} != SearchListings id {summary['listingId']!r}"
    )
    assert listing["listingName"] == summary["listingName"], (
        f"GetListing name {listing['listingName']!r} != SearchListings name {summary['listingName']!r}"
    )
    assert listing["catalog"] == summary["catalog"], (
        f"GetListing catalog {listing['catalog']!r} != SearchListings catalog {summary['catalog']!r}"
    )
    assert listing["publisher"]["sellerProfileId"] == summary["publisher"]["sellerProfileId"], (
        f"GetListing sellerProfileId {listing['publisher']['sellerProfileId']!r} != "
        f"SearchListings sellerProfileId {summary['publisher']['sellerProfileId']!r}"
    )
    assert listing["publisher"]["displayName"] == summary["publisher"]["displayName"], (
        f"GetListing publisher displayName {listing['publisher']['displayName']!r} != "
        f"SearchListings publisher displayName {summary['publisher']['displayName']!r}"
    )
    listing_category_ids = {c["categoryId"] for c in listing["categories"]}
    summary_category_ids = {c["categoryId"] for c in summary["categories"]}
    assert listing_category_ids == summary_category_ids, (
        f"GetListing categories {listing_category_ids} != SearchListings categories {summary_category_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
