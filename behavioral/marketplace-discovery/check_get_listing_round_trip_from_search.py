"""get-listing-round-trip-from-search."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-round-trip-from-search"
GROUP = "discovery"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A listingId discovered via SearchListings resolves via GetListing to matching details."""
    client = ctx.client("marketplace-discovery")
    search_resp = client.search_listings(maxResults=1)
    summaries = search_resp["listingSummaries"]
    assert summaries, "expected at least one listing from SearchListings"
    summary = summaries[0]

    detail = client.get_listing(listingId=summary["listingId"])

    assert detail["listingId"] == summary["listingId"], (
        f"listingId mismatch: detail={detail['listingId']!r} summary={summary['listingId']!r}"
    )
    assert detail["listingName"] == summary["listingName"], (
        f"listingName mismatch: detail={detail['listingName']!r} summary={summary['listingName']!r}"
    )
    assert detail["catalog"] == summary["catalog"], (
        f"catalog mismatch: detail={detail['catalog']!r} summary={summary['catalog']!r}"
    )
    assert detail["shortDescription"] == summary["shortDescription"], (
        f"shortDescription mismatch: detail={detail['shortDescription']!r} "
        f"summary={summary['shortDescription']!r}"
    )
    assert detail["publisher"]["sellerProfileId"] == summary["publisher"]["sellerProfileId"], (
        f"sellerProfileId mismatch: detail={detail['publisher']['sellerProfileId']!r} "
        f"summary={summary['publisher']['sellerProfileId']!r}"
    )
    assert detail["publisher"]["displayName"] == summary["publisher"]["displayName"], (
        f"publisher displayName mismatch: detail={detail['publisher']['displayName']!r} "
        f"summary={summary['publisher']['displayName']!r}"
    )
    detail_category_ids = {c["categoryId"] for c in detail["categories"]}
    summary_category_ids = {c["categoryId"] for c in summary["categories"]}
    assert detail_category_ids == summary_category_ids, (
        f"category set mismatch: detail={sorted(detail_category_ids)} "
        f"summary={sorted(summary_category_ids)}"
    )
    assert detail["longDescription"], "expected a non-empty longDescription on GetListing detail"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
