"""get-listing-concurrent-reads-consistent."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "get-listing-concurrent-reads-consistent"
GROUP = "concurrency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent GetListing reads for the same listingId all observe an identical payload (no torn/partial reads)."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=1)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listing visible to this account to exercise concurrent GetListing reads")
    listing_id = summaries[0]["listingId"]

    def _fetch(_):
        detail = client.get_listing(listingId=listing_id)
        # categories are structured objects (not plain strings) -- compare their canonical JSON
        # representation, which sorts deterministically and doesn't require dict ordering.
        categories_key = tuple(
            sorted(json.dumps(c, sort_keys=True, default=str) for c in detail["categories"])
        )
        return (
            detail["listingName"],
            detail["catalog"],
            detail["shortDescription"],
            categories_key,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_fetch, range(8)))

    assert len(set(results)) == 1, (
        f"concurrent GetListing reads for listing {listing_id} returned inconsistent payloads: {set(results)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
