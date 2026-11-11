"""concurrent-get-listing-calls-consistent."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-get-listing-calls-consistent"
GROUP = "concurrency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Firing many concurrent GetListing calls for the same listingId always returns identical
    core data -- reads must be consistent under concurrent access, never mixed or corrupted."""
    md = ctx.client("marketplace-discovery")
    resp = md.search_listings(maxResults=1)
    summaries = resp["listingSummaries"]
    if not summaries:
        raise AssertionError("no listings are visible via SearchListings for this caller/catalog")
    listing_id = summaries[0]["listingId"]

    def _fetch(_i: int):
        detail = md.get_listing(listingId=listing_id)
        # categories are structured objects (not plain strings) -- compare their canonical JSON
        # representation, which sorts deterministically and doesn't require dict ordering.
        categories_key = tuple(
            sorted(json.dumps(c, sort_keys=True, default=str) for c in detail["categories"])
        )
        return detail["listingId"], detail["listingName"], detail["catalog"], detail["shortDescription"], categories_key

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_fetch, range(8)))

    assert len(results) == 8
    listing_ids = {r[0] for r in results}
    names = {r[1] for r in results}
    catalogs = {r[2] for r in results}
    descriptions = {r[3] for r in results}
    categories = {r[4] for r in results}
    assert listing_ids == {listing_id}
    assert len(names) == 1, f"expected one consistent listingName, got {names}"
    assert len(catalogs) == 1, f"expected one consistent catalog, got {catalogs}"
    assert len(descriptions) == 1, f"expected one consistent shortDescription, got {descriptions}"
    assert len(categories) == 1, f"expected one consistent categories set, got {categories}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
