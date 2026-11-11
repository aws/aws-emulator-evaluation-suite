"""search-listings-pagination-no-duplicate-across-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pagination-no-duplicate-across-pages"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Walking SearchListings one result at a time never repeats a listingId, and totalResults
    stays stable across every page."""
    md = ctx.client("marketplace-discovery")
    seen: set[str] = set()
    total = None
    token = None
    max_pages = 3
    for page_num in range(1, max_pages + 1):
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = md.search_listings(**kwargs)

        page_total = resp["totalResults"]
        if total is None:
            total = page_total
            assert total >= 2, "expected at least two listings in the public catalog"
        else:
            assert page_total == total, f"totalResults changed across pages: {total} -> {page_total}"

        page = resp["listingSummaries"]
        assert len(page) == 1, f"expected exactly one listing per page, got {len(page)}"
        listing_id = page[0]["listingId"]
        assert listing_id not in seen, f"listingId {listing_id!r} repeated across pages"
        seen.add(listing_id)

        token = resp.get("nextToken")
        if page_num == 1:
            assert token, "expected a nextToken to fetch a second page"
        if not token:
            break

    assert len(seen) >= 2, "expected at least two distinct listings across paginated calls"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
