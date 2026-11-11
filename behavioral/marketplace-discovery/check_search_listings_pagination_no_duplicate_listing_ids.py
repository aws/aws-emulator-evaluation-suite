"""search-listings-pagination-no-duplicate-listing-ids."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pagination-no-duplicate-listing-ids"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating SearchListings one result at a time never repeats a listingId across pages."""
    md = ctx.client("marketplace-discovery")
    seen: set[str] = set()
    token = None
    max_pages = 15
    pages_fetched = 0
    for _ in range(max_pages):
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = md.search_listings(**kwargs)
        pages_fetched += 1
        page = resp["listingSummaries"]
        assert len(page) <= 1, f"expected at most 1 listing per page with maxResults=1, got {len(page)}"
        for s in page:
            assert s["listingId"] not in seen, f"duplicate listingId {s['listingId']!r} across pages"
            seen.add(s["listingId"])
        token = resp.get("nextToken")
        if not token:
            break
    assert pages_fetched > 1, (
        f"expected to exercise multiple pages of the catalog, only fetched {pages_fetched}"
    )
    assert len(seen) >= 2, f"expected at least two distinct listings while paginating, got {len(seen)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
