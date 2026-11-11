"""search-listings-pagination-disjoint-ids."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-pagination-disjoint-ids"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging through SearchListings with nextToken never repeats a listingId across pages,
    and the catalog is large enough that at least two pages are actually fetched."""
    client = ctx.client("marketplace-discovery")
    seen: set[str] = set()
    token = None
    pages = 0
    max_pages = 5
    while pages < max_pages:
        kwargs = {"maxResults": 2}
        if token:
            kwargs["nextToken"] = token
        resp = client.search_listings(**kwargs)
        ids = [s["listingId"] for s in resp["listingSummaries"]]
        assert len(ids) <= 2, f"page returned {len(ids)} listings, exceeding maxResults=2"
        overlap = seen.intersection(ids)
        assert not overlap, f"listingIds repeated across pages: {overlap}"
        seen.update(ids)
        if pages == 0 and resp["totalResults"] > 2:
            assert resp.get("nextToken"), (
                "totalResults exceeds maxResults but no nextToken was returned"
            )
        token = resp.get("nextToken")
        pages += 1
        if not token:
            break
    assert pages >= 2, "expected pagination to span at least two pages to exercise cross-page disjointness"
    assert len(seen) >= 2, "expected at least two distinct listings across paginated calls"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
