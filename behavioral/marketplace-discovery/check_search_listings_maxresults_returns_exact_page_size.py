"""search-listings-maxresults-returns-exact-page-size."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-maxresults-returns-exact-page-size"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When more results exist than maxResults, SearchListings returns exactly maxResults items and a nextToken."""
    md = ctx.client("marketplace-discovery")
    resp = md.search_listings(maxResults=2)
    total = resp["totalResults"]
    assert total >= 3, "expected the public catalog to have more than a couple of listings"
    assert len(resp["listingSummaries"]) == 2, (
        f"expected exactly maxResults=2 items, got {len(resp['listingSummaries'])}"
    )
    assert resp.get("nextToken"), "expected a nextToken since more results remain beyond the page"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
