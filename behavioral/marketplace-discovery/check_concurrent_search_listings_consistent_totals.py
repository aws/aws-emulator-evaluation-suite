"""concurrent-search-listings-consistent-totals."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-search-listings-consistent-totals"
GROUP = "concurrency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Identical SearchListings calls fired concurrently all observe the same totalResults for the catalog."""
    md = ctx.client("marketplace-discovery")

    def _search(_):
        return md.search_listings(maxResults=5)["totalResults"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        totals = list(pool.map(_search, range(5)))

    assert len(set(totals)) == 1, f"expected identical totalResults across concurrent reads, got {totals}"
    assert totals[0] > 0, "totalResults was 0 for every concurrent read -- agreeing on an empty catalog proves nothing"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
