"""search-listings-maxresults-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-maxresults-respected"
GROUP = "discovery"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings never returns more items than maxResults, and signals more pages via nextToken."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=3)
    summaries = resp["listingSummaries"]
    total = resp["totalResults"]
    assert len(summaries) <= 3, f"maxResults=3 but got {len(summaries)} listingSummaries"
    if total > 3:
        assert len(summaries) == 3, (
            f"totalResults={total} exceeds maxResults=3 but page had {len(summaries)} items, not a full page"
        )
        assert resp.get("nextToken"), (
            "totalResults exceeds maxResults but no nextToken was returned"
        )
    else:
        assert len(summaries) == total, (
            f"totalResults={total} but page had {len(summaries)} items"
        )
        assert not resp.get("nextToken"), (
            "nextToken must be absent once all results fit within maxResults"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
