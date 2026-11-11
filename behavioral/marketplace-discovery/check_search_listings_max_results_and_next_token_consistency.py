"""search-listings-max-results-and-next-token-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-max-results-and-next-token-consistency"
GROUP = "pagination"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """maxResults caps the page size, and nextToken is present iff more results remain."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=3)
    summaries = resp["listingSummaries"]
    total = resp["totalResults"]

    assert len(summaries) <= 3, f"maxResults=3 but got {len(summaries)} listingSummaries"
    if total > 3:
        assert len(summaries) == 3, "a full page of 3 was not returned even though more results remain"
        assert resp.get("nextToken"), "nextToken must be present when more results remain"
    else:
        assert len(summaries) == total, "page did not contain exactly totalResults items"
        assert not resp.get("nextToken"), "nextToken must be absent once all results have been returned"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
