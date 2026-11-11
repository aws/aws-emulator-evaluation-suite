"""search-text-max-results-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-text-max-results-enforced"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchText truncates its result list to the requested MaxResults."""
    geo = ctx.client("geo-places")
    resp = geo.search_text(
        QueryText="Starbucks",
        BiasPosition=[-122.3493, 47.6205],  # downtown Seattle
        MaxResults=3,
    )
    items = resp.get("ResultItems", [])
    assert len(items) == 3, f"expected exactly 3 results when MaxResults=3, got {len(items)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
