"""search-listings-sort-by-rating-descending-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-sort-by-rating-descending-order"
GROUP = "search-relevance"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchListings sorted by AVERAGE_CUSTOMER_RATING DESCENDING returns rated listings in non-increasing rating order."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(sortBy="AVERAGE_CUSTOMER_RATING", sortOrder="DESCENDING", maxResults=100)

    ratings = []
    for summary in resp.get("listingSummaries", []):
        sources = summary.get("reviewSummary", {}).get("reviewSourceSummaries", [])
        parsed = []
        for source in sources:
            try:
                parsed.append(float(source["averageRating"]))
            except (KeyError, TypeError, ValueError):
                continue
        if parsed:
            ratings.append(max(parsed))

    if len(ratings) < 2:
        raise AssertionError(
            "fewer than 2 listings with a parseable average rating in the sampled page; cannot verify sort order"
        )

    for higher, lower in zip(ratings, ratings[1:]):
        assert higher >= lower - 1e-9, (
            f"AVERAGE_CUSTOMER_RATING DESCENDING order violated: rating {higher} appeared before {lower}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
