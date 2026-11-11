"""search-listings-finds-listing-by-exact-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-finds-listing-by-exact-name"
GROUP = "search-relevance"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Searching by a listing's exact listingName surfaces that same listing among the results."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=10)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listings visible to this account to search for by name")
    target = summaries[0]
    unfiltered_total = resp["totalResults"]

    name_search = client.search_listings(searchText=target["listingName"], maxResults=25)
    found_ids = {s["listingId"] for s in name_search.get("listingSummaries", [])}

    assert target["listingId"] in found_ids, (
        f"searching for the exact listingName {target['listingName']!r} did not surface "
        f"listing {target['listingId']} among the first 25 results"
    )
    assert name_search["totalResults"] < unfiltered_total, (
        f"searching by the exact listingName {target['listingName']!r} returned "
        f"{name_search['totalResults']} totalResults, no fewer than the "
        f"{unfiltered_total} unfiltered catalog total — searchText does not look like it "
        "narrowed the catalog at all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
