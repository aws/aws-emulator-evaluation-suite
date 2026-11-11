"""search-listings-searchtext-finds-source-listing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-searchtext-finds-source-listing"
GROUP = "search-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Searching by a listing's own name narrows the result set and still surfaces that listing."""
    client = ctx.client("marketplace-discovery")
    base = client.search_listings(maxResults=1)
    assert base["listingSummaries"], "need at least one listing to derive search text"
    listing = base["listingSummaries"][0]
    all_total = base["totalResults"]

    garbage_text = ctx.unique_name("sim2real-behav-no-such-listing-")
    unmatched = client.search_listings(searchText=garbage_text, maxResults=10)
    assert unmatched["totalResults"] < all_total, (
        f"searchText={garbage_text!r} matches no real listing, so it must filter out at least "
        f"one of the {all_total} catalog entries rather than echoing the full catalog "
        f"(got totalResults={unmatched['totalResults']!r})"
    )

    search_text = listing["listingName"][:200]
    narrowed = client.search_listings(searchText=search_text, maxResults=100)
    assert narrowed["totalResults"] <= all_total, (
        "adding searchText must not increase the total matching-listing count"
    )

    ids = [s["listingId"] for s in narrowed["listingSummaries"]]
    token = narrowed.get("nextToken")
    pages = 1
    while listing["listingId"] not in ids and token and pages < 3:
        page = client.search_listings(searchText=search_text, maxResults=100, nextToken=token)
        ids.extend(s["listingId"] for s in page["listingSummaries"])
        token = page.get("nextToken")
        pages += 1

    assert listing["listingId"] in ids, (
        f"searching for {listing['listingId']}'s own name did not surface that listing "
        f"within {pages} page(s)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
