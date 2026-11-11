"""search-listings-nonexistent-category-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-nonexistent-category-returns-empty"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CATEGORY filter value that matches nothing yields zero results, not an error -- proven
    against a positive control showing the same CATEGORY filter mechanism returns real matches for
    a category that does exist, so a target that always answers empty cannot pass by accident."""
    md = ctx.client("marketplace-discovery")

    facets = md.search_facets(facetTypes=["CATEGORY"])
    category_facets = facets["listingFacets"].get("CATEGORY", [])
    real_category = next((f["value"] for f in category_facets if f["count"] > 0), None)
    assert real_category is not None, "catalog exposed no CATEGORY facet value with a positive count"

    positive = md.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [real_category]}],
        maxResults=10,
    )
    assert positive["totalResults"] > 0, (
        f"positive control: filtering by real category {real_category!r} returned "
        f"totalResults={positive['totalResults']}, expected > 0"
    )

    bogus_category = ctx.unique_name("sim2real-behav-nonexistent-category-")
    resp = md.search_listings(
        filters=[{"filterType": "CATEGORY", "filterValues": [bogus_category]}],
        maxResults=10,
    )

    assert resp["totalResults"] == 0, (
        f"expected totalResults=0 for bogus category {bogus_category!r}, got {resp['totalResults']}"
    )
    assert resp["listingSummaries"] == [], (
        f"expected no listing summaries for bogus category, got {resp['listingSummaries']}"
    )
    assert "nextToken" not in resp or not resp["nextToken"], (
        f"expected no nextToken on an empty page, got {resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
