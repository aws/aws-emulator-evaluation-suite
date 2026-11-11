"""autocomplete-results-relevant-to-prefix."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "autocomplete-results-relevant-to-prefix"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Autocomplete on a partial street address, biased near it, surfaces that address.

    Autocomplete only ever returns addresses/address-components (never POIs like
    landmarks), so this exercises a real street-address prefix.
    """
    geo = ctx.client("geo-places")
    resp = geo.autocomplete(
        QueryText="400 Broad St",
        BiasPosition=[-122.3493, 47.6205],  # downtown Seattle (400 Broad St is here)
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Autocomplete suggestions for a partial street address"
    titles = [i["Title"] for i in items]
    assert any("400 broad st" in t.lower() for t in titles), (
        f"expected '400 Broad St' among autocomplete suggestions, got {titles}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
