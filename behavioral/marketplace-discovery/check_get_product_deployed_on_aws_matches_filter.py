"""get-product-deployed-on-aws-matches-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-product-deployed-on-aws-matches-filter"
GROUP = "product-state"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every product a single DEPLOYED_ON_AWS facet value surfaces reports the same deployedOnAws state
    through GetProduct: the facet value denotes one state, even though the facet's own value is an
    opaque token rather than the enum string."""
    client = ctx.client("marketplace-discovery")
    facets_resp = client.search_facets(facetTypes=["DEPLOYED_ON_AWS"])
    deployed_facets = facets_resp["listingFacets"].get("DEPLOYED_ON_AWS", [])
    if not deployed_facets:
        raise AssertionError("no DEPLOYED_ON_AWS facet values visible to this account")
    filter_value = deployed_facets[0]["value"]

    resp = client.search_listings(
        filters=[{"filterType": "DEPLOYED_ON_AWS", "filterValues": [filter_value]}],
        maxResults=25,
    )

    product_ids = []
    for summary in resp.get("listingSummaries", []):
        entities = summary.get("associatedEntities") or []
        if entities:
            product_ids.append(entities[0]["product"]["productId"])
    if not product_ids:
        raise AssertionError(
            f"no DEPLOYED_ON_AWS={filter_value!r} listing with an associated product is visible "
            "to this account"
        )

    observed_states = set()
    for product_id in product_ids[:5]:
        product = client.get_product(productId=product_id)
        assert product["deployedOnAws"] in ("DEPLOYED", "NOT_DEPLOYED", "NOT_APPLICABLE"), (
            f"product {product_id!r} reported deployedOnAws={product['deployedOnAws']!r}, "
            "outside the documented enum"
        )
        observed_states.add(product["deployedOnAws"])

    assert len(observed_states) == 1, (
        f"products surfaced by the same DEPLOYED_ON_AWS={filter_value!r} facet value reported "
        f"inconsistent deployedOnAws states: {observed_states}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
