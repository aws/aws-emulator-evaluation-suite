"""get-product-matches-listing-associated-entity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-product-matches-listing-associated-entity"
GROUP = "consistency"
SERVICES = ["marketplace-discovery"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProduct on a productId referenced by a listing's associatedEntities matches that reference."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=25)

    target = None
    for summary in resp.get("listingSummaries", []):
        entities = summary.get("associatedEntities") or []
        if entities:
            target = entities[0]["product"]
            break
    if target is None:
        raise AssertionError(
            "no listing in the sampled page has an associated product to cross-check against GetProduct"
        )

    product = client.get_product(productId=target["productId"])

    assert product["productId"] == target["productId"], (
        f"GetProduct productId {product['productId']!r} does not match the productId "
        f"{target['productId']!r} referenced by the listing's associated entity"
    )
    assert product["productName"] == target["productName"], (
        f"GetProduct productName {product['productName']!r} does not match the productName "
        f"{target['productName']!r} the search summary reported for this product"
    )
    assert product["manufacturer"]["sellerProfileId"] == target["manufacturer"]["sellerProfileId"], (
        f"GetProduct manufacturer.sellerProfileId {product['manufacturer']['sellerProfileId']!r} does "
        f"not match {target['manufacturer']['sellerProfileId']!r} from the search summary"
    )
    assert product["manufacturer"]["displayName"] == target["manufacturer"]["displayName"], (
        f"GetProduct manufacturer.displayName {product['manufacturer']['displayName']!r} does not "
        f"match {target['manufacturer']['displayName']!r} from the search summary"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
