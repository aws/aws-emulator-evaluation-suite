"""get-product-deployed-on-aws-enum-membership."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-product-deployed-on-aws-enum-membership"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_DEPLOYED_ON_AWS_VALUES = {"DEPLOYED", "NOT_DEPLOYED", "NOT_APPLICABLE"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProduct's deployedOnAws is always a recognized enum value, and identity fields match the search origin."""
    md = ctx.client("marketplace-discovery")
    search = md.search_listings(maxResults=25)

    product_info = None
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product:
                product_info = product
                break
        if product_info:
            break
    assert product_info is not None, "expected at least one listing with an associated product"

    resp = md.get_product(productId=product_info["productId"])

    assert resp["productId"] == product_info["productId"], (
        f"expected productId {product_info['productId']!r}, got {resp['productId']!r}"
    )
    assert resp["productName"] == product_info["productName"], (
        f"expected productName {product_info['productName']!r}, got {resp['productName']!r}"
    )
    assert resp["manufacturer"]["sellerProfileId"] == product_info["manufacturer"]["sellerProfileId"], (
        f"expected sellerProfileId {product_info['manufacturer']['sellerProfileId']!r}, "
        f"got {resp['manufacturer']['sellerProfileId']!r}"
    )
    assert resp["manufacturer"]["displayName"] == product_info["manufacturer"]["displayName"], (
        f"expected manufacturer displayName {product_info['manufacturer']['displayName']!r}, "
        f"got {resp['manufacturer']['displayName']!r}"
    )
    assert resp["deployedOnAws"] in _DEPLOYED_ON_AWS_VALUES, (
        f"deployedOnAws {resp['deployedOnAws']!r} is not one of {_DEPLOYED_ON_AWS_VALUES}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
