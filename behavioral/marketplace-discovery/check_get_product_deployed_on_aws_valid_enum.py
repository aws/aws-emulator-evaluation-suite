"""get-product-deployed-on-aws-valid-enum."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-product-deployed-on-aws-valid-enum"
GROUP = "state"
SERVICES = ["marketplace-discovery"]

_VALID_DEPLOYED_ON_AWS = {"DEPLOYED", "NOT_DEPLOYED", "NOT_APPLICABLE"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProduct's deployedOnAws attribute is always one of the documented enum states, and the
    productId in the response matches the one requested."""
    md = ctx.client("marketplace-discovery")
    product_id = _first_product_id(md)
    if product_id is None:
        raise AssertionError(
            "no scanned listing summary exposed a product association within the scan window"
        )
    product = md.get_product(productId=product_id)
    assert product["productId"] == product_id, (
        f"expected productId={product_id!r}, GetProduct returned {product['productId']!r}"
    )
    assert product["deployedOnAws"] in _VALID_DEPLOYED_ON_AWS, (
        f"deployedOnAws={product['deployedOnAws']!r} is not one of {sorted(_VALID_DEPLOYED_ON_AWS)}"
    )


def _first_product_id(md, max_scan: int = 20):
    resp = md.search_listings(maxResults=max_scan)
    for summary in resp["listingSummaries"]:
        for entity in summary["associatedEntities"]:
            product = entity.get("product")
            if product:
                return product["productId"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
