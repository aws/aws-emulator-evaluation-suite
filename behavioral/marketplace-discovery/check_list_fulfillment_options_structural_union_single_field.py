"""list-fulfillment-options-structural-union-single-field."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-fulfillment-options-structural-union-single-field"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_FULFILLMENT_MEMBERS = {
    "amazonMachineImageFulfillmentOption",
    "apiFulfillmentOption",
    "cloudFormationFulfillmentOption",
    "containerFulfillmentOption",
    "helmFulfillmentOption",
    "eksAddOnFulfillmentOption",
    "ec2ImageBuilderComponentFulfillmentOption",
    "dataExchangeFulfillmentOption",
    "professionalServicesFulfillmentOption",
    "saasFulfillmentOption",
    "sageMakerAlgorithmFulfillmentOption",
    "sageMakerModelFulfillmentOption",
}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFulfillmentOptions returns options where each element carries exactly one recognized option type."""
    md = ctx.client("marketplace-discovery")
    search = md.search_listings(maxResults=25)

    product_id = None
    for summary in search["listingSummaries"]:
        if not summary["fulfillmentOptionSummaries"]:
            continue
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product:
                product_id = product["productId"]
                break
        if product_id:
            break

    if product_id is None:
        raise AssertionError(
            "no sampled listing advertised a non-empty fulfillmentOptionSummaries to anchor the check on"
        )

    resp = md.list_fulfillment_options(productId=product_id, maxResults=50)
    options = resp["fulfillmentOptions"]
    assert options, f"expected fulfillment options for product {product_id} with advertised summaries"

    for option in options:
        set_members = [key for key in option if option.get(key) is not None]
        assert len(set_members) == 1, f"expected exactly one fulfillment option type set, got {set_members}"
        assert set_members[0] in _FULFILLMENT_MEMBERS, f"unrecognized fulfillment option type {set_members[0]}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
