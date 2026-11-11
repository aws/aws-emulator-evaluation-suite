"""list-fulfillment-options-matches-product-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-fulfillment-options-matches-product-types"
GROUP = "cross-reference"
SERVICES = ["marketplace-discovery"]

_UNION_TO_TYPE = {
    "amazonMachineImageFulfillmentOption": "AMAZON_MACHINE_IMAGE",
    "apiFulfillmentOption": "API",
    "cloudFormationFulfillmentOption": "CLOUDFORMATION_TEMPLATE",
    "containerFulfillmentOption": "CONTAINER",
    "helmFulfillmentOption": "HELM",
    "eksAddOnFulfillmentOption": "EKS_ADD_ON",
    "ec2ImageBuilderComponentFulfillmentOption": "EC2_IMAGE_BUILDER_COMPONENT",
    "dataExchangeFulfillmentOption": "DATA_EXCHANGE",
    "professionalServicesFulfillmentOption": "PROFESSIONAL_SERVICES",
    "saasFulfillmentOption": "SAAS",
    "sageMakerAlgorithmFulfillmentOption": "SAGEMAKER_ALGORITHM",
    "sageMakerModelFulfillmentOption": "SAGEMAKER_MODEL",
}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The set of fulfillment option types returned by ListFulfillmentOptions matches the
    fulfillmentOptionSummaries reported for the same product by GetProduct."""
    md = ctx.client("marketplace-discovery")
    product_id = _first_product_id(md)
    if product_id is None:
        raise AssertionError(
            "no scanned listing summary exposed a product association within the scan window"
        )
    product = md.get_product(productId=product_id)
    summary_types = {fo["fulfillmentOptionType"] for fo in product["fulfillmentOptionSummaries"]}
    if not summary_types:
        raise AssertionError(
            f"product {product_id!r} exposes no fulfillment option summaries to compare against"
        )

    listed = md.list_fulfillment_options(productId=product_id, maxResults=50)
    listed_types = set()
    for opt in listed["fulfillmentOptions"]:
        matched = [v for k, v in _UNION_TO_TYPE.items() if opt.get(k) is not None]
        assert len(matched) == 1, f"expected exactly one populated fulfillment option variant, got {matched}"
        listed_types.add(matched[0])

    assert listed_types == summary_types, (
        f"ListFulfillmentOptions types {listed_types} did not match GetProduct's "
        f"fulfillmentOptionSummaries types {summary_types} for product {product_id!r}"
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
