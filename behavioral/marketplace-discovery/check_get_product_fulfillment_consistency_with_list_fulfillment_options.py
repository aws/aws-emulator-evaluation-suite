"""get-product-fulfillment-consistency-with-list-fulfillment-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-product-fulfillment-consistency-with-list-fulfillment-options"
GROUP = "data-plane"
SERVICES = ["marketplace-discovery"]

_FULFILLMENT_UNION_TO_TYPE = {
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


def _fulfillment_type(item):
    for key, ftype in _FULFILLMENT_UNION_TO_TYPE.items():
        if item.get(key) is not None:
            return ftype
    raise AssertionError(f"fulfillment option item has no recognized union member set: {item!r}")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A product's GetProduct fulfillmentOptionSummaries types are exactly the types ListFulfillmentOptions returns for it."""
    md = ctx.client("marketplace-discovery")
    search = md.search_listings(maxResults=25)

    candidate_product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product and product["productId"] not in candidate_product_ids:
                candidate_product_ids.append(product["productId"])

    for product_id in candidate_product_ids[:10]:
        product = md.get_product(productId=product_id)
        expected_types = sorted(
            {fo["fulfillmentOptionType"] for fo in product["fulfillmentOptionSummaries"]}
        )
        if not expected_types:
            continue
        options = md.list_fulfillment_options(productId=product_id, maxResults=50)
        actual_types = sorted({_fulfillment_type(item) for item in options["fulfillmentOptions"]})
        assert actual_types == expected_types, (
            f"product {product_id} advertises fulfillmentOptionSummaries types {expected_types} "
            f"via GetProduct but ListFulfillmentOptions returned types {actual_types}"
        )
        return

    raise AssertionError(
        "none of the sampled products reported a non-empty fulfillmentOptionSummaries via GetProduct"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
