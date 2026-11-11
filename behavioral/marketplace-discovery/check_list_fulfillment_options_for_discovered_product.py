"""list-fulfillment-options-for-discovered-product."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-fulfillment-options-for-discovered-product"
GROUP = "resource-lookup"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFulfillmentOptions for a real product returns FulfillmentOption unions each carrying
    exactly one populated variant, and each variant's fulfillmentOptionType is a documented enum
    value."""
    client = ctx.client("marketplace-discovery")
    product_id = _discover_product_id(ctx)
    if product_id is None:
        raise AssertionError(
            "no product with advertised fulfillment options was discoverable via a real "
            "SearchListings scan within 5 pages of 100"
        )
    resp = client.list_fulfillment_options(productId=product_id)
    options = resp["fulfillmentOptions"]
    assert isinstance(options, list)
    assert options, f"expected at least one fulfillment option for product {product_id} with advertised summaries"
    for option in options:
        matched = [
            variant_type
            for key, variant_type in _UNION_TO_TYPE.items()
            if option.get(key) is not None
        ]
        assert len(matched) == 1, (
            f"expected exactly one populated FulfillmentOption union variant, got {matched}"
        )
        variant_data = next(v for k, v in option.items() if v is not None)
        assert variant_data["fulfillmentOptionType"] == matched[0], (
            f"variant's own fulfillmentOptionType {variant_data.get('fulfillmentOptionType')!r} "
            f"did not match its union tag {matched[0]!r}"
        )


def _discover_product_id(ctx, max_pages: int = 5):
    client = ctx.client("marketplace-discovery")
    token = None
    for _ in range(max_pages):
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = client.search_listings(**kwargs)
        for summary in resp.get("listingSummaries", []):
            if not summary.get("fulfillmentOptionSummaries"):
                continue
            for entity in summary.get("associatedEntities", []):
                product = entity.get("product")
                if product:
                    return product["productId"]
        token = resp.get("nextToken")
        if not token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
