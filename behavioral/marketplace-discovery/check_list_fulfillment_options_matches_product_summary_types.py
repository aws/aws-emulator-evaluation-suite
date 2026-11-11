"""list-fulfillment-options-matches-product-summary-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-fulfillment-options-matches-product-summary-types"
GROUP = "fulfillment"
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
    """ListFulfillmentOptions for a product returns exactly the types listed in GetProduct's fulfillmentOptionSummaries."""
    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=25)

    candidate_ids: list[str] = []
    for summary in resp.get("listingSummaries", []):
        entities = summary.get("associatedEntities") or []
        if entities:
            candidate_ids.append(entities[0]["product"]["productId"])
    if not candidate_ids:
        raise AssertionError("no listing in the sampled page has an associated product")

    product_id = None
    expected_types: list[str] = []
    for candidate_id in candidate_ids:
        candidate = client.get_product(productId=candidate_id)
        candidate_types = sorted(f["fulfillmentOptionType"] for f in candidate["fulfillmentOptionSummaries"])
        if candidate_types:
            product_id = candidate_id
            expected_types = candidate_types
            break
    if product_id is None:
        raise AssertionError(
            f"none of the {len(candidate_ids)} sampled products has a non-empty "
            "fulfillmentOptionSummaries to cross-check"
        )

    actual_types_set: set[str] = set()
    next_token = None
    while True:
        kwargs = {"productId": product_id, "maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        detailed = client.list_fulfillment_options(**kwargs)
        actual_types_set.update(_fulfillment_type(item) for item in detailed["fulfillmentOptions"])
        next_token = detailed.get("nextToken")
        if not next_token:
            break
    actual_types = sorted(actual_types_set)

    # GetProduct's fulfillmentOptionSummaries are deduped by type, while ListFulfillmentOptions
    # can return multiple concrete options of the same type (e.g. two AMIs) -- compare the set of
    # distinct types each side surfaces, not raw counts.
    assert actual_types == expected_types, (
        f"ListFulfillmentOptions types {actual_types} did not match GetProduct's "
        f"fulfillmentOptionSummaries types {expected_types} for product {product_id}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
