"""get-models-listing-order-matches-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-models-listing-order-matches-creation"
GROUP = "ordering"
SERVICES = ["apigateway"]

_SCHEMA = (
    '{"$schema":"http://json-schema.org/draft-04/schema#",'
    '"title":"%s","type":"object","properties":{"x":{"type":"string"}}}'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModels listing order is stable across repeated calls and an unrelated update.

    Real AWS does not guarantee GetModels reflects creation order (see NOTE below);
    the invariant this check can actually hold a target to is order *stability*.
    """
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "get-models-listing-order-stable"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # Model names must be alphanumeric (no hyphens), so sanitize ctx.unique_name's output.
    names = ["".join(ch for ch in ctx.unique_name(f"SimModel{i}") if ch.isalnum()) for i in range(3)]
    for name in names:
        apigw.create_model(
            restApiId=api_id,
            name=name,
            contentType="application/json",
            schema=_SCHEMA % name,
        )

    # A freshly created RestApi already ships with built-in "Empty"/"Error" models,
    # so filter the listing down to only the ones this check created before comparing.
    # NOTE: GetModels does not guarantee creation order on real AWS (observed order can
    # differ from insertion order), so the real invariant to check is *stability*: the
    # relative order of our created models must not change between repeated calls or
    # after an unrelated update to one of them.
    def _our_listing() -> list[str]:
        full = [m["name"] for m in apigw.get_models(restApiId=api_id)["items"]]
        return [n for n in full if n in names]

    listing_1 = _our_listing()
    listing_2 = _our_listing()
    assert set(listing_1) == set(names), f"expected models {names}, got {listing_1}"
    assert listing_1 == listing_2, f"GetModels order not stable across repeated calls: {listing_1} vs {listing_2}"

    # Unrelated update to a model in the middle of the list must not reorder the listing.
    apigw.update_model(
        restApiId=api_id,
        modelName=names[1],
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated-description"}],
    )

    listing_after_update = _our_listing()
    assert listing_after_update == listing_1, (
        f"listing order changed after unrelated update: expected {listing_1}, got {listing_after_update}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
