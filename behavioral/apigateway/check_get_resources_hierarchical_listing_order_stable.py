"""get-resources-hierarchical-listing-order-stable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resources-hierarchical-listing-order-stable"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources returns the resource tree in a stable, deterministic order across calls."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    # pathPart values are deliberately non-alphabetical (zulu < mike < alpha alphabetically,
    # but created in the opposite order) so a target that lexically re-sorts resources by
    # path/pathPart cannot pass this check by accident.
    res_a = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="zulu")["id"]
    res_b = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="mike")["id"]
    res_c = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="alpha")["id"]
    res_d = apigw.create_resource(restApiId=api_id, parentId=res_a, pathPart="quebec")["id"]

    expected_ids = {root_id, res_a, res_b, res_c, res_d}

    def _list_all_ids() -> list[str]:
        ids: list[str] = []
        position = None
        while True:
            kwargs = {"limit": 2}
            if position:
                kwargs["position"] = position
            resp = apigw.get_resources(restApiId=api_id, **kwargs)
            ids.extend(item["id"] for item in resp.get("items", []))
            position = resp.get("position")
            if not position:
                break
        return ids

    listing_1 = _list_all_ids()
    listing_2 = _list_all_ids()

    # GetResources does not guarantee creation order or hierarchical (parent-before-child)
    # order on real AWS -- observed order can be neither. The real invariant to check is
    # *stability*: repeated calls with no intervening mutation return the exact same
    # sequence, and every created resource (plus root) appears exactly once.
    assert listing_1 == listing_2, f"GetResources order not stable across calls: {listing_1} vs {listing_2}"
    assert set(listing_1) == expected_ids, f"expected ids {expected_ids}, got {set(listing_1)}"
    assert len(listing_1) == len(expected_ids), f"duplicate/missing entries in listing: {listing_1}"

    # Creating one more resource must not reshuffle the relative order of the existing ones.
    res_e = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="india")["id"]
    listing_3 = _list_all_ids()
    existing_relative_order = [rid for rid in listing_3 if rid in expected_ids]
    assert existing_relative_order == listing_1, (
        f"relative order of pre-existing resources changed after creating a new one: "
        f"expected {listing_1}, got {existing_relative_order}"
    )
    assert res_e in listing_3, "newly created resource missing from listing"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
