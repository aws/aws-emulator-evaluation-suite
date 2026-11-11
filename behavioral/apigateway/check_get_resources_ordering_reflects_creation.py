"""get-resources-ordering-reflects-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resources-ordering-reflects-creation"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginated GetResources (limit=2) lists the root's children in a stable relative order.

    The order repeats across reads, and creating another sibling does not reshuffle it.
    """
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-restapi-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_items = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(i["id"] for i in root_items if i["path"] == "/")

    # Deliberately not alphabetical, so an emulator that re-sorts pathPart would diverge.
    path_parts = ["zulu", "alpha", "mike"]
    for part in path_parts:
        apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=part)

    def _list_children() -> tuple[list[str], list[str]]:
        """Paginated listing of root's children -> (order restricted to path_parts, full pathPart list)."""
        all_items: list[dict] = []
        position = None
        for _ in range(50):
            kwargs = {"restApiId": api_id, "limit": 2}
            if position:
                kwargs["position"] = position
            resp = apigw.get_resources(**kwargs)
            all_items.extend(resp.get("items", []))
            position = resp.get("position")
            if not position:
                break
        else:
            raise AssertionError("pagination did not terminate within 50 pages")
        children = [i for i in all_items if i.get("parentId") == root_id]
        restricted = [i["pathPart"] for i in children if i.get("pathPart") in path_parts]
        return restricted, [i["pathPart"] for i in children]

    # Freeze detector (no mutation between the two reads): a target that reshuffles on
    # every read must not pass merely by chance on a single observation.
    order_before, _ = _list_children()
    order_before_repeat, _ = _list_children()
    assert order_before == order_before_repeat, (
        f"GetResources order changed across two reads with no intervening mutation: "
        f"{order_before} -> {order_before_repeat}"
    )
    assert set(order_before) == set(path_parts), (
        f"expected all {len(path_parts)} created child resources listed, got {order_before}"
    )
    assert len(order_before) == len(path_parts), (
        f"duplicate or missing entries among created children: {order_before}"
    )

    # AWS does not document GetResources as sorted by creation time. What must hold: adding
    # a further, unrelated sibling resource must NOT reshuffle the relative order of the
    # pre-existing siblings (stable relative ordering under mutation), regardless of what
    # the underlying sort key actually is -- and the new sibling itself must become visible.
    apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="bravo")

    order_after, all_children_after = _list_children()
    assert order_after == order_before, (
        f"relative order of pre-existing sibling resources changed after adding an unrelated "
        f"sibling: {order_before} -> {order_after}"
    )
    assert "bravo" in all_children_after, (
        f"newly created sibling resource is missing from the listing: {all_children_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
