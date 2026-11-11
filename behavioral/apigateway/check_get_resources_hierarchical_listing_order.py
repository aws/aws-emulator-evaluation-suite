"""get-resources-hierarchical-listing-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resources-hierarchical-listing-order"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources returns the same order on repeated calls for an unchanged nested tree.

    Each listing holds exactly the created resources, each with its exact path and parentId.
    """
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    # Build a nested tree in a fixed, known creation order:
    #   /a
    #   /a/b
    #   /a/b/c
    #   /d          (sibling of /a, created last)
    a_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="a")["id"]
    ab_id = apigw.create_resource(restApiId=api_id, parentId=a_id, pathPart="b")["id"]
    abc_id = apigw.create_resource(restApiId=api_id, parentId=ab_id, pathPart="c")["id"]
    d_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="d")["id"]

    expected_ids = {root_id, a_id, ab_id, abc_id, d_id}

    def _list_order():
        items = apigw.get_resources(restApiId=api_id, limit=500)["items"]
        ids = [it["id"] for it in items]
        paths = {it["id"]: it.get("path") for it in items}
        parent_ids = {it["id"]: it.get("parentId") for it in items}
        return ids, paths, parent_ids

    order1, paths1, parents1 = _list_order()
    order2, paths2, parents2 = _list_order()
    order3, _, _ = _list_order()

    assert order1 == order2 == order3, (
        f"GetResources returned a different order across repeated calls: "
        f"{order1} vs {order2} vs {order3}"
    )
    assert set(order1) == expected_ids, (
        f"GetResources listing does not match the created resource set exactly: "
        f"expected {expected_ids}, got {set(order1)}"
    )

    # Real AWS does not guarantee parent-before-child adjacency in GetResources (the
    # collection is not necessarily returned in hierarchical or creation order), but
    # a faithful implementation MUST: (a) return every resource's "path" and
    # "parentId" fields correctly and consistently, and (b) return the exact same
    # total order on every call for an unchanged resource tree (no reshuffling
    # between list calls, which would break client-side pagination assumptions).
    assert paths1 == paths2, (
        f"GetResources returned different path data across repeated calls: "
        f"{paths1} vs {paths2}"
    )
    assert parents1 == parents2, (
        f"GetResources returned different parentId data across repeated calls: "
        f"{parents1} vs {parents2}"
    )
    expected_paths = {
        root_id: "/",
        a_id: "/a",
        ab_id: "/a/b",
        abc_id: "/a/b/c",
        d_id: "/d",
    }
    expected_parents = {
        root_id: None,
        a_id: root_id,
        ab_id: a_id,
        abc_id: ab_id,
        d_id: root_id,
    }
    for rid, expected_path in expected_paths.items():
        assert paths1.get(rid) == expected_path, (
            f"resource {rid} has path {paths1.get(rid)!r}, expected {expected_path!r}"
        )
    for rid, expected_parent in expected_parents.items():
        assert parents1.get(rid) == expected_parent, (
            f"resource {rid} has parentId {parents1.get(rid)!r}, expected {expected_parent!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
