"""get-models-ordering-reflects-creation."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-models-ordering-reflects-creation"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginated GetModels (limit=2) lists every created model in a stable relative order.

    Creating another model does not reshuffle the relative order of the pre-existing ones.
    """
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-restapi-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # Model names must be alphanumeric; deliberately not alphabetical as created.
    unique = ctx.unique_name("m").replace("-", "")
    model_names = [f"Zeta{unique}", f"Alpha{unique}", f"Mike{unique}"]
    for name in model_names:
        schema = json.dumps(
            {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "title": name,
                "type": "object",
                "properties": {"id": {"type": "string"}},
            }
        )
        apigw.create_model(restApiId=api_id, name=name, contentType="application/json", schema=schema)

    all_items: list[dict] = []
    position = None
    for _ in range(50):
        kwargs = {"restApiId": api_id, "limit": 2}
        if position:
            kwargs["position"] = position
        resp = apigw.get_models(**kwargs)
        all_items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
    else:
        raise AssertionError("pagination did not terminate within 50 pages")

    order_before = [i["name"] for i in all_items if i["name"] in model_names]
    assert set(order_before) == set(model_names), (
        f"expected all {len(model_names)} created models listed, got {order_before}"
    )

    # AWS does not document GetModels as sorted by creation time (it may sort some other
    # deterministic way). What must hold: inserting a new, unrelated model must NOT
    # reshuffle the relative order of the pre-existing models (stable relative ordering
    # under mutation), and a second listing must reproduce that same order.
    extra_name = f"Bravo{unique}"
    schema_extra = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": extra_name,
            "type": "object",
            "properties": {"id": {"type": "string"}},
        }
    )
    apigw.create_model(restApiId=api_id, name=extra_name, contentType="application/json", schema=schema_extra)

    all_items_2: list[dict] = []
    position = None
    for _ in range(50):
        kwargs = {"restApiId": api_id, "limit": 2}
        if position:
            kwargs["position"] = position
        resp = apigw.get_models(**kwargs)
        all_items_2.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
    else:
        raise AssertionError("pagination did not terminate within 50 pages")

    order_after = [i["name"] for i in all_items_2 if i["name"] in model_names]
    assert order_after == order_before, (
        f"relative order of pre-existing models changed after adding an unrelated model: "
        f"{order_before} -> {order_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
