"""documentation-part-properties-json-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "documentation-part-properties-json-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A documentation part's nested properties JSON blob is stored and returned unchanged."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-docpart-"),
        tags={"sim2real-check": CHECK},
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    properties_obj = {
        "description": "A widget resource",
        "nested": {
            "list": [1, 2, 3],
            "flag": True,
            "inner": {"key": "value", "count": 0},
        },
        "tags": ["alpha", "beta"],
    }
    properties_json = json.dumps(properties_obj)

    part = apigw.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties=properties_json,
    )
    part_id = part["id"]

    fetched = apigw.get_documentation_part(
        restApiId=rest_api_id, documentationPartId=part_id
    )
    returned_props = json.loads(fetched["properties"])

    assert returned_props == properties_obj, (
        f"documentation part properties changed: {returned_props!r} != {properties_obj!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
