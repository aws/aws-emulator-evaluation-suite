"""documentation-part-nested-properties-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "documentation-part-nested-properties-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A documentation part's deeply nested JSON properties payload round-trips exactly."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    properties = {
        "description": "Ünïcödé docs: 説明テキスト",
        "tags": ["alpha", "bëta", "gámma"],
        "meta": {
            "level1": {
                "level2": {
                    "level3": [
                        "x",
                        "y",
                        {"deep": True, "count": 3, "note": "深い値"},
                    ]
                }
            }
        },
        "empty_list": [],
        "empty_obj": {},
    }
    properties_json = json.dumps(properties, ensure_ascii=False)

    created = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=properties_json,
    )
    part_id = created["id"]

    got = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    assert got["properties"] == properties_json, "nested properties payload was not preserved exactly"


def _create_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
