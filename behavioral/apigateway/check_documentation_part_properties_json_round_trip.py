"""documentation-part-properties-json-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "documentation-part-properties-json-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A documentation part's properties JSON with nested structures/special chars round-trips exactly."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    properties_obj = {
        "description": 'Special "quotes", <tags> & 日本語 ☕ — em—dash',
        "nested": {
            "list": [1, 2, {"inner": "value\nwith\nnewlines\tand\ttabs"}],
            "unicode": "北京 – naïve café 🚀",
        },
        "empty": "",
        "boolFlag": True,
    }
    properties_json = json.dumps(properties_obj, ensure_ascii=False)

    created = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=properties_json,
    )
    part_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id))

    got = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    round_tripped = json.loads(got["properties"])
    assert round_tripped == properties_obj, round_tripped


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
