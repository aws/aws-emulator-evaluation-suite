"""get-models-lists-created."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-models-lists-created"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A model created via CreateModel is enumerable via GetModels with its contentType intact."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-models-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    apigw.create_model(
        restApiId=api_id,
        name="Widget",
        contentType="application/json",
        schema=json.dumps({"type": "object", "properties": {"name": {"type": "string"}}}),
    )

    items = apigw.get_models(restApiId=api_id)["items"]
    matches = [i for i in items if i["name"] == "Widget"]
    assert len(matches) == 1, f"expected exactly one model named Widget in {items}"
    assert matches[0]["contentType"] == "application/json", (
        f"expected contentType application/json, got {matches[0]['contentType']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
