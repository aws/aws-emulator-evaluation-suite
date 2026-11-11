"""import-rest-api-creates-full-api."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-rest-api-creates-full-api"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi builds resources/methods from an OpenAPI document in one call."""
    apigw = ctx.client("apigateway")
    title = ctx.unique_name("sim2real-import-api-")
    doc = {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": {
            "/pets": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }

    created = apigw.import_rest_api(body=json.dumps(doc).encode("utf-8"))
    api_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    assert created["name"] == title, f"expected ImportRestApi's own response to carry the doc title, got {created!r}"

    got = apigw.get_rest_api(restApiId=api_id)
    assert got["name"] == title, f"expected GetRestApi (an independent read) to carry the doc title, got {got!r}"

    resources = apigw.get_resources(restApiId=api_id)["items"]
    paths = {r["path"] for r in resources}
    assert "/pets" in paths, paths
    assert "/" in paths, paths

    pets_resource = next(r for r in resources if r["path"] == "/pets")
    methods = pets_resource.get("resourceMethods", {})
    assert "GET" in methods, pets_resource
    assert "POST" not in methods, (
        f"the imported spec defines only GET on /pets; ImportRestApi must not fabricate a "
        f"method the doc never declared, got resourceMethods={methods!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
