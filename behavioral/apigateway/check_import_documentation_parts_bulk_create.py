"""import-documentation-parts-bulk-create."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-documentation-parts-bulk-create"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts bulk-creates multiple documentation parts visible via GetDocumentationParts."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-docimport-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    baseline = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert baseline == [], "fresh API should start with no documentation parts"

    # ImportDocumentationParts recognizes the "API Gateway extensions to OpenAPI" input format: a
    # full OpenAPI/Swagger document that carries the documentation parts under the
    # "x-amazon-apigateway-documentation" extension, with each part's "properties" given as a JSON
    # *object* (not a pre-serialized string). A bare {"documentationParts": [...]} object -- lacking
    # the swagger/openapi envelope -- is not a shape the importer recognizes, and real AWS rejects it
    # with "Unable to build importer with provided input."
    payload = {
        "swagger": "2.0",
        "info": {"title": ctx.unique_name("sim2real-docimport-"), "version": "1.0"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "documentationParts": [
                {"location": {"type": "API"}, "properties": {"description": "sim2real API doc"}},
                {
                    "location": {"type": "RESOURCE", "path": "/"},
                    "properties": {"description": "sim2real root doc"},
                },
            ]
        },
    }

    imported = apigw.import_documentation_parts(
        restApiId=api_id, mode="merge", failOnWarnings=True, body=json.dumps(payload).encode("utf-8")
    )
    assert len(imported["ids"]) == 2, imported
    assert imported.get("warnings", []) == [], imported["warnings"]

    listed = apigw.get_documentation_parts(restApiId=api_id)["items"]
    listed_ids = {p["id"] for p in listed}
    assert set(imported["ids"]) <= listed_ids, (imported["ids"], listed_ids)
    assert len(listed) == 2, listed

    descriptions = {json.loads(p["properties"])["description"] for p in listed}
    assert descriptions == {"sim2real API doc", "sim2real root doc"}, descriptions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
