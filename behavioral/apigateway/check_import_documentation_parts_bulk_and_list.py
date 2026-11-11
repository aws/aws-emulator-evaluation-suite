"""import-documentation-parts-bulk-and-list."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-documentation-parts-bulk-and-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts bulk-creates parts that subsequently appear via GetDocumentationParts."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-docimport-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # ImportDocumentationParts' importer only recognizes an OpenAPI/Swagger
    # document carrying the "x-amazon-apigateway-documentation" extension
    # (this is the same shape produced by exporting an API with
    # extensions="documentation"). A bare top-level JSON array of parts is
    # NOT one of the importer's supported input shapes and is rejected with
    # "Unable to build importer with provided input." on real AWS. Within
    # that extension, each part's "properties" is a nested JSON *object*
    # (not a JSON-encoded string) -- the string-encoding only happens on the
    # way *out* of GetDocumentationParts/CreateDocumentationPart, which is
    # why the assertions below re-parse "properties" from the list response.
    body = json.dumps({
        "swagger": "2.0",
        "info": {"title": "sim2real-apigw-docimport", "version": "1.0"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "documentationParts": [
                {
                    "location": {"type": "API"},
                    "properties": {"description": "bulk imported API doc"},
                },
                {
                    "location": {"type": "RESOURCE", "path": "/"},
                    "properties": {"description": "bulk imported resource doc"},
                },
            ],
        },
    }).encode()

    imported = apigw.import_documentation_parts(restApiId=api_id, body=body, mode="merge", failOnWarnings=True)
    imported_ids = set(imported["ids"])
    assert len(imported_ids) == 2, imported

    parts = apigw.get_documentation_parts(restApiId=api_id)["items"]
    listed_ids = {p["id"] for p in parts}
    assert imported_ids.issubset(listed_ids), (imported_ids, listed_ids)

    by_type = {p["location"]["type"]: p for p in parts if p["id"] in imported_ids}
    api_description = json.loads(by_type["API"]["properties"])["description"]
    assert api_description == "bulk imported API doc", (api_description, by_type["API"])
    resource_description = json.loads(by_type["RESOURCE"]["properties"])["description"]
    assert resource_description == "bulk imported resource doc", (resource_description, by_type["RESOURCE"])
    assert by_type["RESOURCE"]["location"]["path"] == "/", by_type["RESOURCE"]["location"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
