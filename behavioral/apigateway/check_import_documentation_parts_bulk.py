"""import-documentation-parts-bulk."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-documentation-parts-bulk"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts bulk-creates parts, all visible via GetDocumentationParts."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    # NOTE: ImportDocumentationParts does NOT accept a bare {"documentationParts": [...]} object —
    # it expects a full OpenAPI/Swagger document carrying the parts under the
    # "x-amazon-apigateway-documentation" extension (the same extension GetExport would emit). A
    # bare documentationParts payload is unrecognizable to the importer ("Unable to build importer
    # with provided input") on real AWS. Additionally, within that extension "properties" is a
    # nested JSON OBJECT (it's already embedded inside the Swagger JSON document) — NOT a
    # doubly-encoded JSON string. A stringified "properties" value doesn't match the extension's
    # schema, so real AWS silently drops every part that carries one (ImportDocumentationParts
    # returns 0 ids, not an error).
    parts_payload = {
        "swagger": "2.0",
        "info": {"title": ctx.unique_name("sim2real-behav-docs-"), "version": "1.0"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "version": "1.0",
            "documentationParts": [
                {"location": {"type": "API"}, "properties": {"description": "bulk API doc"}},
                {
                    "location": {"type": "RESOURCE", "path": "/"},
                    "properties": {"description": "bulk root resource doc"},
                },
            ],
        },
    }
    body = json.dumps(parts_payload).encode("utf-8")

    result = apigw.import_documentation_parts(restApiId=api_id, body=body, mode="merge")
    imported_ids = result["ids"]
    assert len(imported_ids) == 2, f"expected 2 imported documentation parts, got {imported_ids!r}"

    listed = apigw.get_documentation_parts(restApiId=api_id)["items"]
    listed_ids = {p["id"] for p in listed}
    for part_id in imported_ids:
        assert part_id in listed_ids, f"imported documentation part {part_id} missing from GetDocumentationParts"

    by_type = {p["location"]["type"]: p for p in listed if p["id"] in imported_ids}
    assert set(by_type) == {"API", "RESOURCE"}, f"expected imported location types {{'API', 'RESOURCE'}}, got {set(by_type)!r}"

    # GetDocumentationParts re-serializes "properties" back into a JSON-encoded string on the way
    # out (the object form only holds on the way in, inside the swagger envelope) -- so the
    # round-trip has to be verified by re-parsing it, not by comparing it as a raw string.
    descriptions = {loc_type: json.loads(part["properties"])["description"] for loc_type, part in by_type.items()}
    assert descriptions == {
        "API": "bulk API doc",
        "RESOURCE": "bulk root resource doc",
    }, f"expected imported properties to round-trip verbatim, got {descriptions!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
