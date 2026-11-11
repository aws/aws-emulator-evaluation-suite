"""import-documentation-parts-overwrite-mode."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "import-documentation-parts-overwrite-mode"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts mode=merge preserves untouched parts and updates/adds the
    imported ones; mode=overwrite discards the entire prior DocumentationParts collection and
    replaces it with exactly what was imported."""
    apig = ctx.client("apigateway")
    rest_api_id = apig.create_rest_api(
        name=ctx.unique_name("sim2real-behav-docimport-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=rest_api_id))

    # Pre-existing documentation part at the API level, created directly (not via import).
    api_part_id = apig.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "api-desc-original"}),
    )["id"]

    # --- mode=merge: adds a new MODEL part, leaves the existing API part untouched. ---
    merge_body = _doc_import_body(
        [{"location": {"type": "MODEL", "name": "Empty"}, "properties": {"title": "Empty Schema Doc v1"}}]
    )
    merge_resp = apig.import_documentation_parts(restApiId=rest_api_id, mode="merge", body=merge_body)
    assert len(merge_resp["ids"]) == 1, f"expected 1 imported id from merge, got {merge_resp['ids']}"
    model_part_id = merge_resp["ids"][0]

    parts_after_merge = apig.get_documentation_parts(restApiId=rest_api_id)["items"]
    by_id = {p["id"]: p for p in parts_after_merge}
    assert len(parts_after_merge) == 2, f"expected 2 parts after merge, got {len(parts_after_merge)}"
    assert api_part_id in by_id, "merge must preserve the pre-existing API-level part"
    assert model_part_id in by_id, "merge must add the newly imported MODEL part"
    api_part_desc = json.loads(by_id[api_part_id]["properties"])["description"]
    assert api_part_desc == "api-desc-original", (
        f"expected preserved API-part description 'api-desc-original', got {api_part_desc!r}"
    )
    model_part_title = json.loads(by_id[model_part_id]["properties"])["title"]
    assert model_part_title == "Empty Schema Doc v1", (
        f"expected imported MODEL-part title 'Empty Schema Doc v1', got {model_part_title!r}"
    )

    # --- mode=overwrite: replaces the ENTIRE collection; the pre-existing API part is gone. ---
    overwrite_body = _doc_import_body(
        [{"location": {"type": "MODEL", "name": "Empty"}, "properties": {"title": "Empty Schema Doc v2"}}]
    )
    apig.import_documentation_parts(restApiId=rest_api_id, mode="overwrite", body=overwrite_body)

    parts_after_overwrite = apig.get_documentation_parts(restApiId=rest_api_id)["items"]
    ids_after_overwrite = {p["id"] for p in parts_after_overwrite}
    assert len(parts_after_overwrite) == 1, (
        f"overwrite must replace the whole set; expected 1 part, got {len(parts_after_overwrite)}"
    )
    assert api_part_id not in ids_after_overwrite, "overwrite must remove the pre-existing API-level part"
    remaining = parts_after_overwrite[0]
    assert remaining["location"]["type"] == "MODEL" and remaining["location"]["name"] == "Empty", (
        f"expected the surviving part to be the imported MODEL/Empty location, got {remaining['location']}"
    )
    remaining_title = json.loads(remaining["properties"])["title"]
    assert remaining_title == "Empty Schema Doc v2", (
        f"expected surviving part title 'Empty Schema Doc v2', got {remaining_title!r}"
    )


def _doc_import_body(documentation_parts: list[dict[str, Any]]) -> bytes:
    body = {
        "swagger": "2.0",
        "info": {"title": "doc", "version": "1"},
        "paths": {},
        "x-amazon-apigateway-documentation": {"documentationParts": documentation_parts},
    }
    return json.dumps(body).encode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
