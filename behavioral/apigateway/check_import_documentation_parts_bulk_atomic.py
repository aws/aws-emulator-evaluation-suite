"""import-documentation-parts-bulk-atomic."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-documentation-parts-bulk-atomic"
GROUP = 'documentation'
SERVICES = ['apigateway']


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts creates every part in a bulk payload, per GetDocumentationParts;
    failOnWarnings=true rejects a warning-producing import and creates nothing, false commits it."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)

    doc = {
        "openapi": "3.0.0",
        "info": {"title": "doc-import", "version": "1"},
        "paths": {"/": {"get": {"responses": {"200": {"description": "200 response"}}}}},
        "x-amazon-apigateway-documentation": {
            "version": "1.0",
            "documentationParts": [
                {"location": {"type": "API"}, "properties": {"description": "sim2real-behav api doc"}},
                {
                    "location": {"type": "METHOD", "method": "GET"},
                    "properties": {"description": "sim2real-behav root GET doc"},
                },
                {
                    "location": {"type": "RESOURCE", "path": "/"},
                    "properties": {"description": "sim2real-behav root resource doc"},
                },
            ],
        },
    }
    body = json.dumps(doc).encode("utf-8")

    result = ag.import_documentation_parts(restApiId=api_id, mode="merge", body=body)
    ids = result.get("ids", [])
    # AWS may also infer parts from the OpenAPI definition (e.g. a RESPONSE part from the
    # "200 response" description), so expect at least the 3 explicit parts.
    assert len(ids) >= 3, f"expected at least the 3 explicitly-specified documentation parts imported in one call, got ids={ids!r}"

    parts = ag.get_documentation_parts(restApiId=api_id)["items"]
    assert len(parts) == len(ids), (
        f"expected GetDocumentationParts to reflect every part ImportDocumentationParts reported, "
        f"got {len(parts)} parts vs {len(ids)} ids"
    )

    part_ids = {p["id"] for p in parts}
    assert part_ids == set(ids), (
        f"expected GetDocumentationParts ids to match ImportDocumentationParts' returned ids, "
        f"got {part_ids!r} vs {set(ids)!r}"
    )

    types_seen = {p["location"]["type"] for p in parts}
    assert {"API", "METHOD", "RESOURCE"} <= types_seen, (
        f"expected all 3 explicitly imported location types to be present, got {types_seen!r}"
    )
    api_part = next(p for p in parts if p["location"]["type"] == "API")
    assert json.loads(api_part["properties"]).get("description") == "sim2real-behav api doc"

    # A duplicate location within one batch is not a warning (both parts are created); an
    # unresolvable model "$ref" is. failOnWarnings=true then raises BadRequestException and
    # creates nothing; failOnWarnings=false returns it in `warnings` and commits the part.
    before_warn = ag.get_documentation_parts(restApiId=api_id)["items"]

    warn_doc = {
        "openapi": "3.0.0",
        "info": {"title": "doc-import-warn", "version": "1"},
        "paths": {
            "/": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "200 response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DoesNotExist"}
                                }
                            },
                        }
                    }
                }
            }
        },
        "x-amazon-apigateway-documentation": {
            "version": "1.0",
            "documentationParts": [
                {"location": {"type": "MODEL", "name": "Empty"}, "properties": {"description": "warn-part"}},
            ],
        },
    }
    warn_body = json.dumps(warn_doc).encode("utf-8")

    blocked_code, blocked_message = _error(
        lambda: ag.import_documentation_parts(
            restApiId=api_id, mode="merge", failOnWarnings=True, body=warn_body
        )
    )
    assert blocked_code == "BadRequestException", (
        f"expected BadRequestException when failOnWarnings=true encounters a warning, "
        f"got {blocked_code!r}"
    )
    assert blocked_message == (
        "Warnings found during import:\n"
        "\tReference to model 'DoesNotExist' not found. Ignoring.\n"
        "\tReference to model 'DoesNotExist' not found. Ignoring.\n"
        "\tInvalid format for model application/json for method GET"
    ), (
        f"expected the unresolvable model reference to be named in the rejection, "
        f"got {blocked_message!r}"
    )

    after_blocked = ag.get_documentation_parts(restApiId=api_id)["items"]
    assert len(after_blocked) == len(before_warn), (
        f"failOnWarnings=true rejecting the import must roll back to nothing new -- "
        f"expected {len(before_warn)} parts, found {len(after_blocked)}"
    )

    allowed = ag.import_documentation_parts(restApiId=api_id, mode="merge", failOnWarnings=False, body=warn_body)
    assert allowed.get("warnings"), (
        f"expected the identical model-$ref warning with failOnWarnings=false, got {allowed!r}"
    )
    allowed_ids = set(allowed.get("ids", []))
    assert allowed_ids, (
        f"failOnWarnings=false must not roll back on a warning, got ids={allowed.get('ids')!r}"
    )

    # mode=merge reuses existing part ids for locations already documented, so `ids` is not a
    # count of new parts; assert only that the MODEL part is new and the collection grew.
    before_ids = {p["id"] for p in before_warn}
    new_ids = allowed_ids - before_ids
    assert new_ids, (
        f"failOnWarnings=false committed nothing genuinely new despite reporting ids={allowed_ids!r} "
        f"(pre-existing ids were {before_ids!r})"
    )

    after_allowed = ag.get_documentation_parts(restApiId=api_id)["items"]
    assert len(after_allowed) > len(before_warn), (
        f"expected the DocumentationParts collection to grow after the non-blocking import, "
        f"had {len(before_warn)}, now {len(after_allowed)}"
    )

    after_by_id = {p["id"]: p for p in after_allowed}
    model_part = next(
        (after_by_id[pid] for pid in new_ids if after_by_id.get(pid, {}).get("location", {}).get("type") == "MODEL"),
        None,
    )
    assert model_part is not None, (
        f"expected the explicit MODEL documentation part to be among the newly committed ids "
        f"{new_ids!r}, found types {[after_by_id[pid]['location']['type'] for pid in new_ids]!r}"
    )
    assert json.loads(model_part["properties"]).get("description") == "warn-part", (
        f"expected the committed MODEL part's properties to match what was imported, got {model_part!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected a ClientError, but the call SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
