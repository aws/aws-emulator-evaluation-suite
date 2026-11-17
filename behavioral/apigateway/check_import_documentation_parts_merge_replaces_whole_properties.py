"""import-documentation-parts-merge-replaces-whole-properties."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-documentation-parts-merge-replaces-whole-properties"
GROUP = "documentation"
SERVICES = ["apigateway"]

_THROTTLE = ("TooManyRequestsException", "Too Many Requests")


def _doc_body(location: dict, description: str) -> bytes:
    doc = {
        "swagger": "2.0",
        "info": {"title": "doc-import", "version": "1"},
        "paths": {},
        "x-amazon-apigateway-documentation": {
            "documentationParts": [{"location": location, "properties": {"description": description}}]
        },
    }
    return json.dumps(doc).encode("utf-8")


def _import_with_backoff(fn, *, budget_s: float = 60.0):
    """Retry fn() across ImportDocumentationParts' own account-level throttle."""
    deadline = time.monotonic() + budget_s
    delay = 2.0
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err.get("Message")) != _THROTTLE or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 10.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportDocumentationParts reuses an existing METHOD part's id at the imported location and
    replaces its whole properties with the imported one, dropping omitted fields; an unrelated
    location's part stays untouched. Mode omitted and mode=merge behave the same."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-docimport-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    resource_path = resource["path"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource["id"], httpMethod="GET", authorizationType="NONE"
    )

    method_location = {"type": "METHOD", "path": resource_path, "method": "GET"}
    method_part_id = apigw.create_documentation_part(
        restApiId=api_id, location=method_location,
        properties=json.dumps({"description": "method-doc-v1"}),
    )["id"]
    apigw.update_documentation_part(
        restApiId=api_id, documentationPartId=method_part_id,
        patchOperations=[{
            "op": "replace", "path": "/properties",
            "value": json.dumps(
                {"description": "method-doc-v1", "summary": "method-summary", "tags": ["alpha", "beta"]}
            ),
        }],
    )

    other_location = {"type": "API"}
    other_part_id = apigw.create_documentation_part(
        restApiId=api_id, location=other_location,
        properties=json.dumps({"description": "api-doc-untouched"}),
    )["id"]

    # --- import #1: mode omitted, so the default (merge) applies. ---
    result_default = _import_with_backoff(
        lambda: apigw.import_documentation_parts(
            restApiId=api_id, body=_doc_body(method_location, "method-doc-v2-default")
        )
    )
    assert result_default["ids"] == [method_part_id], (
        f"expected the default-mode import to reuse the existing METHOD part id {method_part_id!r}, "
        f"got ids={result_default['ids']!r}"
    )

    after_default = json.loads(
        apigw.get_documentation_part(restApiId=api_id, documentationPartId=method_part_id)["properties"]
    )
    assert after_default == {"description": "method-doc-v2-default"}, (
        f"expected the import to replace the whole properties object with exactly what it "
        f"imported, dropping the summary and tags it did not mention, got {after_default!r}"
    )

    other_after_default = json.loads(
        apigw.get_documentation_part(restApiId=api_id, documentationPartId=other_part_id)["properties"]
    )
    assert other_after_default == {"description": "api-doc-untouched"}, (
        f"the unrelated API-level part must be untouched by an import targeting a METHOD part, "
        f"got {other_after_default!r}"
    )

    # --- import #2: mode="merge" explicitly, which behaves the same as the default. ---
    result_merge = _import_with_backoff(
        lambda: apigw.import_documentation_parts(
            restApiId=api_id, mode="merge",
            body=_doc_body(method_location, "method-doc-v3-explicit-merge"),
        )
    )
    assert result_merge["ids"] == [method_part_id], (
        f"expected mode=merge to also reuse the existing METHOD part id {method_part_id!r}, "
        f"got ids={result_merge['ids']!r}"
    )

    after_merge = json.loads(
        apigw.get_documentation_part(restApiId=api_id, documentationPartId=method_part_id)["properties"]
    )
    assert after_merge == {"description": "method-doc-v3-explicit-merge"}, (
        f"expected mode=merge to replace the whole properties object the same way the default "
        f"did, got {after_merge!r}"
    )

    other_after_merge = json.loads(
        apigw.get_documentation_part(restApiId=api_id, documentationPartId=other_part_id)["properties"]
    )
    assert other_after_merge == {"description": "api-doc-untouched"}, (
        f"the unrelated API-level part must still be untouched after the second import, "
        f"got {other_after_merge!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
