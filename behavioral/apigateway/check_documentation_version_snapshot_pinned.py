"""documentation-version-snapshot-pinned."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "documentation-version-snapshot-pinned"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DocumentationVersion freezes DocumentationParts at creation: GetExport for a stage pinned
    to it returns the snapshot, not a later edit that the live part itself does show."""
    apig = ctx.client("apigateway")
    rest_api_id = apig.create_rest_api(
        name=ctx.unique_name("sim2real-behav-docsnap-"),
        tags={"sim2real": "documentation-version-snapshot-pinned"},
    )["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=rest_api_id))
    _add_root_mock_method(apig, rest_api_id)

    part_id = apig.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "v1-description"}),
    )["id"]

    _retry_throttled(
        lambda: apig.create_documentation_version(
            restApiId=rest_api_id, documentationVersion="1.0.0", description="snapshot-1"
        )
    )

    # Edit the live documentation part AFTER the snapshot was taken.
    apig.update_documentation_part(
        restApiId=rest_api_id,
        documentationPartId=part_id,
        patchOperations=[
            {"op": "replace", "path": "/properties", "value": json.dumps({"description": "v2-description"})}
        ],
    )

    # Positive control: the live part now shows the edit.
    live_part = apig.get_documentation_part(restApiId=rest_api_id, documentationPartId=part_id)
    live_description = json.loads(live_part["properties"])["description"]
    assert live_description == "v2-description", (
        f"expected the live documentation part to reflect the post-snapshot edit, "
        f"got description={live_description!r}"
    )

    deployment_id = apig.create_deployment(restApiId=rest_api_id)["id"]
    stage_name = ctx.unique_name("sim2real-stage-")[:32]
    apig.create_stage(
        restApiId=rest_api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        documentationVersion="1.0.0",
    )

    export = apig.get_export(
        restApiId=rest_api_id,
        stageName=stage_name,
        exportType="swagger",
        parameters={"extensions": "documentation"},
        accepts="application/json",
    )
    exported = json.loads(export["body"].read())
    doc_parts = exported["x-amazon-apigateway-documentation"]["documentationParts"]
    api_parts = [p for p in doc_parts if p["location"]["type"] == "API"]
    assert len(api_parts) == 1, f"expected exactly 1 API-level documentation part, got {len(api_parts)}"
    assert api_parts[0]["properties"]["description"] == "v1-description", (
        "exported snapshot must reflect state at CreateDocumentationVersion time, not later edits: "
        f"got {api_parts[0]['properties']}"
    )


def _retry_throttled(fn, attempts: int = 6, base_delay: float = 2.0):
    """Bounded retry with exponential backoff for API Gateway's account-level
    TooManyRequestsException throttling, which botocore's own retry budget can exhaust."""
    from botocore.exceptions import ClientError

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException":
                raise
            last_exc = exc
            time.sleep(base_delay * (2**attempt))
    raise last_exc


def _add_root_mock_method(apig, rest_api_id: str) -> None:
    """Wire up a trivial GET / MOCK method so the API has something deployable."""
    root_id = next(r["id"] for r in apig.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/")
    apig.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apig.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apig.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apig.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
