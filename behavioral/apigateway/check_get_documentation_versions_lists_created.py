"""get-documentation-versions-lists-created."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-documentation-versions-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDocumentationVersions reflects a newly created version."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-docverlist-"), tags={"sim2real": "true"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"},
        properties=json.dumps({"description": "snapshot content"}),
    )
    apigw.create_documentation_version(restApiId=api_id, documentationVersion="v1")
    ctx.on_cleanup(lambda: _safe_delete_version(apigw, api_id, "v1"))

    versions = apigw.get_documentation_versions(restApiId=api_id)["items"]
    assert len(versions) == 1, f"expected exactly one documentation version, got {versions}"
    assert versions[0]["version"] == "v1", f"expected version 'v1', got {versions[0]}"


def _safe_delete_version(apigw, api_id: str, version: str) -> None:
    try:
        apigw.delete_documentation_version(restApiId=api_id, documentationVersion=version)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
