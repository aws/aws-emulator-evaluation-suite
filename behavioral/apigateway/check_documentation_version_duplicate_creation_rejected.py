"""documentation-version-duplicate-creation-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "documentation-version-duplicate-creation-rejected"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationVersion with an existing version id is rejected with ConflictException
    and leaves the original snapshot unmodified; a fresh version id succeeds (positive control)."""
    apig = ctx.client("apigateway")
    rest_api_id = apig.create_rest_api(
        name=ctx.unique_name("sim2real-behav-docverdupe-"),
        tags={"sim2real": "documentation-version-duplicate-creation-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=rest_api_id))

    apig.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "initial"}),
    )

    apig.create_documentation_version(
        restApiId=rest_api_id, documentationVersion="1.0.0", description="original-snapshot"
    )

    # Positive control: a distinct version identifier succeeds.
    apig.create_documentation_version(
        restApiId=rest_api_id, documentationVersion="2.0.0", description="second-snapshot"
    )
    second = apig.get_documentation_version(restApiId=rest_api_id, documentationVersion="2.0.0")
    assert second["description"] == "second-snapshot", (
        f"expected positive-control version '2.0.0' to carry description='second-snapshot', "
        f"got {second['description']!r}"
    )

    # Negative: re-using "1.0.0" must be rejected, and must NOT overwrite the existing snapshot.
    err = _error(
        lambda: apig.create_documentation_version(
            restApiId=rest_api_id, documentationVersion="1.0.0", description="attempted-overwrite"
        )
    )
    expected = ("ConflictException", "Documentation version 1.0.0 already exists.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    unchanged = apig.get_documentation_version(restApiId=rest_api_id, documentationVersion="1.0.0")
    assert unchanged["description"] == "original-snapshot", (
        "rejected duplicate-version create must not have mutated the existing snapshot: "
        f"got description={unchanged['description']!r}"
    )

    versions = apig.get_documentation_versions(restApiId=rest_api_id)["items"]
    assert sorted(v["version"] for v in versions) == ["1.0.0", "2.0.0"], (
        f"expected exactly the two real versions to exist, got {[v['version'] for v in versions]}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
