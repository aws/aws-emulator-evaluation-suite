"""documentation-version-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "documentation-version-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationVersion -> Get -> Update -> Delete -> 404 on get and on mutation ->
    version id reusable."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-docver-"), tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"},
        properties=json.dumps({"description": "snapshot content"}),
    )

    created = apigw.create_documentation_version(
        restApiId=api_id, documentationVersion="v1", description="sim2real initial version",
    )
    ctx.on_cleanup(lambda: _safe_delete_version(apigw, api_id, "v1"))
    assert created["version"] == "v1", f"expected version 'v1' echoed on create, got {created.get('version')!r}"
    assert created["description"] == "sim2real initial version", (
        f"expected initial description echoed on create, got {created.get('description')!r}"
    )

    got = apigw.get_documentation_version(restApiId=api_id, documentationVersion="v1")
    assert got["version"] == "v1", f"expected independent read to see version 'v1', got {got.get('version')!r}"

    updated = apigw.update_documentation_version(
        restApiId=api_id, documentationVersion="v1",
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real updated version"}],
    )
    assert updated["description"] == "sim2real updated version", (
        f"expected patched description, got {updated.get('description')!r}"
    )

    apigw.delete_documentation_version(restApiId=api_id, documentationVersion="v1")

    not_found = ("NotFoundException", "Invalid Documentation version specified")
    read_err = _error(
        lambda: apigw.get_documentation_version(restApiId=api_id, documentationVersion="v1")
    )
    assert read_err == not_found, (
        f"expected {not_found!r} reading a deleted version, got {read_err!r}"
    )

    mutate_err = _error(
        lambda: apigw.update_documentation_version(
            restApiId=api_id, documentationVersion="v1",
            patchOperations=[{"op": "replace", "path": "/description", "value": "should not apply"}],
        )
    )
    assert mutate_err == not_found, (
        f"expected UpdateDocumentationVersion on a deleted version to also fail {not_found!r}, "
        f"got {mutate_err!r}"
    )

    recreated = apigw.create_documentation_version(
        restApiId=api_id, documentationVersion="v1", description="sim2real reused version id",
    )
    assert recreated["version"] == "v1", (
        f"expected the version id 'v1' to be reusable after delete, got {recreated.get('version')!r}"
    )

    reread = apigw.get_documentation_version(restApiId=api_id, documentationVersion="v1")
    assert reread["description"] == "sim2real reused version id", (
        f"expected an independent read to see the reused version's own description, "
        f"got {reread.get('description')!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_version(apigw, api_id: str, version: str) -> None:
    try:
        apigw.delete_documentation_version(restApiId=api_id, documentationVersion=version)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
