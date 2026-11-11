"""documentation-part-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "documentation-part-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationPart -> Get -> Update -> independent Get -> Delete -> 404 on
    get and on a further mutation of the dead id."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-docpart-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    created = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "sim2real initial doc"}),
    )
    part_id = created["id"]
    ctx.on_cleanup(lambda: _safe_delete_part(apigw, api_id, part_id))
    created_desc = json.loads(created["properties"])["description"]
    assert created_desc == "sim2real initial doc", (
        f"expected created properties.description='sim2real initial doc', got {created_desc!r}"
    )

    got = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    assert got["location"]["type"] == "API", (
        f"expected location.type='API' on independent get, got {got['location']['type']!r}"
    )

    updated = apigw.update_documentation_part(
        restApiId=api_id, documentationPartId=part_id,
        patchOperations=[{
            "op": "replace", "path": "/properties",
            "value": json.dumps({"description": "sim2real updated doc"}),
        }],
    )
    updated_desc = json.loads(updated["properties"])["description"]
    assert updated_desc == "sim2real updated doc", (
        f"expected updated properties.description='sim2real updated doc', got {updated_desc!r}"
    )

    reread = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    reread_desc = json.loads(reread["properties"])["description"]
    assert reread_desc == "sim2real updated doc", (
        f"update did not persist: independent get returned properties.description={reread_desc!r}"
    )

    apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id)
    not_found = ("NotFoundException", "Invalid Documentation part identifier specified")
    get_after_delete = _error(
        lambda: apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    )
    assert get_after_delete == not_found, (
        f"expected {not_found!r} reading a deleted documentation part, got {get_after_delete!r}"
    )

    update_after_delete = _error(
        lambda: apigw.update_documentation_part(
            restApiId=api_id, documentationPartId=part_id,
            patchOperations=[{
                "op": "replace", "path": "/properties",
                "value": json.dumps({"description": "sim2real post-delete"}),
            }],
        )
    )
    assert update_after_delete == not_found, (
        f"expected {not_found!r} mutating a deleted documentation part, got {update_after_delete!r}"
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


def _safe_delete_part(apigw, api_id: str, part_id: str) -> None:
    try:
        apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
