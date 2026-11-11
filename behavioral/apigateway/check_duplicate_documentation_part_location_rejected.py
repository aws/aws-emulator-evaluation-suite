"""duplicate-documentation-part-location-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "duplicate-documentation-part-location-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationPart rejects a second part at a location that already has one; the first is untouched."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-dupdoc-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # Positive control: the first documentation part for the API-level location succeeds.
    first_props = json.dumps({"description": "sim2real first"})
    first = apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"}, properties=first_props
    )

    # A second part at the exact same location must be refused.
    err = _error(
        lambda: apigw.create_documentation_part(
            restApiId=api_id, location={"type": "API"}, properties=json.dumps({"description": "sim2real second"})
        )
    )
    expected = ("ConflictException", "Documentation part already exists for the specified location: type 'API'.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # The original documentation part must remain the only one, unchanged.
    listed = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert len(listed) == 1, listed
    assert listed[0]["id"] == first["id"], f"expected id {first['id']!r}, got {listed[0]['id']!r}"
    assert listed[0]["properties"] == first_props, (
        f"expected unchanged properties {first_props!r}, got {listed[0]['properties']!r}"
    )

    # Restore: once the location is freed, the identical call that was just
    # refused must now succeed — proving the rejection was about the occupied
    # location, not the request shape.
    apigw.delete_documentation_part(restApiId=api_id, documentationPartId=first["id"])
    restored_props = json.dumps({"description": "sim2real restored"})
    restored = apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"}, properties=restored_props
    )
    ctx.on_cleanup(
        lambda: apigw.delete_documentation_part(restApiId=api_id, documentationPartId=restored["id"])
    )
    listed_after_restore = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert len(listed_after_restore) == 1, listed_after_restore
    assert listed_after_restore[0]["id"] == restored["id"], (
        f"expected restored id {restored['id']!r}, got {listed_after_restore[0]['id']!r}"
    )
    assert listed_after_restore[0]["properties"] == restored_props, (
        f"expected restored properties {restored_props!r}, got {listed_after_restore[0]['properties']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
