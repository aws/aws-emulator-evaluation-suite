"""create-documentation-part-duplicate-location-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-documentation-part-duplicate-location-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second documentation part at an identical location is rejected with ConflictException
    and the original is untouched; a part at a different location on the same API succeeds."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-docdup-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    first = apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"},
        properties=json.dumps({"description": "first"}),
    )
    ctx.on_cleanup(lambda: _safe_delete_part(apigw, api_id, first["id"]))

    code, message = _error(lambda: apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"},
        properties=json.dumps({"description": "duplicate"}),
    ))
    assert code == "ConflictException", (
        f"expected ConflictException creating a duplicate-location documentation part, got {code!r}"
    )
    assert message == ("Documentation part already exists for the specified location: type 'API'."), f"unexpected ConflictException message {message!r}"

    parts = apigw.get_documentation_parts(restApiId=api_id)["items"]
    api_type_parts = [p for p in parts if p["location"]["type"] == "API"]
    assert len(api_type_parts) == 1, (
        f"expected exactly 1 API-type documentation part after the rejected duplicate, "
        f"found {len(api_type_parts)}: {api_type_parts}"
    )
    assert api_type_parts[0]["id"] == first["id"], (
        f"the original documentation part must be untouched, expected id {first['id']!r}, "
        f"found {api_type_parts[0]['id']!r}"
    )

    second = apigw.create_documentation_part(
        restApiId=api_id, location={"type": "RESOURCE", "path": "/"},
        properties=json.dumps({"description": "resource-level"}),
    )
    ctx.on_cleanup(lambda: _safe_delete_part(apigw, api_id, second["id"]))
    fetched_second = apigw.get_documentation_part(
        restApiId=api_id, documentationPartId=second["id"]
    )
    assert fetched_second["location"]["type"] == "RESOURCE", (
        f"expected the differently-located documentation part to be created and readable, "
        f"got location {fetched_second['location']!r}"
    )



def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
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
