"""documentation-part-duplicate-location-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "documentation-part-duplicate-location-rejected"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateDocumentationPart at type=API is rejected with ConflictException and adds no
    duplicate; after the first is deleted the same call succeeds, as does a different location."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    first = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties='{"description": "first"}',
    )
    first_id = first["id"]
    ctx.on_cleanup(lambda: _safe_delete_part(apigw, api_id, first_id))

    err = _error(
        lambda: apigw.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties='{"description": "duplicate-attempt"}',
        )
    )
    expected = ("ConflictException", "Documentation part already exists for the specified location: type 'API'.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # effect absent: exactly one documentation part of type API exists for this API
    parts = apigw.get_documentation_parts(restApiId=api_id, type="API")["items"]
    assert len(parts) == 1, f"expected exactly 1 API-type documentation part, found {len(parts)}"
    assert parts[0]["id"] == first_id, (
        f"expected surviving part to be the original {first_id!r}, found {parts[0]['id']!r}"
    )

    # restore: the location is blocked by the first part's existence, not by the location
    # value itself — deleting it must free the location for the identical call to succeed.
    apigw.delete_documentation_part(restApiId=api_id, documentationPartId=first_id)
    restored = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties='{"description": "restored"}',
    )
    restored_id = restored["id"]
    ctx.on_cleanup(lambda: _safe_delete_part(apigw, api_id, restored_id))
    restored_parts = apigw.get_documentation_parts(restApiId=api_id, type="API")["items"]
    assert len(restored_parts) == 1, (
        f"expected exactly 1 API-type documentation part after restore, found "
        f"{len(restored_parts)}"
    )
    assert restored_parts[0]["id"] == restored_id, (
        f"expected the restored part {restored_id!r} to occupy the freed location, "
        f"found {restored_parts[0]['id']!r}"
    )

    # positive control: a different location on the same API succeeds
    second = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "RESOURCE", "path": "/"},
        properties='{"description": "resource-level"}',
    )
    second_id = second["id"]
    ctx.on_cleanup(
        lambda: apigw.delete_documentation_part(restApiId=api_id, documentationPartId=second_id)
    )
    fetched_second = apigw.get_documentation_part(
        restApiId=api_id, documentationPartId=second_id
    )
    assert fetched_second["location"]["type"] == "RESOURCE", (
        f"expected the second part's independent read to report location type RESOURCE, "
        f"got {fetched_second['location']!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises."""
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
