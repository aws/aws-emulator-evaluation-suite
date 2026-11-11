"""create-documentation-part-duplicate-location-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-documentation-part-duplicate-location-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second documentation part with an identical location fails with ConflictException; deleting the
    part frees the location for reuse, and deleting the deleted part again fails with NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-docpart-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    location = {"type": "API"}
    part_id = apigw.create_documentation_part(
        restApiId=api_id, location=location, properties='{"description":"first"}'
    )["id"]

    code, message = _error(
        lambda: apigw.create_documentation_part(
            restApiId=api_id, location=location, properties='{"description":"second"}'
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException creating a documentation part at a duplicate "
        f"location, got {code!r}"
    )
    assert message == ("Documentation part already exists for the specified location: type 'API'."), f"unexpected ConflictException message {message!r}"

    parts = apigw.get_documentation_parts(restApiId=api_id)["items"]
    matching = [p for p in parts if p["location"] == location]
    assert len(matching) == 1 and matching[0]["id"] == part_id, (
        f"duplicate location must not create a second documentation part, got {matching!r}"
    )

    # restore: deleting the occupying part must free the location
    apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id)

    parts_after_delete = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert not [p for p in parts_after_delete if p["location"] == location], (
        f"deleted documentation part must no longer appear at its location, got {parts_after_delete!r}"
    )

    redelete_code, redelete_message = _error(
        lambda: apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id)
    )
    assert redelete_code == "NotFoundException", (
        f"deleting an already-deleted documentation part must be NotFoundException, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == "Invalid Documentation part identifier specified", f"unexpected NotFoundException message {redelete_message!r}"

    # identical call now succeeds: the location is free again
    restored_id = apigw.create_documentation_part(
        restApiId=api_id, location=location, properties='{"description":"restored"}'
    )["id"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: apigw.delete_documentation_part(
                restApiId=api_id, documentationPartId=restored_id
            )
        )
    )
    final_parts = apigw.get_documentation_parts(restApiId=api_id)["items"]
    final_matching = [p for p in final_parts if p["location"] == location]
    assert len(final_matching) == 1 and final_matching[0]["id"] == restored_id, (
        f"recreating at the freed location must succeed and be visible, got {final_matching!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
