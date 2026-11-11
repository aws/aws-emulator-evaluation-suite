"""create-documentation-part-invalid-location-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-documentation-part-invalid-location-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationPart with a location.type outside the enumerated set is rejected."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    code, message = _error(
        lambda: apigw.create_documentation_part(
            restApiId=api_id,
            location={"type": "NOT_A_REAL_LOCATION_TYPE"},
            properties='{"description": "bogus"}',
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value 'NOT_A_REAL_LOCATION_TYPE' at "
        "'createDocumentationPartInput.location.type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [RESPONSE_BODY, RESPONSE, METHOD, MODEL, "
        "AUTHORIZER, RESPONSE_HEADER, RESOURCE, PATH_PARAMETER, REQUEST_BODY, "
        "QUERY_PARAMETER, API, REQUEST_HEADER]"
    ), f"unexpected ValidationException message {message!r}"

    # (b) effect absent: no documentation part exists on this API.
    parts = apigw.get_documentation_parts(restApiId=api_id)["items"]
    assert parts == [], "a documentation part was created despite the rejected request"

    # (c) positive control: a valid location.type ("API") is accepted.
    part = apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"}, properties='{"description": "ok"}'
    )
    part_id = part["id"]
    assert part["location"]["type"] == "API", f"expected location.type API, got {part['location']}"

    # terminal read: an independent GetDocumentationPart (not the mutating Create's own
    # response) confirms the positive control actually persisted.
    got = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    assert got["location"]["type"] == "API", f"expected persisted location.type API, got {got['location']}"


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
