"""delete-nonexistent-documentation-part-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-documentation-part-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDocumentationPart on an unknown id returns NotFoundException.

    Positive control: create a real documentation part, delete it successfully, then
    delete the same (now nonexistent) id again to observe the specific denial.
    """
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-docpart-api-"),
        tags={"sim2real": "true"},
    )
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    part = apigw.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties='{"description": "sim2real doc part"}',
    )
    part_id = part["id"]

    # positive control: it exists and the first delete succeeds
    apigw.get_documentation_part(restApiId=rest_api_id, documentationPartId=part_id)
    apigw.delete_documentation_part(restApiId=rest_api_id, documentationPartId=part_id)

    # negative: repeat delete on the now-gone id
    code, message = _client_error(
        lambda: apigw.delete_documentation_part(
            restApiId=rest_api_id, documentationPartId=part_id
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Documentation part identifier specified", message

    get_code, get_message = _client_error(
        lambda: apigw.get_documentation_part(
            restApiId=rest_api_id, documentationPartId=part_id
        )
    )
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "Invalid Documentation part identifier specified", get_message


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
