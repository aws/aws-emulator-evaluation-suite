"""gateway-response-invalid-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-response-invalid-type-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse with an invalid responseType is rejected and adds nothing to the response list."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_rest_api(restApiId=api_id)))

    before_count = len(apigw.get_gateway_responses(restApiId=api_id)["items"])

    # Positive control: a valid responseType is accepted.
    apigw.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_5XX", statusCode="500",
        responseTemplates={"application/json": '{"message":"boom"}'},
    )
    after_valid_count = len(apigw.get_gateway_responses(restApiId=api_id)["items"])
    assert after_valid_count == before_count, (
        f"expected {before_count} (DEFAULT_5XX already listed by default), got {after_valid_count}"
    )

    valid = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_5XX")
    assert valid["defaultResponse"] is False and valid["statusCode"] == "500", valid

    # Negative: an invalid responseType is rejected outright.
    status, code = _error_status_and_code(
        lambda: apigw.put_gateway_response(
            restApiId=api_id, responseType="NOT_A_REAL_RESPONSE_TYPE", statusCode="500"
        )
    )
    # Real AWS rejects the unknown responseType with an HTTP 400, but does not always
    # populate a distinguishing Error.Code for this particular validation failure.
    assert status == 400, f"expected HTTP 400 for invalid responseType, got status={status} code={code}"

    # The rejected call must not have mutated the set of configured gateway responses.
    still_valid = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_5XX")
    assert still_valid["statusCode"] == "500" and still_valid["defaultResponse"] is False, still_valid


def _error_status_and_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["ResponseMetadata"]["HTTPStatusCode"],
            e.response["Error"].get("Code"),
        )
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
