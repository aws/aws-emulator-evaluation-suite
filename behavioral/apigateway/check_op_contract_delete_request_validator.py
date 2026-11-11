"""op-contract-delete-request-validator."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-request-validator"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRequestValidator removes the validator (a subsequent GetRequestValidator is
    NotFoundException); deleting a nonexistent requestValidatorId on a real restApiId is
    rejected with NotFoundException and creates no phantom state."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    validator_id = apigw.create_request_validator(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-apigw-validator-"),
        validateRequestBody=True,
        validateRequestParameters=False,
    )["id"]
    fetched = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert fetched["validateRequestBody"] is True, f"expected validateRequestBody True, got {fetched!r}"

    apigw.delete_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    err = _client_error(
        lambda: apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    )
    assert err.get("Code") == "NotFoundException", f"expected validator to be gone, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Request Validator identifier specified", (
        f"expected the exact NotFound message from GetRequestValidator, got {err.get('Message')!r}"
    )

    # a mutation on the now-dead id must also fail, not resurrect or silently no-op
    double_delete = _client_error(
        lambda: apigw.delete_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    )
    assert double_delete.get("Code") == "NotFoundException", f"expected double-delete of the dead id to be rejected, got {double_delete.get('Code')!r}"
    assert double_delete.get("Message") == "Invalid Request Validator identifier specified", (
        f"expected the exact NotFound message from the double delete, got {double_delete.get('Message')!r}"
    )

    # error boundary: deleting a requestValidatorId that never existed on a real restApiId
    err2 = _client_error(
        lambda: apigw.delete_request_validator(restApiId=api_id, requestValidatorId="bogus1")
    )
    assert err2.get("Code") == "NotFoundException", f"expected NotFoundException, got {err2.get('Code')!r}"
    assert err2.get("Message") == "Invalid Request Validator identifier specified", (
        f"expected the exact NotFound message for a never-created id, got {err2.get('Message')!r}"
    )
    remaining = apigw.get_request_validators(restApiId=api_id)["items"]
    assert remaining == [], "no request validator should remain or have been created"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
