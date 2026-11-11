"""update-request-validator-nonexistent-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-request-validator-nonexistent-error"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRequestValidator for an id removed out-of-band returns NotFoundException, and
    the list of validators no longer includes it."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    created = apigw.create_request_validator(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-validator-"),
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    validator_id = created["id"]

    got = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert got["validateRequestBody"] is True, f"expected validateRequestBody True, got {got['validateRequestBody']!r}"

    # Positive control: UpdateRequestValidator succeeds against the live id, so the
    # NotFoundException asserted below is attributable to the deletion, not to a target
    # that rejects every UpdateRequestValidator call.
    apigw.update_request_validator(
        restApiId=api_id,
        requestValidatorId=validator_id,
        patchOperations=[{"op": "replace", "path": "/validateRequestBody", "value": "false"}],
    )
    after_positive_update = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert after_positive_update["validateRequestBody"] is False, (
        f"expected the positive-control update to flip validateRequestBody to False, "
        f"got {after_positive_update['validateRequestBody']!r}"
    )

    apigw.delete_request_validator(restApiId=api_id, requestValidatorId=validator_id)

    err = _client_error(
        lambda: apigw.update_request_validator(
            restApiId=api_id,
            requestValidatorId=validator_id,
            patchOperations=[{"op": "replace", "path": "/validateRequestBody", "value": "true"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Request Validator identifier specified", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
    )

    remaining_ids = {v["id"] for v in apigw.get_request_validators(restApiId=api_id)["items"]}
    assert validator_id not in remaining_ids, f"expected {validator_id!r} to be gone, still listed in {remaining_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
