"""update-request-validator-patch-flags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-request-validator-patch-flags"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRequestValidator toggles validateRequestBody/Parameters independently."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    created = apigw.create_request_validator(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-bh-validator-"),
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    validator_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_request_validator(restApiId=api_id, requestValidatorId=validator_id))
    assert created["validateRequestBody"] is True, f"expected validateRequestBody True on create, got {created['validateRequestBody']!r}"
    assert created["validateRequestParameters"] is False, f"expected validateRequestParameters False on create, got {created['validateRequestParameters']!r}"

    # Toggle only validateRequestParameters -> body flag must stay untouched.
    step1 = apigw.update_request_validator(
        restApiId=api_id,
        requestValidatorId=validator_id,
        patchOperations=[{"op": "replace", "path": "/validateRequestParameters", "value": "true"}],
    )
    assert step1["validateRequestBody"] is True, "unrelated flag must be preserved"
    assert step1["validateRequestParameters"] is True, f"expected validateRequestParameters True after patch, got {step1['validateRequestParameters']!r}"

    # Now toggle only validateRequestBody -> parameters flag (just flipped) must stay untouched.
    step2 = apigw.update_request_validator(
        restApiId=api_id,
        requestValidatorId=validator_id,
        patchOperations=[{"op": "replace", "path": "/validateRequestBody", "value": "false"}],
    )
    assert step2["validateRequestBody"] is False, f"expected validateRequestBody False after patch, got {step2['validateRequestBody']!r}"
    assert step2["validateRequestParameters"] is True, "unrelated flag must be preserved"

    fetched = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert fetched["validateRequestBody"] is False, f"expected validateRequestBody False on independent read, got {fetched['validateRequestBody']!r}"
    assert fetched["validateRequestParameters"] is True, f"expected validateRequestParameters True on independent read, got {fetched['validateRequestParameters']!r}"


def _create_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
