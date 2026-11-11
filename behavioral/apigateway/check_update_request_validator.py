"""update-request-validator."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-request-validator"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching validateRequestBody/validateRequestParameters on a request validator is
    reflected when listing validators via GetRequestValidators."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    validator_name = ctx.unique_name("sim2real-validator-")
    created = apigw.create_request_validator(
        restApiId=api_id,
        name=validator_name,
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    validator_id = created["id"]
    assert created["validateRequestBody"] is True, (
        f"expected validateRequestBody True on create, got {created['validateRequestBody']}"
    )
    assert created["validateRequestParameters"] is False, (
        f"expected validateRequestParameters False on create, got {created['validateRequestParameters']}"
    )

    apigw.update_request_validator(
        restApiId=api_id,
        requestValidatorId=validator_id,
        patchOperations=[
            {"op": "replace", "path": "/validateRequestBody", "value": "false"},
            {"op": "replace", "path": "/validateRequestParameters", "value": "true"},
        ],
    )

    listed = apigw.get_request_validators(restApiId=api_id)["items"]
    match = next((v for v in listed if v["id"] == validator_id), None)
    assert match is not None, f"validator {validator_id} missing from GetRequestValidators listing"
    assert match["name"] == validator_name, f"expected name {validator_name}, got {match['name']}"
    assert match["validateRequestBody"] is False, "validateRequestBody must flip to False"
    assert match["validateRequestParameters"] is True, "validateRequestParameters must flip to True"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
