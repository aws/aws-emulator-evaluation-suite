"""put-method-nonexistent-request-validator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-nonexistent-request-validator-rejected"
GROUP = "methods"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMethod rejects a requestValidatorId that names no RequestValidator on the API, and
    creates no method, while a requestValidatorId naming a real validator is accepted."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-pm-rv-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")

    validator_id = apigw.create_request_validator(
        restApiId=api_id, name="sim2real-body-validator", validateRequestBody=True
    )["id"]

    control = apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        authorizationType="NONE", requestValidatorId=validator_id,
    )
    assert control["requestValidatorId"] == validator_id, (
        f"positive control: expected requestValidatorId {validator_id!r} echoed, "
        f"got {control.get('requestValidatorId')!r}"
    )
    fetched = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["requestValidatorId"] == validator_id, (
        f"positive control: expected requestValidatorId {validator_id!r} on independent read, "
        f"got {fetched.get('requestValidatorId')!r}"
    )

    bogus_validator_id = "sim2realnone"
    code, message = _error(lambda: apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="POST",
        authorizationType="NONE", requestValidatorId=bogus_validator_id,
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException for a requestValidatorId naming no validator, got {code!r}"
    )
    expected_message = "Invalid Request Validator identifier specified"
    assert message == expected_message, f"unexpected BadRequestException message {message!r}"

    not_found_code, not_found_message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    )
    assert not_found_code == "NotFoundException", (
        f"expected the rejected POST method to not exist, got {not_found_code!r} reading it"
    )
    assert not_found_message == "Invalid Method identifier specified", (
        f"unexpected not-found message {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
