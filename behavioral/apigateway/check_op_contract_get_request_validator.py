"""op-contract-getRequestValidator."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getRequestValidator"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRequestValidator round-trips the exact validateRequestBody/
    validateRequestParameters flags; a lookup with a bogus id 404s."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    name = ctx.unique_name("sim2real-behav-validator-")
    created = apigw.create_request_validator(
        restApiId=api_id, name=name, validateRequestBody=True, validateRequestParameters=False
    )
    validator_id = created["id"]

    got = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert got["id"] == validator_id, f"expected id {validator_id!r}, got {got['id']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["validateRequestBody"] is True, (
        f"expected validateRequestBody True, got {got['validateRequestBody']!r}"
    )
    assert got["validateRequestParameters"] is False, (
        f"expected validateRequestParameters False, got {got['validateRequestParameters']!r}"
    )

    code, message = _error(
        lambda: apigw.get_request_validator(restApiId=api_id, requestValidatorId="nope123")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Request Validator identifier specified", f"unexpected message: {message!r}"


def _error(fn) -> Any:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a bogus id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a bogus requestValidatorId to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
