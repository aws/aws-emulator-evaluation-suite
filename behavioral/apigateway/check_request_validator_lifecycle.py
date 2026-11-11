"""request-validator-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-validator-lifecycle"
GROUP = 'models-validators'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "request-validator-lifecycle"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRequestValidator -> GetRequestValidator reflects fields -> DeleteRequestValidator removes it."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    name = ctx.unique_name("sim2real-behav-validator-")

    created = ag.create_request_validator(
        restApiId=rest_api_id,
        name=name,
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    validator_id = created["id"]

    got = ag.get_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["validateRequestBody"] is True, (
        f"expected validateRequestBody True, got {got['validateRequestBody']!r}"
    )

    ag.delete_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)
    code, message = _error(
        lambda: ag.get_request_validator(
            restApiId=rest_api_id, requestValidatorId=validator_id
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Request Validator identifier specified", (
        f"unexpected message: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
