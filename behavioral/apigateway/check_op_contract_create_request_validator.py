"""op-contract-createRequestValidator."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createRequestValidator"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRequestValidator echoes and persists its validation flags; a nonexistent restApiId is
    rejected with BadRequestException and no validator is created."""
    apigw = ctx.client("apigateway")
    api_id, _root_id = _create_rest_api(ctx)

    created = apigw.create_request_validator(
        restApiId=api_id,
        name="strict-validator",
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    validator_id = created["id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_request_validator(restApiId=api_id, requestValidatorId=validator_id)
        )
    )
    assert created["name"] == "strict-validator", f"expected name echoed, got {created['name']!r}"
    assert created["validateRequestBody"] is True, "expected validateRequestBody=True echoed on create"
    assert created["validateRequestParameters"] is False, (
        "expected validateRequestParameters=False echoed on create"
    )

    fetched = apigw.get_request_validator(restApiId=api_id, requestValidatorId=validator_id)
    assert fetched["validateRequestBody"] is True, (
        f"expected validateRequestBody=True on independent read, got {fetched['validateRequestBody']!r}"
    )
    assert fetched["validateRequestParameters"] is False, (
        "expected validateRequestParameters=False on independent read, got "
        f"{fetched['validateRequestParameters']!r}"
    )

    before_ids = {v["id"] for v in apigw.get_request_validators(restApiId=api_id)["items"]}

    # A same-shaped but nonexistent restApiId gets BadRequestException, not NotFoundException:
    # this create validates the identifier as part of request validation.
    nonexistent_api_id = _nonexistent_like_id(api_id)

    err = _client_error(
        lambda: apigw.create_request_validator(
            restApiId=nonexistent_api_id,
            name="orphan-validator",
            validateRequestBody=True,
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid REST API identifier specified", (
        f"expected the exact bad-identifier message, got {err.get('Message')!r}"
    )

    after_ids = {v["id"] for v in apigw.get_request_validators(restApiId=api_id)["items"]}
    assert before_ids == after_ids, "validator set on the real API changed after a failed create"


def _nonexistent_like_id(id_):
    import random
    import string

    while True:
        candidate = random.choice(string.ascii_lowercase) + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=len(id_) - 1)
        )
        if candidate != id_:
            return candidate


def _client_error(fn):
    """The botocore Error dict of the ClientError fn raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "op-contract-createRequestValidator"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
