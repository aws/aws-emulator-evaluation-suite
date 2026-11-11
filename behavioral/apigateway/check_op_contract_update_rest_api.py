"""op-contract-updateRestApi."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateRestApi"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRestApi patches API-level metadata in place; nonexistent restApiId -> NotFoundException;
    a deleted restApiId is independently confirmed gone and no longer mutable."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        description="original description",
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_idempotent(apigw, api_id))

    updated = apigw.update_rest_api(
        restApiId=api_id,
        patchOperations=[
            {"op": "replace", "path": "/description", "value": "updated description"},
            {"op": "replace", "path": "/minimumCompressionSize", "value": "1024"},
        ],
    )
    assert updated["description"] == "updated description"
    assert updated["minimumCompressionSize"] == 1024
    assert updated["id"] == api_id

    refetched = apigw.get_rest_api(restApiId=api_id)
    assert refetched["description"] == "updated description"
    assert refetched["minimumCompressionSize"] == 1024

    code, message = _error(
        lambda: apigw.update_rest_api(
            restApiId="nonexistent-api-id",
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == (
        f"Invalid API identifier specified {ctx.account}:nonexistent-api-id"
    ), f"unexpected {code} message: {message!r}"

    apigw.delete_rest_api(restApiId=api_id)
    gone_code, gone_code_message = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert gone_code == "NotFoundException", (
        f"a deleted RestApi must be independently unreadable, got {gone_code}"
    )
    assert gone_code_message == (
        f"Invalid API identifier specified {ctx.account}:{api_id}"
    ), f"unexpected {gone_code} message: {gone_code_message!r}"
    mutate_code, mutate_code_message = _error(
        lambda: apigw.update_rest_api(
            restApiId=api_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert mutate_code == "NotFoundException", (
        f"UpdateRestApi on a deleted restApiId must fail NotFoundException, got {mutate_code}"
    )
    assert mutate_code_message == (
        f"Invalid API identifier specified {ctx.account}:{api_id}"
    ), f"unexpected {mutate_code} message: {mutate_code_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_idempotent(apigw, api_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
