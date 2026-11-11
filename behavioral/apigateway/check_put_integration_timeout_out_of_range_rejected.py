"""put-integration-timeout-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-timeout-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegration with timeoutInMillis outside the 50-29000ms range is rejected and no
    integration is stored, while an in-range timeout on the same method succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="NONE",
    )

    # negative: timeoutInMillis above the documented 29000ms ceiling is rejected.
    code, message = _error(
        lambda: apigw.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="HTTP",
            uri="https://example.com/",
            integrationHttpMethod="GET",
            timeoutInMillis=30001,
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        'Timeout should be between 50 ms and 29000 ms'
    ), f"unexpected {code} message: {message!r}"

    # effect-absent: no integration was persisted for this method.
    not_found_code, not_found_code_message = _error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert not_found_code == "NotFoundException", f"expected NotFoundException, got {not_found_code}"
    assert not_found_code_message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {not_found_code} message: {not_found_code_message!r}"

    # positive control: an in-range timeout on the same method succeeds and persists.
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        uri="https://example.com/",
        integrationHttpMethod="GET",
        timeoutInMillis=29000,
    )
    integration = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert integration["timeoutInMillis"] == 29000, (
        f"expected timeoutInMillis 29000, got {integration['timeoutInMillis']}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
