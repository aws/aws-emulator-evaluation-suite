"""put-method-invalid-request-parameter-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-invalid-request-parameter-name-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod with a requestParameters key that doesn't match the
    method.request.{location}.{name} pattern is rejected and the method is never created, while
    a correctly-patterned key on the same resource succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    bad_key = "totally.wrong.shape"
    code, message = _error(
        lambda: apigw.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            authorizationType="NONE",
            requestParameters={bad_key: False},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "Invalid mapping expression specified: Validation Result: warnings : [], "
        f"errors : [Invalid mapping expression specified: {bad_key}]"
    ), f"unexpected message: {message!r}"

    # effect-absent: the GET method was never created on the resource.
    not_found_code, not_found_message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException, got {not_found_code}"
    )
    assert not_found_message == "Invalid Method identifier specified", (
        f"unexpected message: {not_found_message!r}"
    )

    # positive control: a differently-named method (POST, to avoid colliding with the failed
    # GET attempt) using a correctly-patterned requestParameters key succeeds.
    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.foo": False},
    )
    fetched = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    assert fetched["requestParameters"] == {"method.request.querystring.foo": False}, (
        f"expected the correctly-patterned key to round-trip, got {fetched.get('requestParameters')}"
    )


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
