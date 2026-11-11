"""put-method-invalid-request-parameter-location-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-method-invalid-request-parameter-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod with a requestParameters key not using the method.request.* location prefix is rejected."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="things")
    resource_id = resource["id"]

    bad_key = "invalid.request.header.Foo"
    code, message = _error(
        lambda: apigw.put_method(
            restApiId=api_id,
            resourceId=resource_id,
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

    # (b) effect absent: no method was created on this resource.
    get_code, get_message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert get_code == "NotFoundException", "a method exists despite the rejected PutMethod"
    assert get_message == "Invalid Method identifier specified", f"unexpected message: {get_message!r}"

    # (c) positive control: a correctly-prefixed method.request.* location succeeds.
    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.Foo": False},
    )
    fetched = apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert fetched["requestParameters"] == {"method.request.querystring.Foo": False}, (
        f"expected method.request.querystring.Foo param, got {fetched.get('requestParameters')}"
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
