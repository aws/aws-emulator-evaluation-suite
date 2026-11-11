"""put-method-malformed-request-parameter-name-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "put-method-malformed-request-parameter-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod rejects a requestParameters key that isn't method.request.{location}.{name}."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    # Negative: malformed key -- "invalidloc" is not a valid {location} (path|querystring|header).
    bad_key = "method.request.invalidloc.foo"
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

    # Effect absent: the GET method must not have been created on the resource.
    absent_code, absent_message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert absent_code == "NotFoundException", f"malformed PutMethod leaked a method: {absent_code}"
    assert absent_message == "Invalid Method identifier specified", (
        f"unexpected message: {absent_message!r}"
    )

    # Positive control: a syntactically valid requestParameters key succeeds.
    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.foo": False},
    )
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    assert method["requestParameters"] == {"method.request.querystring.foo": False}, (
        f"expected the positive control's requestParameters to persist, got {method.get('requestParameters')!r}"
    )


def _error(fn: Any) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
