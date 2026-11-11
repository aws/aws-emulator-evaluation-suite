"""authorizer-deletion-blocked-while-referenced-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "authorizer-deletion-blocked-while-referenced-rejected"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAuthorizer is rejected with ConflictException while a method references the
    authorizer, which stays intact; once the method is removed the same delete succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-authz-block-"),
        tags={"sim2real": "authz-block"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_delete_rest_api(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="blocked")
    resource_id = resource["id"]

    fake_lambda_arn = f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-nonexistent"
    authorizer_name = ctx.unique_name("sim2real-authz-")
    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=authorizer_name,
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fake_lambda_arn}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )

    code, message = _error(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert code == "ConflictException", f"expected ConflictException while referenced, got {code!r}"
    expected = f"Cannot delete authorizer '{authorizer_name}', is referenced in method: GET//blocked"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    still_there = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert still_there["id"] == authorizer_id, (
        f"authorizer {authorizer_id} vanished after a rejected delete: {still_there!r}"
    )

    apigw.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    code, message = _error(lambda: apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert code == "NotFoundException", f"expected NotFoundException after successful delete, got {code!r}"
    assert message == "Invalid Authorizer identifier specified", f"unexpected message {message!r}"




def _error(fn: Callable[[], Any]) -> tuple:
    """Call fn(); return botocore's (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_rest_api(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
