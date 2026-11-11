"""delete-method-error-contract-no-bad-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-method-error-contract-no-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMethod's error set (Conflict/NotFound/TooManyRequests) never surfaces
    BadRequestException, even for a malformed httpMethod value that PutMethod would reject."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"),
        tags={"sim2real-check": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    # A malformed httpMethod that PutMethod would reject with BadRequestException.
    code, message = _error(
        lambda: apigw.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="NOTAVERB123", authorizationType="NONE"
        )
    )
    assert code == "BadRequestException", f"PutMethod sanity check: expected BadRequestException, got {code!r}"
    assert message == "Invalid HttpMethod specified. Valid options are GET,PUT,POST,DELETE,PATCH,OPTIONS,HEAD,ANY", f"unexpected message: {message!r}"

    # DeleteMethod with the same malformed httpMethod never surfaces BadRequestException.
    code, message = _error(
        lambda: apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="NOTAVERB123")
    )
    assert code == "NotFoundException", f"DeleteMethod: expected NotFoundException, got {code!r}"
    assert message == "Invalid Method identifier specified", f"unexpected message: {message!r}"
    assert code != "BadRequestException", f"DeleteMethod must never surface BadRequestException, got {code!r}"

    # Confirm the real method is unaffected, then delete it and prove it is gone and unusable.
    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"GET method still present after delete, got {code!r}"
    assert message == "Invalid Method identifier specified", f"unexpected message: {message!r}"

    code, message = _error(
        lambda: apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"re-delete of already-deleted GET method: expected NotFoundException, got {code!r}"
    assert message == "Invalid Method identifier specified", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
