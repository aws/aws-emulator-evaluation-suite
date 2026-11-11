"""get-method-family-unauthorized-error-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-method-family-unauthorized-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a NotFoundException, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMethod, GetMethodResponse and GetResource return NotFoundException, never
    BadRequestException, for malformed identifiers; each negative is paired with a positive
    control on the same operation, so a target refusing every call fails the control."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    child = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")
    child_id = child["id"]
    apigw.put_method(restApiId=api_id, resourceId=child_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(
        restApiId=api_id, resourceId=child_id, httpMethod="GET", statusCode="200"
    )

    # Positive control: GetResource on the real child id must succeed and echo that id back.
    got_resource = apigw.get_resource(restApiId=api_id, resourceId=child_id)
    assert got_resource["id"] == child_id, (
        f"GetResource positive control: expected {child_id!r}, got {got_resource.get('id')!r}"
    )

    # Positive control: GetMethod on the real, defined httpMethod must succeed and echo it back.
    got_method = apigw.get_method(restApiId=api_id, resourceId=child_id, httpMethod="GET")
    assert got_method["httpMethod"] == "GET", (
        f"GetMethod positive control: expected 'GET', got {got_method.get('httpMethod')!r}"
    )

    # Positive control: GetMethodResponse on the real, defined statusCode must succeed and echo it back.
    got_method_response = apigw.get_method_response(
        restApiId=api_id, resourceId=child_id, httpMethod="GET", statusCode="200"
    )
    assert got_method_response["statusCode"] == "200", (
        f"GetMethodResponse positive control: expected '200', got {got_method_response.get('statusCode')!r}"
    )

    # GetMethod with a malformed/never-defined httpMethod -> NotFoundException, not BadRequestException
    code, message = _error(
        lambda: apigw.get_method(restApiId=api_id, resourceId=child_id, httpMethod="NOT-A-VERB!!")
    )
    assert code == "NotFoundException", f"GetMethod: expected NotFoundException, got {code!r}"
    assert message == "Invalid Method identifier specified", f"GetMethod: unexpected message {message!r}"

    # GetMethodResponse with a well-formed but undefined statusCode -> NotFoundException, not
    # BadRequestException; a malformed statusCode would fail shape validation and miss the not-found path.
    code, message = _error(
        lambda: apigw.get_method_response(
            restApiId=api_id, resourceId=child_id, httpMethod="GET", statusCode="599"
        )
    )
    assert code == "NotFoundException", f"GetMethodResponse: expected NotFoundException, got {code!r}"
    assert message == "Invalid Response status code specified", (
        f"GetMethodResponse: unexpected message {message!r}"
    )

    # GetResource with a bogus resourceId -> NotFoundException, not BadRequestException
    code, message = _error(lambda: apigw.get_resource(restApiId=api_id, resourceId="zzzzzzzz-bogus"))
    assert code == "NotFoundException", f"GetResource: expected NotFoundException, got {code!r}"
    assert message == "Invalid Resource identifier specified", f"GetResource: unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
