"""put-integration-response-without-integration-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-integration-response-without-integration-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIntegrationResponse on a method that has no integration configured yet
    must be rejected with NotFoundException, not silently accepted -- and the
    identical call must succeed once an integration is attached."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-noint-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    # Positive control: an identical PutIntegrationResponse call succeeds on a
    # sibling method that DOES have an integration -- proves the account/API is
    # otherwise healthy for this call, so the negative below can't be "this
    # target rejects every PutIntegrationResponse".
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    control = apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": ""},
    )
    assert control["statusCode"] == "200", f"positive control did not succeed: {control}"

    # Break exactly one thing: a second method on the same resource with no
    # integration configured yet.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE")
    # Deliberately skip PutIntegration on POST.

    code, message = _error(
        lambda: apigw.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="POST",
            statusCode="200",
            responseTemplates={"application/json": ""},
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException without an integration, got {code!r}"
    assert message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {code} message: {message!r}"

    # Effect absent: no integration response leaked through despite the rejection.
    code2, code2_message = _error(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="POST", statusCode="200"
        )
    )
    assert code2 == "NotFoundException", f"expected NotFoundException on independent read, got {code2!r}"
    assert code2_message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {code2} message: {code2_message!r}"

    # Restore: attach the integration that was missing, then retry the IDENTICAL
    # PutIntegrationResponse call -- it must now succeed.
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="POST", type="MOCK")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="POST", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )

    # Terminal read: independent of the mutating call, at the destination.
    restored = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="POST", statusCode="200"
    )
    assert restored["statusCode"] == "200", f"restored integration response missing: {restored}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
