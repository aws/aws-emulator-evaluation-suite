"""put-integration-invalid-uri-scheme-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-integration-invalid-uri-scheme-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIntegration of type HTTP with a URI using an unsupported scheme (ftp://) is rejected
    with BadRequestException and no integration is stored on the method, while an otherwise
    identical request using a valid http(s):// URI succeeds (positive control, same file)."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )

    code, message = _error(
        lambda: apigw.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="HTTP",
            integrationHttpMethod="GET",
            uri="ftp://example.com/resource",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        'Invalid HTTP endpoint specified for URI'
    ), f"unexpected {code} message: {message!r}"

    # Effect absent: no integration was stored on the method.
    not_found_code, not_found_code_message = _error(
        lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException, got {not_found_code!r}"
    )
    assert not_found_code_message == (
        'Invalid Integration identifier specified'
    ), f"unexpected {not_found_code} message: {not_found_code_message!r}"

    # Positive control: a valid http(s) URI is accepted and persisted.
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        integrationHttpMethod="GET",
        uri="https://example.com/resource",
    )
    fetched = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["type"] == "HTTP", f"expected HTTP, got {fetched['type']!r}"
    assert fetched["uri"] == "https://example.com/resource", (
        f"expected https://example.com/resource, got {fetched['uri']!r}"
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
