"""delete-nonexistent-integration-response-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-integration-response-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIntegrationResponse on a status code never mapped returns NotFoundException.

    Positive control: mapping status code 200 lets the first delete succeed; deleting
    the same status code again (now unmapped) reproduces the negative case.
    """
    apigw = ctx.client("apigateway")
    rest_api_id, resource_id = _create_api_with_mock_integration(ctx, apigw)

    code1, message1 = _client_error(
        lambda: apigw.delete_integration_response(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code1 == "NotFoundException", f"expected NotFoundException, got {code1}"
    assert message1 == "Invalid Response status code specified", message1

    # positive control: map status 200, then delete it successfully
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": ""},
    )
    mapped = apigw.get_integration_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert mapped["statusCode"] == "200", f"expected the mapping to be visible, got {mapped}"
    apigw.delete_integration_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )

    # effect absent: an independent read of the just-deleted mapping 404s
    gone_code, gone_message = _client_error(
        lambda: apigw.get_integration_response(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
        )
    )
    assert gone_code == "NotFoundException", f"expected the deleted mapping to be gone, got {gone_code}"
    assert gone_message == "Invalid Response status code specified", gone_message

    # negative again: a second delete of the now-unmapped status also 404s
    code2, message2 = _client_error(
        lambda: apigw.delete_integration_response(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code2 == "NotFoundException", f"expected NotFoundException, got {code2}"
    assert message2 == "Invalid Response status code specified", message2

    # the status code is reusable: re-mapping it and reading it back succeeds
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": ""},
    )
    remapped = apigw.get_integration_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert remapped["statusCode"] == "200", f"expected status 200 to be reusable, got {remapped}"


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_api_with_mock_integration(ctx, apigw):
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-intresp-api-"))
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    resources = apigw.get_resources(restApiId=rest_api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    return rest_api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
