"""delete-nonexistent-integration-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-integration-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIntegration on a method with no integration succeeds as a no-op while GetIntegration reports
    NotFoundException before and after; once a MOCK integration is wired, GetIntegration succeeds, the
    delete removes it, and GetIntegration reports NotFoundException again."""
    apigw = ctx.client("apigateway")
    rest_api_id, resource_id = _create_api_with_method(ctx, apigw)

    # confirm the method truly has no integration yet
    get_code0, get_code0_message = _client_error(
        lambda: apigw.get_integration(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
        )
    )
    assert get_code0 == "NotFoundException", f"expected NotFoundException, got {get_code0}"
    assert get_code0_message == "Invalid Integration identifier specified", get_code0_message

    # DeleteIntegration on a bare method is a no-op success, not an error
    status1 = apigw.delete_integration(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )["ResponseMetadata"]["HTTPStatusCode"]
    assert status1 == 204, f"expected the idempotent no-op delete to return 204, got {status1}"

    # positive control: wire a real MOCK integration, confirm it's gettable, then delete it
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    wired = apigw.get_integration(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET")
    assert wired["type"] == "MOCK", f"expected MOCK integration, got {wired.get('type')}"
    apigw.delete_integration(restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET")

    # the method is bare once more: GetIntegration confirms the real removal
    get_code, get_code_message = _client_error(
        lambda: apigw.get_integration(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
        )
    )
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_code_message == "Invalid Integration identifier specified", get_code_message

    # deleting again on this now-bare method is still a no-op success
    status2 = apigw.delete_integration(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )["ResponseMetadata"]["HTTPStatusCode"]
    assert status2 == 204, f"expected the idempotent no-op delete to return 204, got {status2}"

    # independent read proves the no-op truly did nothing: the method is still bare
    final_code, final_code_message = _client_error(
        lambda: apigw.get_integration(
            restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
        )
    )
    assert final_code == "NotFoundException", f"expected NotFoundException, got {final_code}"
    assert final_code_message == "Invalid Integration identifier specified", final_code_message


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises,
    so an accepted call is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_api_with_method(ctx, apigw):
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-integ-api-"))
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
    return rest_api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
