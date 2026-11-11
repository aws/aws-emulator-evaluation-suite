"""update-integration-response-invalid-template-bad-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-integration-response-invalid-template-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIntegrationResponse with a valid contentHandling patch succeeds (positive control);
    the identical patch with an invalid contentHandling enum value fails BadRequestException and
    leaves the integration response exactly as the positive control left it."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"statusCode": 200}'},
    )

    # Positive control: the same operation (UpdateIntegrationResponse), a valid contentHandling
    # patch, succeeds and is persisted — proves the rejection below targets the enum value, not
    # every call to this operation.
    apigw.update_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        patchOperations=[{"op": "replace", "path": "/contentHandling", "value": "CONVERT_TO_TEXT"}],
    )
    control = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    assert control.get("contentHandling") == "CONVERT_TO_TEXT", (
        f"positive control: expected contentHandling CONVERT_TO_TEXT, got {control.get('contentHandling')!r}"
    )

    err = _client_error(
        lambda: apigw.update_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            patchOperations=[
                {"op": "replace", "path": "/contentHandling", "value": "NOT_A_REAL_ENCODING"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid ContentHandlingType specified. Valid options are CONVERT_TO_BINARY,CONVERT_TO_TEXT"
    ), f"expected the exact contentHandling refusal message, got {err.get('Message')!r}"

    # untouched: exactly what the positive control left, not the invalid value and not reverted
    got = apigw.get_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert got["responseTemplates"]["application/json"] == '{"statusCode": 200}', (
        f"expected original responseTemplates preserved, got {got.get('responseTemplates')!r}"
    )
    assert got.get("contentHandling") == "CONVERT_TO_TEXT", (
        f"expected contentHandling to still be the positive control's CONVERT_TO_TEXT, got {got.get('contentHandling')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
