"""delete-gateway-response-default-type-resets-state."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-gateway-response-default-type-resets-state"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGatewayResponse on a customized DEFAULT_4XX succeeds and resets it to the default
    (defaultResponse=True, customization cleared) rather than failing or leaving it in place.

    Reference: https://docs.aws.amazon.com/apigateway/latest/api/API_DeleteGatewayResponse.html"""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-gwresp-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    baseline = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert baseline["defaultResponse"] is True, "DEFAULT_4XX must start out uncustomized"

    apigw.put_gateway_response(
        restApiId=api_id,
        responseType="DEFAULT_4XX",
        statusCode="404",
        responseTemplates={"application/json": '{"message":"sim2real-custom"}'},
    )
    customized = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert customized["defaultResponse"] is False, "PutGatewayResponse must mark it customized"
    assert customized["statusCode"] == "404", (
        f"expected statusCode '404' after PutGatewayResponse, got {customized['statusCode']!r}"
    )

    # DeleteGatewayResponse on DEFAULT_4XX succeeds; a refusal raises ClientError here.
    apigw.delete_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")

    reset = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert reset["defaultResponse"] is True, (
        "DeleteGatewayResponse must fully reset DEFAULT_4XX back to the built-in "
        "default, not leave the prior customization in place"
    )
    assert reset.get("statusCode") == baseline.get("statusCode"), (
        f"expected the reset statusCode to match the pristine baseline "
        f"({baseline.get('statusCode')!r}), got {reset.get('statusCode')!r} -- the custom "
        f"statusCode must not survive the reset"
    )
    assert reset.get("responseTemplates", {}) == baseline.get("responseTemplates", {}), (
        f"expected the reset responseTemplates to match the pristine baseline "
        f"({baseline.get('responseTemplates')!r}), got {reset.get('responseTemplates')!r} -- "
        f"the custom response templates must not survive the reset"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
