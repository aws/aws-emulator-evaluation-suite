"""gateway-response-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "gateway-response-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGatewayResponse -> Get -> Update -> Delete reverts to the default response."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-gwresp-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    default_before = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert default_before["defaultResponse"] is True, (
        f"expected a fresh REST API's DEFAULT_4XX to be uncustomized, got {default_before!r}"
    )

    put = apigw.put_gateway_response(
        restApiId=api_id, responseType="DEFAULT_4XX", statusCode="404",
        responseTemplates={"application/json": '{"message":"sim2real custom 4xx"}'},
    )
    ctx.on_cleanup(lambda: _safe_delete_response(apigw, api_id))
    assert put["defaultResponse"] is False, (
        f"expected PutGatewayResponse's own response to report defaultResponse=False, got {put!r}"
    )
    assert put["statusCode"] == "404", f"expected PutGatewayResponse to echo statusCode 404, got {put!r}"

    got = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert got["defaultResponse"] is False, (
        f"expected an independent GetGatewayResponse after Put to report defaultResponse=False, got {got!r}"
    )
    assert got["statusCode"] == "404", f"expected the independent read to see statusCode 404, got {got!r}"
    assert got["responseTemplates"]["application/json"] == '{"message":"sim2real custom 4xx"}', (
        f"expected the independent read to see the custom template, got {got!r}"
    )

    updated = apigw.update_gateway_response(
        restApiId=api_id, responseType="DEFAULT_4XX",
        patchOperations=[{"op": "replace", "path": "/statusCode", "value": "400"}],
    )
    assert updated["statusCode"] == "400", (
        f"expected UpdateGatewayResponse's own response to report statusCode 400, got {updated!r}"
    )

    got_after_update = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert got_after_update["statusCode"] == "400", (
        "expected an independent GetGatewayResponse after Update to reflect the patched "
        f"statusCode 400, got {got_after_update!r}"
    )
    assert got_after_update["responseTemplates"]["application/json"] == (
        '{"message":"sim2real custom 4xx"}'
    ), (
        "the patch replaces only statusCode, so the earlier custom template must survive "
        f"in an independent read, got {got_after_update!r}"
    )

    apigw.delete_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    after_delete = apigw.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    assert after_delete["defaultResponse"] is True, (
        f"expected DeleteGatewayResponse to fully revert DEFAULT_4XX to the built-in default, "
        f"got {after_delete!r}"
    )
    assert after_delete.get("statusCode") != "400", (
        f"the patched statusCode 400 must not survive the delete/reset, got {after_delete!r}"
    )
    assert (after_delete.get("responseTemplates") or {}).get("application/json") != (
        '{"message":"sim2real custom 4xx"}'
    ), f"the custom response template must not survive the delete/reset, got {after_delete!r}"


def _safe_delete_response(apigw, api_id: str) -> None:
    try:
        apigw.delete_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
