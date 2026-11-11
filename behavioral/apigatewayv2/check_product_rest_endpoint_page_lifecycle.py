"""product-rest-endpoint-page-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "product-rest-endpoint-page-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProductRestEndpointPage is gettable, UpdateProductRestEndpointPage mutates TryItState, Delete -> NotFoundException."""
    apigwv1 = ctx.client("apigateway")
    apigwv2 = ctx.client("apigatewayv2")

    rest_api_id, stage_name = _create_mock_rest_api(ctx, apigwv1)

    product_id = apigwv2.create_portal_product(DisplayName=ctx.unique_name("sim2real-rep-prod-"))[
        "PortalProductId"
    ]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigwv2.delete_portal_product(PortalProductId=product_id))
    )

    identifier = {
        "IdentifierParts": {
            "RestApiId": rest_api_id,
            "Stage": stage_name,
            "Method": "GET",
            "Path": "/",
        }
    }
    created = apigwv2.create_product_rest_endpoint_page(
        PortalProductId=product_id, RestEndpointIdentifier=identifier
    )
    page_id = created["ProductRestEndpointPageId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigwv2.delete_product_rest_endpoint_page(
                PortalProductId=product_id, ProductRestEndpointPageId=page_id
            )
        )
    )
    initial_try_it_state = created["TryItState"]

    status = _poll_until(
        lambda: apigwv2.get_product_rest_endpoint_page(
            PortalProductId=product_id, ProductRestEndpointPageId=page_id
        )["Status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert status == "AVAILABLE", f"product REST endpoint page reached {status}, expected AVAILABLE"

    target_state = "DISABLED" if initial_try_it_state == "ENABLED" else "ENABLED"
    updated = apigwv2.update_product_rest_endpoint_page(
        PortalProductId=product_id, ProductRestEndpointPageId=page_id, TryItState=target_state
    )
    assert updated["TryItState"] == target_state, (
        f"expected update to set TryItState={target_state!r}, got {updated['TryItState']!r}"
    )
    assert updated["TryItState"] != initial_try_it_state, (
        f"expected TryItState to change from {initial_try_it_state!r}, still {updated['TryItState']!r}"
    )

    got2 = apigwv2.get_product_rest_endpoint_page(
        PortalProductId=product_id, ProductRestEndpointPageId=page_id
    )
    assert got2["TryItState"] == target_state, (
        f"expected independent read to see TryItState={target_state!r}, got {got2['TryItState']!r}"
    )

    apigwv2.delete_product_rest_endpoint_page(
        PortalProductId=product_id, ProductRestEndpointPageId=page_id
    )
    err = _error(
        lambda: apigwv2.get_product_rest_endpoint_page(
            PortalProductId=product_id, ProductRestEndpointPageId=page_id
        )
    )
    assert err == ("NotFoundException", "ProductRestEndpointPage not found"), (
        f"expected NotFoundException reading a deleted product REST endpoint page, got {err!r}"
    )


def _create_mock_rest_api(ctx, apigwv1) -> tuple[str, str]:
    rest_api_id = apigwv1.create_rest_api(name=ctx.unique_name("sim2real-rep-restapi-"))["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigwv1.delete_rest_api(restApiId=rest_api_id)))

    root_id = next(
        item["id"]
        for item in apigwv1.get_resources(restApiId=rest_api_id)["items"]
        if item["path"] == "/"
    )
    apigwv1.put_method(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigwv1.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigwv1.put_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigwv1.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "prod"
    apigwv1.create_deployment(restApiId=rest_api_id, stageName=stage_name)
    return rest_api_id, stage_name


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
