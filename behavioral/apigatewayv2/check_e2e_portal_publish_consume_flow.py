"""e2e-portal-publish-consume-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-portal-publish-consume-flow"
GROUP = "e2e"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A portal built from a portal product + product page goes preview -> publish, and GetPortal
    reports a PUBLISHED state with the product included, a populated default domain and a
    LastPublished stamp."""
    apigw = ctx.client("apigatewayv2")

    try:
        product = apigw.create_portal_product(
            DisplayName=ctx.unique_name("sim2real-behav-product-"),
            Tags={"sim2real:managed": "true"},
        )
    except apigw.exceptions.AccessDeniedException as exc:
        raise AssertionError(
            "this account/region is not enrolled in the API Gateway portals feature "
            "(CreatePortalProduct returned AccessDeniedException)"
        ) from exc
    product_id = product["PortalProductId"]
    product_arn = product["PortalProductArn"]
    ctx.on_cleanup(lambda: apigw.delete_portal_product(PortalProductId=product_id))

    page = apigw.create_product_page(
        PortalProductId=product_id,
        DisplayContent={"Title": "Getting started", "Body": "sim2real behavioral test product page"},
    )
    page_id = page["ProductPageId"]
    ctx.on_cleanup(lambda: apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id))

    theme = {
        "CustomColors": {
            "ErrorValidationColor": "#FF0000",
            "HeaderColor": "#000000",
            "BackgroundColor": "#FFFFFF",
            "AccentColor": "#0000FF",
            "NavigationColor": "#111111",
            "TextColor": "#222222",
        }
    }
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Description": "sim2real behavioral test portal",
            "Theme": theme,
        },
        IncludedPortalProductArns=[product_arn],
        Tags={"sim2real:managed": "true"},
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _disable_and_delete_portal(ctx, portal_id))

    apigw.preview_portal(PortalId=portal_id)
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id).get("Preview", {}).get("PreviewStatus"),
        lambda status: status == "PREVIEW_READY",
        timeout_s=180.0,
        interval_s=5.0,
        description="portal preview to become PREVIEW_READY",
    )

    apigw.publish_portal(PortalId=portal_id)
    published = _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id),
        lambda resp: resp.get("PublishStatus") == "PUBLISHED",
        timeout_s=600.0,
        interval_s=10.0,
        description="portal publish to reach PUBLISHED",
    )

    assert published["PublishStatus"] == "PUBLISHED"
    assert product_arn in published["IncludedPortalProductArns"]
    endpoint_cfg = published["EndpointConfiguration"]
    default_domain = endpoint_cfg.get("PortalDefaultDomainName")
    assert default_domain
    assert published.get("LastPublished")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str) -> Any:
    deadline = time.monotonic() + timeout_s
    last_value = None
    while time.monotonic() < deadline:
        last_value = probe()
        if predicate(last_value):
            return last_value
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last_value={last_value!r})")


def _disable_and_delete_portal(ctx, portal_id: str) -> None:
    apigw = ctx.client("apigatewayv2")
    try:
        apigw.disable_portal(PortalId=portal_id)
    except apigw.exceptions.ConflictException:
        pass
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id).get("PublishStatus"),
        lambda status: status == "DISABLED",
        timeout_s=900.0,
        interval_s=15.0,
        description="portal disable to reach DISABLED",
    )
    apigw.delete_portal(PortalId=portal_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
