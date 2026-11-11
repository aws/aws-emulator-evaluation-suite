"""e2e-portal-product-publish-flow."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-portal-product-publish-flow"
GROUP = "e2e"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Publishing a Portal with an attached PortalProduct/ProductPage makes the portal's
    default domain start serving content (HTTP 200); disabling it stops serving it."""
    apigw = ctx.client("apigatewayv2")

    product = apigw.create_portal_product(DisplayName=ctx.unique_name("sim2real-behav-prod-"))
    product_id = product["PortalProductId"]
    ctx.on_cleanup(lambda: apigw.delete_portal_product(PortalProductId=product_id))

    page = apigw.create_product_page(
        PortalProductId=product_id,
        DisplayContent={"Title": ctx.unique_name("sim2real-behav-title-"), "Body": "hello from sim2real"},
    )
    page_id = page["ProductPageId"]
    ctx.on_cleanup(
        lambda: apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id)
    )

    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent={
            "DisplayName": ctx.unique_name("sim2real-behav-portal-"),
            "Theme": {
                "CustomColors": {
                    "AccentColor": "#112233",
                    "BackgroundColor": "#ffffff",
                    "ErrorValidationColor": "#ff0000",
                    "HeaderColor": "#000000",
                    "NavigationColor": "#333333",
                    "TextColor": "#111111",
                }
            },
        },
        IncludedPortalProductArns=[product["PortalProductArn"]],
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _disable_and_delete_portal(apigw, portal_id))

    domain = portal["EndpointConfiguration"]["PortalDefaultDomainName"]
    assert domain, f"expected CreatePortal to assign a default domain, got {domain!r}"

    apigw.publish_portal(PortalId=portal_id, Description="sim2real behavioral check publish")
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "PUBLISHED",
        timeout_s=600,
        interval_s=15,
    )

    status = _poll_until(
        lambda: _fetch_status(ctx, domain),
        lambda s: s is not None,
        timeout_s=600,
        interval_s=15,
    )
    assert status == 200, f"expected published portal to serve content, got HTTP {status}"

    apigw.disable_portal(PortalId=portal_id)
    _poll_until(
        lambda: apigw.get_portal(PortalId=portal_id)["PublishStatus"],
        lambda s: s == "DISABLED",
        timeout_s=600,
        interval_s=15,
    )

    status_after = _poll_until(
        lambda: _fetch_status(ctx, domain),
        lambda s: s != 200,
        timeout_s=180,
        interval_s=10,
    )
    assert status_after != 200, "expected disabled portal to stop serving content"


# ===== helpers =====
def _disable_and_delete_portal(apigw, portal_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_portal(PortalId=portal_id)
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NotFoundException":
            return
        if code not in ("ConflictException", "BadRequestException"):  # still published: disable first
            raise
    try:
        apigw.disable_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            status = apigw.get_portal(PortalId=portal_id)["PublishStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if status in ("DISABLED", "DISABLE_FAILED"):
            break
        time.sleep(2)
    try:
        apigw.delete_portal(PortalId=portal_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _fetch_status(ctx, host: str, path: str = "/", timeout: float = 15.0):
    req = urllib.request.Request(f"{ctx.endpoint_url(host)}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
