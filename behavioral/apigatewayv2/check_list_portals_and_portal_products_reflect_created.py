"""list-portals-and-portal-products-reflect-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-portals-and-portal-products-reflect-created"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPortals and ListPortalProducts immediately reflect newly created
    resources and stop listing them after the corresponding delete."""
    apigw = ctx.client("apigatewayv2")

    portal_content = {
        "DisplayName": ctx.unique_name("sim2real-portal-")[:255],
        "Theme": {
            "CustomColors": {
                "AccentColor": "#112233",
                "BackgroundColor": "#FFFFFF",
                "ErrorValidationColor": "#FF0000",
                "HeaderColor": "#000000",
                "NavigationColor": "#222222",
                "TextColor": "#333333",
            }
        },
    }
    portal = apigw.create_portal(
        Authorization={"None": {}},
        EndpointConfiguration={"None": {}},
        PortalContent=portal_content,
        Tags={"environment": "test", "owner": "test"},
    )
    portal_id = portal["PortalId"]
    ctx.on_cleanup(lambda: _safe_delete_portal(apigw, portal_id))

    portal_items = _poll_until(
        lambda: _list_all(apigw.list_portals),
        lambda items: any(p["PortalId"] == portal_id for p in items),
        timeout_s=20,
    )
    assert any(p["PortalId"] == portal_id for p in portal_items), (
        f"ListPortals never showed created portal {portal_id} among {[p['PortalId'] for p in portal_items]}"
    )

    apigw.delete_portal(PortalId=portal_id)
    portal_items_after = _poll_until(
        lambda: _list_all(apigw.list_portals),
        lambda items: not any(p["PortalId"] == portal_id for p in items),
        timeout_s=20,
    )
    assert not any(p["PortalId"] == portal_id for p in portal_items_after), (
        "ListPortals still lists the portal after DeletePortal"
    )

    product = apigw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-product-"),
        Tags={"environment": "test", "owner": "test"},
    )
    product_id = product["PortalProductId"]
    ctx.on_cleanup(lambda: _safe_delete_product(apigw, product_id))

    product_items = _poll_until(
        lambda: _list_all(apigw.list_portal_products),
        lambda items: any(p["PortalProductId"] == product_id for p in items),
        timeout_s=20,
    )
    assert any(p["PortalProductId"] == product_id for p in product_items), (
        f"ListPortalProducts never showed created product {product_id} among "
        f"{[p['PortalProductId'] for p in product_items]}"
    )

    apigw.delete_portal_product(PortalProductId=product_id)
    product_items_after = _poll_until(
        lambda: _list_all(apigw.list_portal_products),
        lambda items: not any(p["PortalProductId"] == product_id for p in items),
        timeout_s=20,
    )
    assert not any(p["PortalProductId"] == product_id for p in product_items_after), (
        "ListPortalProducts still lists the product after DeletePortalProduct"
    )


# ===== helpers (self-contained) =====
def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _list_all(call, **kwargs):
    items = []
    token = None
    for _ in range(50):
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = call(**params)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _safe_delete_portal(apigw, portal_id):
    try:
        apigw.delete_portal(PortalId=portal_id)
    except apigw.exceptions.BadRequestException:
        pass


def _safe_delete_product(apigw, product_id):
    try:
        apigw.delete_portal_product(PortalProductId=product_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
