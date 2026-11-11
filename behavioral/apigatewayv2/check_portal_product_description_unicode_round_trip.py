"""portal-product-description-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "portal-product-description-unicode-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-product"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A portal product created with unicode characters and emoji in its Description
    returns the exact same string via GetPortalProduct (no normalization, transliteration,
    or truncation)."""
    apigw = ctx.client("apigatewayv2")
    display_name = ctx.unique_name("sim2real-product-")
    description = "Caf\u00e9 \u2615 \u65e5\u672c\u8a9e \U0001f680 \u2014 mixed unicode + emoji \u4e2d\u6587"

    created = apigw.create_portal_product(
        DisplayName=display_name, Description=description, Tags=TAGS
    )
    product_id = created["PortalProductId"]
    ctx.on_cleanup(lambda: apigw.delete_portal_product(PortalProductId=product_id))

    assert created["Description"] == description, (
        f"expected {description!r}, got {created['Description']!r}"
    )

    fetched = apigw.get_portal_product(PortalProductId=product_id)
    assert fetched["Description"] == description, (
        f"expected {description!r}, got {fetched['Description']!r}"
    )
    assert fetched["DisplayName"] == display_name, (
        f"expected {display_name!r}, got {fetched['DisplayName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
