"""product-page-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "product-page-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProductPage under a portal product -> GetProductPage returns it -> UpdateProductPage
    mutates content -> DeleteProductPage -> GetProductPage returns NotFoundException -> a further
    UpdateProductPage on the deleted page id also returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")
    product_id = _create_portal_product(ctx, apigw)

    content = {"Title": "Overview", "Body": "Initial body content."}
    created = apigw.create_product_page(PortalProductId=product_id, DisplayContent=content)
    page_id = created["ProductPageId"]
    assert created["DisplayContent"] == content, (
        f"create_product_page returned {created['DisplayContent']!r}, expected {content!r}"
    )

    def _cleanup():
        try:
            apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    got = apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    assert got["DisplayContent"] == content, (
        f"get_product_page returned {got['DisplayContent']!r}, expected {content!r}"
    )

    new_content = {"Title": "Overview v2", "Body": "Updated body content."}
    updated = apigw.update_product_page(
        PortalProductId=product_id, ProductPageId=page_id, DisplayContent=new_content
    )
    assert updated["DisplayContent"] == new_content, (
        f"update_product_page returned {updated['DisplayContent']!r}, expected {new_content!r}"
    )

    got2 = apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    assert got2["DisplayContent"] == new_content, (
        f"get_product_page after update returned {got2['DisplayContent']!r}, expected {new_content!r}"
    )

    apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id)

    err = _error(
        lambda: apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    )
    assert err == ("NotFoundException", "ProductPage not found"), (
        f"get_product_page after delete returned {err!r}, expected NotFoundException"
    )

    mutate_err = _error(
        lambda: apigw.update_product_page(
            PortalProductId=product_id, ProductPageId=page_id, DisplayContent=new_content
        )
    )
    assert mutate_err == ("NotFoundException", "ProductPage not found"), (
        f"update_product_page on a deleted page returned {mutate_err!r}, expected NotFoundException"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_portal_product(ctx, apigw):
    product_id = apigw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-behav-product-"), Tags=TAGS
    )["PortalProductId"]
    def _cleanup():
        try:
            apigw.delete_portal_product(PortalProductId=product_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)
    return product_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
