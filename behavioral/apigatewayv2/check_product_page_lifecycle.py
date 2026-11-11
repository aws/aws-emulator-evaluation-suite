"""product-page-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "product-page-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProductPage under a portal product is gettable, UpdateProductPage mutates content, DeleteProductPage -> NotFoundException."""
    apigw = ctx.client("apigatewayv2")

    product_id = apigw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-pp-prod-"),
        Tags={"sim2real": "product-page-lifecycle"},
    )["PortalProductId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_portal_product(PortalProductId=product_id))
    )

    created = apigw.create_product_page(
        PortalProductId=product_id, DisplayContent={"Title": "Getting started", "Body": "Initial body"}
    )
    page_id = created["ProductPageId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id)
        )
    )
    assert created["DisplayContent"]["Title"] == "Getting started", (
        f"expected created title 'Getting started', got {created['DisplayContent']['Title']!r}"
    )

    got = apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    assert got["DisplayContent"]["Title"] == "Getting started", (
        f"expected fetched title 'Getting started', got {got['DisplayContent']['Title']!r}"
    )
    assert got["DisplayContent"]["Body"] == "Initial body", (
        f"expected fetched body 'Initial body', got {got['DisplayContent']['Body']!r}"
    )

    updated = apigw.update_product_page(
        PortalProductId=product_id,
        ProductPageId=page_id,
        DisplayContent={"Title": "Getting started v2", "Body": "Updated body"},
    )
    assert updated["DisplayContent"]["Title"] == "Getting started v2", (
        f"expected updated title 'Getting started v2', got {updated['DisplayContent']['Title']!r}"
    )
    assert updated["DisplayContent"]["Body"] == "Updated body", (
        f"expected updated body 'Updated body', got {updated['DisplayContent']['Body']!r}"
    )

    got2 = apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    assert got2["DisplayContent"]["Title"] == "Getting started v2", (
        f"expected persisted title 'Getting started v2', got {got2['DisplayContent']['Title']!r}"
    )
    assert got2["DisplayContent"]["Body"] == "Updated body", (
        f"expected persisted body 'Updated body', got {got2['DisplayContent']['Body']!r}"
    )

    apigw.delete_product_page(PortalProductId=product_id, ProductPageId=page_id)
    err = _error(
        lambda: apigw.get_product_page(PortalProductId=product_id, ProductPageId=page_id)
    )
    assert err == ("NotFoundException", "ProductPage not found"), (
        f"expected NotFoundException reading a deleted product page, got {err!r}"
    )

    mutate_err = _error(
        lambda: apigw.update_product_page(
            PortalProductId=product_id,
            ProductPageId=page_id,
            DisplayContent={"Title": "Should not apply", "Body": "Should not apply"},
        )
    )
    assert mutate_err == ("NotFoundException", "ProductPage not found"), (
        f"expected NotFoundException mutating a deleted product page, got {mutate_err!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
