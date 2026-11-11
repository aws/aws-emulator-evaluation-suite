"""portal-product-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "portal-product-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePortalProduct -> GetPortalProduct returns it -> UpdatePortalProduct mutates fields ->
    DeletePortalProduct -> GetPortalProduct returns NotFoundException and a mutation on the dead id
    also returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")
    display_name = ctx.unique_name("sim2real-behav-product-")

    created = apigw.create_portal_product(
        DisplayName=display_name, Description="initial", Tags={"sim2real": CHECK}
    )
    product_id = created["PortalProductId"]
    assert created["DisplayName"] == display_name, (
        f"expected created DisplayName={display_name!r}, got {created['DisplayName']!r}"
    )

    def _cleanup():
        try:
            apigw.delete_portal_product(PortalProductId=product_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    got = apigw.get_portal_product(PortalProductId=product_id)
    assert got["DisplayName"] == display_name and got["Description"] == "initial", (
        f"expected DisplayName={display_name!r} Description='initial', "
        f"got DisplayName={got['DisplayName']!r} Description={got['Description']!r}"
    )

    new_name = f"{display_name}-v2"
    updated = apigw.update_portal_product(
        PortalProductId=product_id, DisplayName=new_name, Description="updated"
    )
    assert updated["DisplayName"] == new_name and updated["Description"] == "updated", (
        f"expected DisplayName={new_name!r} Description='updated', "
        f"got DisplayName={updated['DisplayName']!r} Description={updated['Description']!r}"
    )

    got2 = apigw.get_portal_product(PortalProductId=product_id)
    assert got2["DisplayName"] == new_name and got2["Description"] == "updated", (
        f"expected DisplayName={new_name!r} Description='updated' after update, "
        f"got DisplayName={got2['DisplayName']!r} Description={got2['Description']!r}"
    )

    apigw.delete_portal_product(PortalProductId=product_id)

    not_found = ("NotFoundException", f"Product not found in account {ctx.account} with id {product_id}")
    err = _error(lambda: apigw.get_portal_product(PortalProductId=product_id))
    assert err == not_found, f"expected {not_found!r} reading the deleted product, got {err!r}"

    mutate_err = _error(
        lambda: apigw.update_portal_product(PortalProductId=product_id, DisplayName="dead-id-probe")
    )
    assert mutate_err == not_found, f"expected {not_found!r} mutating the deleted product, got {mutate_err!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
