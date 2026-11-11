"""portal-product-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-product-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePortalProduct is gettable, UpdatePortalProduct mutates DisplayName, DeletePortalProduct ->
    NotFoundException on both a subsequent read and a subsequent mutation of the dead id."""
    apigw = ctx.client("apigatewayv2")

    display_name = ctx.unique_name("sim2real-pprod-")
    created = apigw.create_portal_product(DisplayName=display_name, Description="initial description")
    product_id = created["PortalProductId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_portal_product(PortalProductId=product_id))
    )
    assert created["DisplayName"] == display_name, (
        f"create_portal_product echoed DisplayName={created['DisplayName']!r}, expected {display_name!r}"
    )

    got = apigw.get_portal_product(PortalProductId=product_id)
    assert got["DisplayName"] == display_name, (
        f"get after create returned DisplayName={got['DisplayName']!r}, expected {display_name!r}"
    )
    assert got["Description"] == "initial description", (
        f"get after create returned Description={got['Description']!r}, expected 'initial description'"
    )

    new_display_name = ctx.unique_name("sim2real-pprod-upd-")
    updated = apigw.update_portal_product(
        PortalProductId=product_id, DisplayName=new_display_name, Description="updated description"
    )
    assert updated["DisplayName"] == new_display_name, (
        f"update_portal_product echoed DisplayName={updated['DisplayName']!r}, expected {new_display_name!r}"
    )
    assert updated["Description"] == "updated description", (
        f"update_portal_product echoed Description={updated['Description']!r}, expected 'updated description'"
    )

    got2 = apigw.get_portal_product(PortalProductId=product_id)
    assert got2["DisplayName"] == new_display_name, (
        f"get after update returned DisplayName={got2['DisplayName']!r}, expected {new_display_name!r}"
    )
    assert got2["Description"] == "updated description", (
        f"get after update returned Description={got2['Description']!r}, expected 'updated description'"
    )

    apigw.delete_portal_product(PortalProductId=product_id)

    not_found = ("NotFoundException", f"Product not found in account {ctx.account} with id {product_id}")
    read_err = _error(lambda: apigw.get_portal_product(PortalProductId=product_id))
    assert read_err == not_found, f"get after delete returned {read_err!r}, expected {not_found!r}"

    mutate_err = _error(
        lambda: apigw.update_portal_product(PortalProductId=product_id, DisplayName="post-delete-mutation")
    )
    assert mutate_err == not_found, f"update after delete returned {mutate_err!r}, expected {not_found!r}"


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
