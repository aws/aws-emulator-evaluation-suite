"""site-address-not-configured-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "site-address-not-configured-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSiteAddress for SHIPPING_ADDRESS on a site with only an operating address fails with NotFoundException
    and the message "SHIPPING_ADDRESS not found for SiteId=<id>", while OPERATING_ADDRESS succeeds; after
    UpdateSiteAddress sets it, the same call returns the new address.
    """
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
        OperatingAddress=_address("Seattle", "WA", "98144"),
        # Deliberately no ShippingAddress.
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    # Positive control: the address type that WAS set is retrievable on the same site.
    got_operating = outposts.get_site_address(SiteId=site_id, AddressType="OPERATING_ADDRESS")
    assert got_operating["Address"]["City"] == "Seattle", (
        f"expected the just-created OperatingAddress to read back with City=Seattle, "
        f"got {got_operating['Address']!r}"
    )

    code, message = _error(
        lambda: outposts.get_site_address(SiteId=site_id, AddressType="SHIPPING_ADDRESS")
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a never-configured ShippingAddress, got {code!r}"
    )
    assert message == f"SHIPPING_ADDRESS not found for SiteId={site_id}", (
        f"unexpected GetSiteAddress message: {message!r}"
    )

    # Restore leg: configuring the missing address makes the identical call succeed.
    outposts.update_site_address(
        SiteId=site_id,
        AddressType="SHIPPING_ADDRESS",
        Address=_address("Portland", "OR", "97201"),
    )
    got_shipping = outposts.get_site_address(SiteId=site_id, AddressType="SHIPPING_ADDRESS")
    assert got_shipping["Address"]["City"] == "Portland", (
        f"expected the newly-configured ShippingAddress to read back with City=Portland "
        f"after UpdateSiteAddress, got {got_shipping['Address']!r}"
    )


def _address(city: str, state: str, postal: str) -> dict:
    return {
        "ContactName": "Jane Doe",
        "ContactPhoneNumber": "+61255500000",
        "AddressLine1": "123 Any Street",
        "City": city,
        "StateOrRegion": state,
        "PostalCode": postal,
        "CountryCode": "US",
    }


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
