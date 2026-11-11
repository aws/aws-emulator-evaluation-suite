"""update-site-address-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-site-address-persists"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSiteAddress replaces the operating address and GetSiteAddress returns the new value."""
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        OperatingAddress=_address("Seattle", "WA", "98144"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    new_address = _address("Portland", "OR", "97201")
    outposts.update_site_address(SiteId=site_id, AddressType="OPERATING_ADDRESS", Address=new_address)

    got = outposts.get_site_address(SiteId=site_id, AddressType="OPERATING_ADDRESS")
    assert got["Address"]["City"] == "Portland"
    assert got["Address"]["StateOrRegion"] == "OR"
    assert got["Address"]["PostalCode"] == "97201"

    site = outposts.get_site(SiteId=site_id)["Site"]
    assert site["OperatingAddressCity"] == "Portland"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
