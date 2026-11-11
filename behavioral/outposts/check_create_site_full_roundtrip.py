"""create-site-full-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-site-full-roundtrip"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSite persists name/description/notes/tags/address/rack properties, visible via GetSite/GetSiteAddress."""
    outposts = ctx.client("outposts")
    name = ctx.unique_name("sim2real-outposts-site-")
    operating = _address("Seattle", "WA", "98144")
    shipping = _address("Portland", "OR", "97201")
    resp = outposts.create_site(
        Name=name,
        Description="behavioral fidelity test site",
        Notes="created by automated check, safe to delete",
        Tags={"sim2real-check": "create-site-full-roundtrip"},
        OperatingAddress=operating,
        ShippingAddress=shipping,
        RackPhysicalProperties=_rack_properties(),
    )
    site_id = resp["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    assert resp["Site"]["Name"] == name, f"create response name: expected {name!r}, got {resp['Site']['Name']!r}"
    assert resp["Site"]["SiteArn"].endswith(f"site/{site_id}"), (
        f"create response arn: expected suffix site/{site_id}, got {resp['Site']['SiteArn']!r}"
    )

    got = outposts.get_site(SiteId=site_id)["Site"]
    assert got["SiteId"] == site_id, f"SiteId: expected {site_id!r}, got {got['SiteId']!r}"
    assert got["Name"] == name, f"Name: expected {name!r}, got {got['Name']!r}"
    assert got["Description"] == "behavioral fidelity test site", (
        f"Description: expected 'behavioral fidelity test site', got {got['Description']!r}"
    )
    assert got["Notes"] == "created by automated check, safe to delete", (
        f"Notes: expected 'created by automated check, safe to delete', got {got['Notes']!r}"
    )
    assert got["Tags"] == {"sim2real-check": "create-site-full-roundtrip"}, (
        f"Tags: expected create-site-full-roundtrip tag, got {got['Tags']!r}"
    )
    assert got["OperatingAddressCountryCode"] == "US", (
        f"OperatingAddressCountryCode: expected 'US', got {got['OperatingAddressCountryCode']!r}"
    )
    assert got["OperatingAddressStateOrRegion"] == "WA", (
        f"OperatingAddressStateOrRegion: expected 'WA', got {got['OperatingAddressStateOrRegion']!r}"
    )
    assert got["OperatingAddressCity"] == "Seattle", (
        f"OperatingAddressCity: expected 'Seattle', got {got['OperatingAddressCity']!r}"
    )

    rack = got["RackPhysicalProperties"]
    for key, value in _rack_properties().items():
        assert rack[key] == value, f"RackPhysicalProperties.{key}: expected {value!r}, got {rack.get(key)!r}"

    got_operating = outposts.get_site_address(SiteId=site_id, AddressType="OPERATING_ADDRESS")["Address"]
    for key, value in operating.items():
        assert got_operating[key] == value, (
            f"GetSiteAddress(OPERATING_ADDRESS).{key}: expected {value!r}, got {got_operating.get(key)!r}"
        )

    got_shipping = outposts.get_site_address(SiteId=site_id, AddressType="SHIPPING_ADDRESS")["Address"]
    for key, value in shipping.items():
        assert got_shipping[key] == value, (
            f"GetSiteAddress(SHIPPING_ADDRESS).{key}: expected {value!r}, got {got_shipping.get(key)!r}"
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


def _rack_properties() -> dict:
    return {
        "PowerDrawKva": "POWER_15_KVA",
        "PowerPhase": "SINGLE_PHASE",
        "PowerConnector": "L6_30P",
        "PowerFeedDrop": "ABOVE_RACK",
        "UplinkGbps": "UPLINK_1G",
        "UplinkCount": "UPLINK_COUNT_1",
        "FiberOpticCableType": "SINGLE_MODE",
        "OpticalStandard": "OPTIC_1000BASE_LX",
        "MaximumSupportedWeightLbs": "NO_LIMIT",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
