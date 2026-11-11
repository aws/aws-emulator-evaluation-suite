"""create-site-invalid-country-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-site-invalid-country-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSite with a 3-letter CountryCode fails with ValidationException and the two exact constraint
    messages, and ListSites never shows the attempted name, while the same request with "US" succeeds.
    """
    outposts = ctx.client("outposts")

    bad_name = ctx.unique_name("sim2real-outposts-site-bad-")
    code, message = _error(
        lambda: outposts.create_site(
            Name=bad_name,
            OperatingAddress=_address("USA"),  # CountryCode must match ^[A-Z]{2}$
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # AWS lists the two constraint violations in either order.
    pattern = (
        "Value at 'operatingAddress.countryCode' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^[A-Z]{2}$"
    )
    length = (
        "Value at 'operatingAddress.countryCode' failed to satisfy constraint: "
        "Member must have length less than or equal to 2"
    )
    first, second = (length, pattern) if message.startswith(f"2 validation errors detected: {length}") else (pattern, length)
    expected = f"2 validation errors detected: {first}; {second}"
    assert message == expected, f"unexpected CreateSite validation message: {message!r}"

    # Effect absent: the rejected CreateSite never created a Site under this name.
    names = {site["Name"] for site in _list_all_sites(outposts)}
    assert bad_name not in names, (
        f"{bad_name!r} unexpectedly present in ListSites after a rejected CreateSite"
    )

    # Positive control: a valid 2-letter CountryCode is accepted.
    good_name = ctx.unique_name("sim2real-outposts-site-good-")
    site_id = outposts.create_site(
        Name=good_name,
        OperatingAddress=_address("US"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))
    got = outposts.get_site(SiteId=site_id)["Site"]
    assert got["OperatingAddressCountryCode"] == "US", (
        f"expected OperatingAddressCountryCode 'US', got {got.get('OperatingAddressCountryCode')!r}"
    )


def _address(country_code: str) -> dict:
    return {
        "ContactName": "Jane Doe",
        "ContactPhoneNumber": "+61255500000",
        "AddressLine1": "123 Any Street",
        "City": "Seattle",
        "StateOrRegion": "WA",
        "PostalCode": "98144",
        "CountryCode": country_code,
    }


def _list_all_sites(outposts):
    sites = []
    for page in outposts.get_paginator("list_sites").paginate():
        sites.extend(page.get("Sites", []))
    return sites


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
