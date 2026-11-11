"""geolocation-catalog-and-unknown-location."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "geolocation-catalog-and-unknown-location"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGeoLocations returns the supported catalog; GetGeoLocation resolves a known continent and rejects an unknown country."""
    r53 = ctx.client("route53")
    listed = r53.list_geo_locations()
    assert listed["GeoLocationDetailsList"], "expected a non-empty geo location catalog"

    eu = r53.get_geo_location(ContinentCode="EU")["GeoLocationDetails"]
    assert eu["ContinentCode"] == "EU", eu
    assert eu.get("ContinentName"), eu

    us = r53.get_geo_location(CountryCode="US")["GeoLocationDetails"]
    assert us["CountryCode"] == "US", us

    # ZZ is not an assigned country code
    err = _client_error(lambda: r53.get_geo_location(CountryCode="ZZ"))
    assert err["Code"] == "NoSuchGeoLocation", f"expected NoSuchGeoLocation, got {err}"
    assert err["Message"] == "No geo location for location: [country = ZZ]", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
