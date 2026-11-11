"""op-contract-describeAvailabilityZones."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeAvailabilityZones"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAvailabilityZones returns the region's real zone shape and rejects unknown filters."""
    ec2 = ctx.client("ec2")

    # success path: every region has at least one Availability Zone, with a well-defined shape
    response = ec2.describe_availability_zones()
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200, got {status!r}"
    zones = response["AvailabilityZones"]
    assert isinstance(zones, list) and len(zones) > 0, "expected at least one Availability Zone"
    zone = zones[0]
    for field in ("ZoneName", "ZoneId", "State", "RegionName"):
        assert field in zone, f"missing expected field {field!r} on AvailabilityZone"
    assert zone["RegionName"] == ctx.region, (
        f"expected RegionName {ctx.region!r}, got {zone['RegionName']!r}"
    )

    # error boundary: an unrecognized filter name is rejected with InvalidParameterValue
    bogus_filter = "sim2real-not-a-real-filter"
    code, message = _error(
        lambda: ec2.describe_availability_zones(
            Filters=[{"Name": bogus_filter, "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = f"The filter '{bogus_filter}' is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
