"""spot-price-history-repeat-calls-return-stable-price."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "spot-price-history-repeat-calls-return-stable-price"
GROUP = "spot-pricing"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two back-to-back DescribeSpotPriceHistory calls for m5.large Linux/UNIX in one AZ return the same
    latest Timestamp and SpotPrice."""
    ec2 = ctx.client("ec2")

    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["m5.large"]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers m5.large; offerings were {sorted(offered)!r}"
    az = usable[0]

    kwargs = dict(
        InstanceTypes=["m5.large"], ProductDescriptions=["Linux/UNIX"],
        AvailabilityZone=az, MaxResults=1,
    )
    first = ec2.describe_spot_price_history(**kwargs)["SpotPriceHistory"]
    second = ec2.describe_spot_price_history(**kwargs)["SpotPriceHistory"]

    assert first, f"no spot price history for m5.large/Linux-UNIX/{az}"
    assert second, f"second call returned nothing for m5.large/Linux-UNIX/{az}"
    assert first[0]["Timestamp"] == second[0]["Timestamp"], (
        f"two back-to-back calls disagreed on the latest price's timestamp: "
        f"{first[0]['Timestamp']!r} vs {second[0]['Timestamp']!r}"
    )
    assert first[0]["SpotPrice"] == second[0]["SpotPrice"], (
        f"two back-to-back calls for the SAME latest price point returned different prices: "
        f"{first[0]['SpotPrice']!r} vs {second[0]['SpotPrice']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
