"""op-contract-allocateHosts."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-allocateHosts"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AllocateHosts: a real Dedicated Host allocation returns a well-formed
    host ID that DescribeHosts can see; an unknown Availability Zone name is
    a distinct error boundary."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[
            {"Name": "region-name", "Values": [ctx.region]},
            {"Name": "state", "Values": ["available"]},
        ]
    )["AvailabilityZones"][0]["ZoneName"]

    try:
        alloc = ec2.allocate_hosts(
            AvailabilityZone=az,
            InstanceFamily="c5",
            Quantity=1,
            AutoPlacement="off",
            TagSpecifications=[
                {
                    "ResourceType": "dedicated-host",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-host-")}],
                }
            ],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("InsufficientHostCapacity", "InsufficientCapacityOnHost", "Unsupported"):
            raise AssertionError(f"no dedicated-host capacity available: {code}") from exc
        raise

    host_ids = alloc["HostIds"]
    assert len(host_ids) == 1, host_ids
    host_id = host_ids[0]
    ctx.on_cleanup(lambda: ec2.release_hosts(HostIds=[host_id]))
    assert host_id.startswith("h-"), host_id

    described = ec2.describe_hosts(HostIds=[host_id])["Hosts"][0]
    assert described["AvailabilityZone"] == az, f"expected AZ {az!r}, got {described['AvailabilityZone']!r}"
    assert described["State"] in ("available", "pending"), f"unexpected host state: {described['State']!r}"

    # distinct error boundary: an Availability Zone that does not exist is rejected with
    # the operation's generic "InvalidRequest" error rather than InvalidParameterValue.
    code2 = _error_code(
        lambda: ec2.allocate_hosts(
            AvailabilityZone=f"{ctx.region}-notreal", InstanceFamily="c5", Quantity=1
        )
    )
    assert code2 == "InvalidRequest", f"expected InvalidRequest, got {code2!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
