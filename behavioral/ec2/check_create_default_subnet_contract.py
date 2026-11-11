"""create-default-subnet-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-default-subnet-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-default-subnets")
def run(ctx) -> None:
    """CreateDefaultSubnet for an AZ whose baseline default subnet exists is rejected with
    DefaultSubnetAlreadyExistsInAvailabilityZone naming that subnet, confirmed by an independent
    DescribeSubnets read; a bogus availability zone is always rejected."""
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available availability zones in this region")
    az = azs[0]["ZoneName"]

    existing = ec2.describe_subnets(
        Filters=[
            {"Name": "availability-zone", "Values": [az]},
            {"Name": "default-for-az", "Values": ["true"]},
        ]
    )["Subnets"]
    assert len(existing) == 1, (
        f"the account baseline holds exactly one default subnet in {az!r}, found "
        f"{[s['SubnetId'] for s in existing]!r}"
    )
    baseline_id = existing[0]["SubnetId"]

    try:
        resp = ec2.create_default_subnet(AvailabilityZone=az)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        created = resp["Subnet"]["SubnetId"]
        if created != baseline_id:
            ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=created))
        raise AssertionError(
            f"CreateDefaultSubnet SUCCEEDED in {az!r} while {baseline_id!r} is its default subnet, "
            f"returning {resp['Subnet']!r}"
        )
    assert code == "DefaultSubnetAlreadyExistsInAvailabilityZone", (
        f"unexpected CreateDefaultSubnet rejection code {code!r} ({message})"
    )
    assert message == f"'{baseline_id}' is already the default subnet in {az}.", (
        f"unexpected {code} message {message!r}"
    )
    # The rejected call left the AZ's one default subnet in place.
    after = ec2.describe_subnets(
        Filters=[
            {"Name": "availability-zone", "Values": [az]},
            {"Name": "default-for-az", "Values": ["true"]},
        ]
    )["Subnets"]
    assert [s["SubnetId"] for s in after] == [baseline_id], (
        f"expected {az!r} to keep exactly the default subnet {baseline_id!r}, found "
        f"{[s['SubnetId'] for s in after]!r}"
    )

    # Distinct error boundary: an availability zone that cannot exist must be
    # rejected regardless of default-subnet state.
    code2, message2 = _error_detail(
        lambda: ec2.create_default_subnet(AvailabilityZone="not-a-real-az-1"),
        lambda resp: ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=resp["Subnet"]["SubnetId"])),
    )
    assert code2 == "InvalidAvailabilityZone", (
        f"expected CreateDefaultSubnet to reject a bogus availability zone with "
        f"InvalidAvailabilityZone, got {code2!r} ({message2})"
    )
    assert message2 == (
        "Value (not-a-real-az-1) for parameter availabilityZone is invalid. Subnets can "
        "currently only be created in the following availability zones: "
        + ", ".join(sorted(z["ZoneName"] for z in azs))
        + "."
    ), f"unexpected error message {message2!r}"


# ===== helpers =====
def _error_detail(fn, on_success):
    """(code, message) of the ClientError fn() raises; a success hands its response to on_success
    (which registers the subnet's deletion) and raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    on_success(result)
    raise AssertionError(
        f"expected CreateDefaultSubnet to reject a bogus availability zone, but it "
        f"succeeded with {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
