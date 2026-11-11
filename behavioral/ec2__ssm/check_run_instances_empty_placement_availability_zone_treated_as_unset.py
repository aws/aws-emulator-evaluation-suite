"""run-instances-empty-placement-availability-zone-treated-as-unset."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-instances-empty-placement-availability-zone-treated-as-unset"
GROUP = "dry-run"
SERVICES = ["ec2", "ssm"]

_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_DRY_RUN_OK = ("DryRunOperation", "Request would have succeeded, but DryRun flag is set.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DryRun RunInstances treats Placement.AvailabilityZone '' as unset.

    It passes validation like the subnet's own zone; an unknown zone is refused; nothing launches.
    """
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-azempty-")
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    subnet_id, az = _subnet(ctx, ec2, marker)

    def dry_run(placement):
        return _error(
            lambda: ec2.run_instances(
                DryRun=True,
                ImageId=ami,
                InstanceType=_TYPE,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                Placement=placement,
                TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(marker)}],
            )
        )

    control = dry_run({"AvailabilityZone": az})
    assert control == _DRY_RUN_OK, (
        f"Placement in the subnet's zone {az!r}: expected {_DRY_RUN_OK!r}, got {control!r}"
    )

    empty = dry_run({"AvailabilityZone": ""})
    assert empty == _DRY_RUN_OK, (
        f"Placement.AvailabilityZone '': expected {_DRY_RUN_OK!r}, got {empty!r}"
    )

    bad_az = f"{ctx.region}-nozone"
    refused = dry_run({"AvailabilityZone": bad_az})
    want = ("InvalidParameterValue", f"Invalid availability zone: [{bad_az}]")
    assert refused == want, (
        f"Placement.AvailabilityZone {bad_az!r}: expected {want!r}, got {refused!r}"
    )

    launched = [
        i["InstanceId"]
        for r in ec2.describe_instances(
            Filters=[{"Name": "tag:sim2real-marker", "Values": [marker]}]
        )["Reservations"]
        for i in r["Instances"]
    ]
    assert launched == [], f"DryRun requests must launch nothing, found {launched!r}"


def _subnet(ctx, ec2, marker):
    """A VPC and one subnet of this check's own making, in a zone that offers the instance type."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(marker)}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )

    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available zone offers {_TYPE!r} in {ctx.region}"
    az = usable[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.78.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(marker)}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")
    )
    return subnet_id, az


def _tags_for(marker):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-marker", "Value": marker}]


def _error(fn):
    """Return the (code, message) fn() is refused with; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
