"""run-instances-refuses-an-eight-hex-image-id-as-not-found."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-instances-refuses-an-eight-hex-image-id-as-not-found"
GROUP = "run-instances-reference-validation"
SERVICES = ["ec2"]

# The short 8-hex image id form is well-formed: an absent one is NotFound, never Malformed.
_ABSENT_AMI = "ami-12345678"
_ABSENT = ("InvalidAMIID.NotFound", f"The image id '[{_ABSENT_AMI}]' does not exist")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunInstances with the 8-hex image id ami-12345678 is refused InvalidAMIID.NotFound.

    The short id form is well-formed, so it is not InvalidAMIID.Malformed; nothing is launched.
    """
    ec2 = ctx.client("ec2")
    subnets = ctx.network().subnets
    subnet_id = subnets[_usable_az(ec2, subnets)]
    name = ctx.unique_name("sim2real-ami8-")

    described = _client_error(lambda: ec2.describe_images(ImageIds=[_ABSENT_AMI]))
    assert described == _ABSENT, (
        f"DescribeImages({_ABSENT_AMI!r}) returned {described!r}, expected {_ABSENT!r}: the image "
        f"must be absent for the launch assertion below"
    )

    launched_ids: list[str] = []
    ctx.on_cleanup(lambda: _drop_launched(ctx, name, launched_ids))
    got = _client_error(
        lambda: _launch(
            ec2,
            launched_ids,
            ImageId=_ABSENT_AMI,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            TagSpecifications=_tags(name),
        )
    )
    assert got == _ABSENT, (
        f"RunInstances with the absent image {_ABSENT_AMI!r} returned {got!r}, expected {_ABSENT!r}"
    )

    launched = _tagged_instances(ec2, name)
    assert launched == set(), (
        f"DescribeInstances filtered on tag:Name={name!r} lists {sorted(launched)!r} after the "
        f"refused launch; a refused launch creates nothing"
    )


def _usable_az(ec2, subnets, instance_type: str = "t3.micro") -> str:
    """The first available AZ that offers instance_type and holds a shared-network subnet."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneName"] in subnets
    )
    assert usable, (
        f"no available AZ in {ec2.meta.region_name!r} offers {instance_type!r} and holds a "
        f"shared-network subnet; offerings were {sorted(offered)!r}, subnets {sorted(subnets)!r}"
    )
    return usable[0]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, capped by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) fn() raises. Raises when the call SUCCEEDS: real AWS rejects it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call succeeded; real AWS rejects it. Result: {result!r}")


def _tags(name: str) -> list[dict]:
    return [
        {
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "1"}],
        }
    ]


def _tagged_instances(ec2, name: str, *, live_only: bool = False) -> set[str]:
    """Ids of the instances carrying Name=name, in any state unless live_only."""
    return {
        i["InstanceId"]
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:Name", "Values": [name]}]
        )
        for res in page["Reservations"]
        for i in res["Instances"]
        if not live_only or i["State"]["Name"] != "terminated"
    }


def _launch(ec2, launched_ids: list[str], **kwargs) -> dict:
    """RunInstances, recording any launched instance id for the cleanup to terminate."""
    result = ec2.run_instances(**kwargs)
    launched_ids.extend(i["InstanceId"] for i in result.get("Instances", []))
    return result


def _drop_launched(ctx, name: str, launched_ids: list[str]) -> None:
    """Terminate the ids a launch that should have been refused returned, plus any tagged with name.

    The tag lookup is a backup only: DescribeInstances may not list a just-launched instance yet.
    """
    ec2 = ctx.client("ec2")
    left = sorted(set(launched_ids) | _tagged_instances(ec2, name, live_only=True))
    if not left:
        return
    ec2.terminate_instances(InstanceIds=left)
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=left,
        WaiterConfig={"Delay": 5, "MaxAttempts": max(1, int(_budget_s(ctx, 600.0) // 5))},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
