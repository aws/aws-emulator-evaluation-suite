"""run-instances-refuses-a-nonexistent-key-pair-and-launches-nothing."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-instances-refuses-a-nonexistent-key-pair-and-launches-nothing"
GROUP = "run-instances-reference-validation"
SERVICES = ["ec2", "ssm"]

# The (code, message) for an absent key pair; the message names the key: format it with the name.
_KEY_NOT_FOUND = ("InvalidKeyPair.NotFound", "The key pair '{}' does not exist")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real RunInstances naming an absent key pair is refused InvalidKeyPair.NotFound.

    The call is not a DryRun; the exact message is asserted, and no instance is launched.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
    """
    ec2 = ctx.client("ec2")
    ami = _al2023_ami(ctx)
    subnets = ctx.network().subnets
    subnet_id = subnets[_usable_az(ec2, subnets)]
    key_name = ctx.unique_name("sim2real-nokey-")
    name = ctx.unique_name("sim2real-nokeyrun-")
    absent = (_KEY_NOT_FOUND[0], _KEY_NOT_FOUND[1].format(key_name))

    described = _client_error(lambda: ec2.describe_key_pairs(KeyNames=[key_name]))
    assert described == absent, (
        f"DescribeKeyPairs({key_name!r}) returned {described!r}, expected {absent!r}: the key "
        f"must be absent for the launch assertion below"
    )

    launched_ids: list[str] = []
    ctx.on_cleanup(lambda: _drop_launched(ctx, name, launched_ids))
    got = _client_error(
        lambda: _launch(
            ec2,
            launched_ids,
            ImageId=ami,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            KeyName=key_name,
            TagSpecifications=_tags(name),
        )
    )
    assert got == absent, (
        f"RunInstances with the absent key pair {key_name!r} returned {got!r}, expected {absent!r}"
    )

    launched = _tagged_instances(ec2, name)
    assert launched == set(), (
        f"DescribeInstances filtered on tag:Name={name!r} lists {sorted(launched)!r} after the "
        f"refused launch; a refused launch creates nothing"
    )


def _al2023_ami(ctx) -> str:
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the SSM AMI alias resolved to {ami!r}, expected an ami-* id"
    return ami


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
