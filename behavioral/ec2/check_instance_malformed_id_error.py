"""instance-malformed-id-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-malformed-id-error"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstances rejects a structurally invalid id and the documentation placeholder
    "i-1234567890abcdef0" as InvalidInstanceID.Malformed, yet describes a real instance id.
    """
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ec2, ctx=ctx)
    ami_id = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert ami_id, "no available al2023 x86_64 AMI owned by amazon in this region"
    ami_id = sorted(ami_id, key=lambda i: i["CreationDate"], reverse=True)[0]["ImageId"]

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-imid-")}],
            }
        ],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    # Positive control. Right after RunInstances, DescribeInstances can transiently raise
    # InvalidInstanceID.NotFound before the instance has propagated.
    real = _poll_until(
        lambda: _describe_or_none(ec2, instance_id),
        lambda v: v is not None,
        timeout_s=60.0,
        description=f"instance {instance_id!r} becoming describable",
    )
    assert real["InstanceId"] == instance_id, (
        f"positive control did not describe the real instance {instance_id!r}: {real!r}"
    )

    try:
        ec2.describe_instances(InstanceIds=["i-not-a-valid-id"])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed for a structurally invalid id, got {code}"
    )
    assert message == 'Invalid id: "i-not-a-valid-id"', message

    # Most never-issued well-shaped ids are NotFound, but this placeholder is Malformed.
    try:
        ec2.describe_instances(InstanceIds=["i-1234567890abcdef0"])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidInstanceID.Malformed", (
        "expected InvalidInstanceID.Malformed for the well-shaped documentation-"
        f"placeholder id 'i-1234567890abcdef0', got {code}"
    )
    assert message == 'Invalid id: "i-1234567890abcdef0"', message


def _describe_or_none(ec2, instance_id):
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return None
        raise
    reservations = resp.get("Reservations", [])
    if not reservations:
        return None
    return reservations[0]["Instances"][0]


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _default_vpc_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
