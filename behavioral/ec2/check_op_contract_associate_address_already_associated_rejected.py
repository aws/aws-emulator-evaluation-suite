"""op-contract-associate-address-already-associated-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associate-address-already-associated-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Moving a bound EIP to another ENI with AllowReassociation=False fails with
    Resource.AlreadyAssociated and leaves it in place; with True it moves. An unissued
    instance id is rejected as InvalidInstanceID.Malformed."""
    ec2 = ctx.client("ec2")
    instance_id, subnet_id, vpc_id = _launch_instance(ctx)

    alloc1 = ec2.allocate_address(Domain="vpc")
    alloc_id1 = alloc1["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id1))
    alloc2 = ec2.allocate_address(Domain="vpc")
    alloc_id2 = alloc2["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id2))

    assoc = ec2.associate_address(InstanceId=instance_id, AllocationId=alloc_id1)
    assoc_id = assoc["AssociationId"]
    assert assoc["AssociationId"]

    described = ec2.describe_addresses(AllocationIds=[alloc_id1])["Addresses"][0]
    assert described.get("InstanceId") == instance_id
    assert described.get("AssociationId") == assoc_id

    # AllowReassociation only governs moving an already-associated address; binding a second
    # address to the instance would just replace its association.
    eni2 = ec2.create_network_interface(SubnetId=subnet_id, Description=ctx.unique_name("sim2real-eni-"))[
        "NetworkInterface"
    ]
    eni2_id = eni2["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni2_id))

    code, message = _client_error(
        lambda: ec2.associate_address(NetworkInterfaceId=eni2_id, AllocationId=alloc_id1, AllowReassociation=False)
    )
    assert code == "Resource.AlreadyAssociated", f"unexpected error code: {code}"
    expected = f"resource {alloc_id1} is already associated with associate-id {assoc_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_on_instance = ec2.describe_addresses(AllocationIds=[alloc_id1])["Addresses"][0]
    assert still_on_instance.get("InstanceId") == instance_id, (
        f"rejected reassociation must not have moved the address off its instance, got {still_on_instance}"
    )
    assert still_on_instance.get("NetworkInterfaceId") != eni2_id, (
        f"rejected reassociation must not have bound the address to the new ENI, got {still_on_instance}"
    )

    ec2.associate_address(NetworkInterfaceId=eni2_id, AllocationId=alloc_id1, AllowReassociation=True)
    moved = ec2.describe_addresses(AllocationIds=[alloc_id1])["Addresses"][0]
    assert moved.get("NetworkInterfaceId") == eni2_id, (
        f"positive-control reassociation with AllowReassociation=True should have moved the address "
        f"to {eni2_id}, got {moved}"
    )
    ctx.on_cleanup(lambda: _safe_disassociate(ec2, alloc_id1))

    # An id EC2 could never have issued fails as InvalidInstanceID.Malformed before any lookup, not
    # NotFound: the real id with a non-zero leading hex digit keeps the shape but leaves the range.
    fake_instance_id = _unissued_sibling_id(instance_id)
    code2, message2 = _client_error(lambda: ec2.associate_address(InstanceId=fake_instance_id, AllocationId=alloc_id2))
    assert code2 == "InvalidInstanceID.Malformed", f"unexpected error code: {code2}"
    expected2 = f'Invalid id: "{fake_instance_id}"'
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _safe_disassociate(ec2, allocation_id):
    from botocore.exceptions import ClientError

    try:
        addr = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
        assoc_id = addr.get("AssociationId")
        if assoc_id:
            ec2.disassociate_address(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidAssociationID.NotFound",
        ):
            raise


def _unissued_sibling_id(real_id: str) -> str:
    prefix, _, suffix = real_id.partition("-")
    lead = "e" if suffix[0] == "f" else "f"
    return f"{prefix}-{lead}{suffix[1:]}"


def _client_error(fn):
    """Return the (code, message) of fn()'s ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-instance-")}]}
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id, subnet_id, vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
