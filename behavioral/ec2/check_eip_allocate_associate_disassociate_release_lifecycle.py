"""eip-allocate-associate-disassociate-release-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except Exception:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
    """Poll DescribeInstances until the instance reaches *state* (swallows the
    eventually-consistent InvalidInstanceID.NotFound window right after launch)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


def _release_eip(ec2, alloc_id):
    """Best-effort teardown: disassociate (if bound) then release the EIP."""
    try:
        addr = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
        if addr.get("AssociationId"):
            ec2.disassociate_address(AssociationId=addr["AssociationId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidAssociationID.NotFound",
        ):
            raise
    try:
        ec2.release_address(AllocationId=alloc_id)
    except ClientError as exc:
        # The check itself releases the address; one already released is not a leak.
        if exc.response.get("Error", {}).get("Code") != "InvalidAllocationID.NotFound":
            raise

CHECK = "eip-allocate-associate-disassociate-release-lifecycle"
GROUP = 'elastic-ip'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AllocateAddress -> AssociateAddress(instance) -> DisassociateAddress -> ReleaseAddress lifecycle."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    resp = ec2.allocate_address(Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    alloc_id = resp["AllocationId"]
    ctx.on_cleanup(lambda: _release_eip(ec2, alloc_id))
    assoc = ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_id)
    assoc_id = assoc["AssociationId"]

    addr = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert addr["InstanceId"] == instance_id, (
        f"expected address associated with {instance_id}, got {addr['InstanceId']}"
    )
    assert addr["AssociationId"] == assoc_id, (
        f"expected association id {assoc_id}, got {addr['AssociationId']}"
    )

    ec2.disassociate_address(AssociationId=assoc_id)
    addr = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert addr.get("InstanceId", "") == "", f"expected address disassociated, got {addr}"

    ec2.release_address(AllocationId=alloc_id)
    try:
        ec2.describe_addresses(AllocationIds=[alloc_id])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidAllocationID.NotFound", f"expected address gone, got {code}"
    assert message == f"The allocation ID '{alloc_id}' does not exist", message

    # The released allocation id must also be unusable, not merely absent from
    # DescribeAddresses: a mutating call against it is rejected the same way.
    try:
        ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_id)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidAllocationID.NotFound", (
        f"expected AssociateAddress on a released allocation to fail with "
        f"InvalidAllocationID.NotFound, got {code}"
    )
    assert message == f"The allocation ID '{alloc_id}' does not exist", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
