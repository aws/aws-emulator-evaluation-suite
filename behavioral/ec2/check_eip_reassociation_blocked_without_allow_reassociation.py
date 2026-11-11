"""eip-reassociation-blocked-without-allow-reassociation."""
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidAssociationID.NotFound",
        ):
            raise
    ec2.release_address(AllocationId=alloc_id)

CHECK = "eip-reassociation-blocked-without-allow-reassociation"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateAddress(InstanceId=...) with AllowReassociation=False must fail with Resource.AlreadyAssociated
    if the EIP is already associated, and must leave the association unchanged; AllowReassociation=True must
    then move the address, each state confirmed by an independent describe_addresses read (overly-permissive check)."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_a = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_a]))
    instance_b = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_b]))
    _wait_instance_state(ec2, instance_a, "running")
    _wait_instance_state(ec2, instance_b, "running")

    resp = ec2.allocate_address(Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    alloc_id = resp["AllocationId"]
    ctx.on_cleanup(lambda: _release_eip(ec2, alloc_id))
    assoc_a = ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_a)
    assert assoc_a.get("AssociationId"), "positive control: AssociateAddress to instance_a returned no AssociationId"

    addr_before = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert addr_before.get("InstanceId") == instance_a, (
        f"positive control: independent read expected InstanceId={instance_a!r}, "
        f"got {addr_before.get('InstanceId')!r}"
    )

    try:
        ec2.associate_address(
            AllocationId=alloc_id, InstanceId=instance_b, AllowReassociation=False
        )
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "Resource.AlreadyAssociated", f"expected Resource.AlreadyAssociated, got {code}"
    assert message == (f"resource {alloc_id} is already associated with associate-id "
                       f"{assoc_a['AssociationId']}"), message

    addr_blocked = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert addr_blocked.get("InstanceId") == instance_a, (
        f"blocked reassociation must not move the address off {instance_a}, "
        f"independent read shows InstanceId={addr_blocked.get('InstanceId')!r}"
    )
    assert addr_blocked.get("AssociationId") == assoc_a["AssociationId"], (
        f"blocked reassociation must not change AssociationId, "
        f"expected {assoc_a['AssociationId']!r}, got {addr_blocked.get('AssociationId')!r}"
    )

    ec2.associate_address(AllocationId=alloc_id, InstanceId=instance_b, AllowReassociation=True)
    addr_restored = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert addr_restored.get("InstanceId") == instance_b, (
        f"restore control: AllowReassociation=True should move the address to {instance_b}, "
        f"independent read shows InstanceId={addr_restored.get('InstanceId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
