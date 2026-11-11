"""persist-hibernation-on-unencrypted-root-rejected."""
from __future__ import annotations

import math
import time

from behavioral_harness import tags

CHECK = "persist-hibernation-on-unencrypted-root-rejected"
GROUP = "persistence-lifecycle"
SERVICES = ["ec2"]

INSTANCE_TYPE = "m5d.large"


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """Hibernation is refused at launch unless the root volume is encrypted, and nothing launches.

    The refusal leaves no instance or volume behind, and the same launch with an encrypted root is
    accepted and comes up hibernation-enabled.
    """
    ec2 = ctx.client("ec2")

    info = ec2.describe_instance_types(InstanceTypes=[INSTANCE_TYPE])["InstanceTypes"]
    assert info, f"{INSTANCE_TYPE} is not offered in {ctx.region}"
    assert info[0].get("HibernationSupported") is True, (
        f"{INSTANCE_TYPE} reports HibernationSupported {info[0].get('HibernationSupported')!r}; "
        f"the rejection under test must be about encryption, not about the instance type")
    mem_gib = math.ceil(info[0]["MemoryInfo"]["SizeInMiB"] / 1024)

    az = _az_for(ec2, INSTANCE_TYPE)
    ami_id, root_device, ami_gib = _newest_al2023(ec2)
    # Sized for the memory image, so an undersized root cannot be what AWS objects to.
    root_gib = max(ami_gib, mem_gib * 2 + 20)

    name = ctx.unique_name("sim2real-persist-hibneg-")
    subnet_id, sg_id = _network(ctx, ec2, name, az)

    def _launch_kwargs(encrypted: bool) -> dict:
        return {
            "ImageId": ami_id, "InstanceType": INSTANCE_TYPE, "MinCount": 1, "MaxCount": 1,
            "HibernationOptions": {"Configured": True},
            "BlockDeviceMappings": [{"DeviceName": root_device,
                                     "Ebs": {"VolumeSize": root_gib, "VolumeType": "gp3",
                                             "Encrypted": encrypted,
                                             "DeleteOnTermination": True}}],
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
                                   "AssociatePublicIpAddress": False}],
            "TagSpecifications": [{"ResourceType": kind,
                                   "Tags": [{"Key": "sim2real", "Value": name},
                                            {"Key": "Name", "Value": name}]}
                                  for kind in ("instance", "volume")],
        }

    code, message, accepted = _refusal(ec2, _launch_kwargs(encrypted=False))
    if accepted:
        ctx.on_cleanup(lambda: _terminate(ec2, accepted))
    expected_message = "For hibernation, the root device volume must be encrypted."
    assert (code, message) == ("UnsupportedHibernationConfiguration", expected_message), (
        f"RunInstances with HibernationOptions.Configured=true over an UNENCRYPTED root volume "
        f"returned {code!r} ({message!r}); real AWS refuses it with exactly "
        f"'UnsupportedHibernationConfiguration' ({expected_message!r})"
        + (f" -- and here it launched {accepted!r}" if accepted else ""))

    live = _tagged_instances(ec2, name)
    assert live == [], (
        f"the refused launch still left instances {live!r} tagged {name!r}; a rejection must "
        f"create nothing")
    volumes = _tagged_volumes(ec2, name)
    assert volumes == [], (
        f"the refused launch still left volumes {volumes!r} tagged {name!r}; the root volume of a "
        f"rejected RunInstances must never be created")

    control = ec2.run_instances(**_launch_kwargs(encrypted=True))["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate(ec2, control))
    ec2.get_waiter("instance_running").wait(InstanceIds=[control], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    seen = ec2.describe_instances(
        InstanceIds=[control])["Reservations"][0]["Instances"][0]
    assert seen.get("HibernationOptions", {}).get("Configured") is True, (
        f"the encrypted-root control launched but reports HibernationOptions "
        f"{seen.get('HibernationOptions')!r}; the rejection above is only meaningful if the same "
        f"request with encryption really does give a hibernation-enabled instance")
    root_volume = [b["Ebs"]["VolumeId"] for b in seen["BlockDeviceMappings"]
                   if b["DeviceName"] == root_device]
    assert root_volume, (
        f"the control instance reports no mapping for its root device {root_device!r}: "
        f"{[b['DeviceName'] for b in seen['BlockDeviceMappings']]!r}")
    volume = ec2.describe_volumes(VolumeIds=root_volume)["Volumes"][0]
    assert volume["Encrypted"] is True, (
        f"the control's root volume {root_volume[0]} reports Encrypted {volume['Encrypted']!r}; "
        f"the launch asked for encryption, and that is the condition the rejection is about")


def _refusal(ec2, kwargs: dict) -> tuple[str, str, str]:
    """(error code, message, instance id if it was wrongly accepted).

    An accepted launch is returned rather than raised on, so the caller can register its teardown
    before failing: the assertion has to be able to clean up the thing that proves it wrong.
    """
    try:
        instance_id = ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
    except Exception as exc:  # noqa: BLE001 - the error IS the observation under test
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code") or type(exc).__name__, err.get("Message", str(exc))[:300], ""
    return "", "", instance_id


def _terminate(ec2, instance_id: str) -> None:
    """Terminate without waiting: _delete_sg is where the teardown waits for the ENI to go, and
    the whole teardown is bounded at 60s."""
    ec2.terminate_instances(InstanceIds=[instance_id])


def _tagged_instances(ec2, name: str) -> list[str]:
    """Every non-terminated instance carrying this run's own tag. Scoped, so a sibling run in the
    same account cannot change the answer."""
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [name]}]):
        for reservation in page["Reservations"]:
            out += [i["InstanceId"] for i in reservation["Instances"]
                    if i["State"]["Name"] != "terminated"]
    return sorted(out)


def _tagged_volumes(ec2, name: str) -> list[str]:
    out = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [name]}]):
        out += [v["VolumeId"] for v in page["Volumes"] if v["State"] != "deleted"]
    return sorted(out)


def _newest_al2023(ec2) -> tuple[str, str, int]:
    images = []
    for page in ec2.get_paginator("describe_images").paginate(
        Owners=["amazon"],
        Filters=[{"Name": "name", "Values": ["al2023-ami-2023.*-kernel-6.1-x86_64"]},
                 {"Name": "state", "Values": ["available"]}],
    ):
        images.extend(page["Images"])
    assert images, f"no available al2023 x86_64 AMI in {ec2.meta.region_name}"
    newest = max(images, key=lambda i: i["CreationDate"])
    root = newest["RootDeviceName"]
    sizes = [b["Ebs"]["VolumeSize"] for b in newest.get("BlockDeviceMappings", [])
             if b["DeviceName"] == root and "Ebs" in b]
    assert sizes, f"{newest['ImageId']} declares no EBS mapping for its root device {root!r}"
    return newest["ImageId"], root, sizes[0]


def _az_for(ec2, itype: str) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [itype]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {itype!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _network(ctx, ec2, name: str, az: str) -> tuple[str, str]:
    """A private VPC and subnet of this check's own. No egress and no ingress: nothing connects to
    these instances, so the security group carries no rules at all."""
    ts = lambda kind: [{"ResourceType": kind,  # noqa: E731
                        "Tags": [{"Key": "sim2real", "Value": name}, {"Key": "Name", "Value": name}]}]
    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=ts("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.77.1.0/24", AvailabilityZone=az,
                               TagSpecifications=ts("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet))
    sg = ec2.create_security_group(GroupName=name, Description=f"sim2real {CHECK}", VpcId=vpc,
                                  TagSpecifications=ts("security-group"))["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg))
    return subnet, sg


def _delete_sg(ec2, sg: str, timeout_s: float = 180.0) -> None:
    """The one blocking step in teardown: an ENI still holding this group is a live instance.

    Every instance this check launched is terminated without a per-instance wait, so this retry is
    where the teardown waits for them to actually go away -- once, for all of them, and against a
    condition that is observable rather than a sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg)
            return
        except Exception as exc:  # noqa: BLE001 - retried below, re-raised at the deadline
            if time.monotonic() >= deadline or "DependencyViolation" not in str(exc):
                raise
            time.sleep(6)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
