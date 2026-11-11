"""hibernate-launch-with-root-volume-too-small-for-ram-rejected."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hibernate-launch-with-root-volume-too-small-for-ram-rejected"
GROUP = "hibernation-preconditions"
SERVICES = ["ec2"]

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_ERR_HIBERNATION = "UnsupportedHibernationConfiguration"
_INSTANCE_TYPE = "m5.large"

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return None
            raise


def _usable_az(ec2, itype):
    """An AZ that is available AND offers `itype`; the offerings catalogue omits zone state."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [itype]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no AZ this region reports as available offers {itype}; offered in {sorted(offered)!r}, "
        f"available {sorted(available)!r}. This region cannot run the check."
    )
    return usable[0]


def _own_vpc(ctx, ec2, az, scenario):
    """A tagged VPC and subnet of this check's own; an account need not have a default VPC."""
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                              TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _newest_al2023(ec2, ssm):
    """The current AL2023 x86_64 AMI, its root device name and the smallest root it permits."""
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"
    img = ec2.describe_images(ImageIds=[ami])["Images"][0]
    root_gib = max((b["Ebs"]["VolumeSize"] for b in img["BlockDeviceMappings"] if "Ebs" in b),
                   default=8)
    return ami, img["RootDeviceName"], root_gib


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _instance_state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI clears only at the
    end, and the subnet/VPC teardown registered earlier cannot proceed until it does."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _live_in_subnet(ec2, subnet):
    """Every instance in this check's own subnet that is not already terminated."""
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}]):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                if i["State"]["Name"] not in ("terminated", "shutting-down"):
                    out.append((i["InstanceId"], i["InstanceType"], i["State"]["Name"]))
    return out


def _volumes_for(ec2, scenario):
    """This scenario's own volumes, by the tag stamped at creation."""
    out = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [scenario]}]):
        for v in page["Volumes"]:
            if v["State"] != "deleted":
                out.append((v["VolumeId"], v["Size"], v["State"]))
    return out


def _refusal(ctx, ec2, kwargs, what):
    """The (code, message) RunInstances refused with; an accepted launch registers teardown and raises."""
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message", "")
    ids = [i["InstanceId"] for i in resp["Instances"]]
    for iid in ids:
        ctx.on_cleanup(lambda i=iid: _terminate_and_wait(ec2, i))
    raise AssertionError(
        f"{what}: RunInstances ACCEPTED a launch real AWS refuses with {_ERR_HIBERNATION} and "
        f"created {ids!r}; they have been registered for teardown"
    )


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """A hibernation launch whose encrypted root cannot hold RAM is refused with no instance or volume
    left behind; the same launch with only a larger root is accepted with hibernation enabled.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    scenario = ctx.unique_name("hib-small-root-")

    info = ec2.describe_instance_types(InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"]
    assert info, f"{_INSTANCE_TYPE} is not offered in {ctx.region}"
    assert info[0].get("HibernationSupported") is True, (
        f"this check needs a type the catalogue says CAN hibernate, so that root size is the only "
        f"thing under test, but {_INSTANCE_TYPE} reports HibernationSupported "
        f"{info[0].get('HibernationSupported')!r}"
    )
    mem_gib = math.ceil(info[0]["MemoryInfo"]["SizeInMiB"] / 1024)
    az = _usable_az(ec2, _INSTANCE_TYPE)
    ami, root_device, ami_gib = _newest_al2023(ec2, ssm)
    # Sizes derive from MemoryInfo and the AMI minimum; the AMI minimum must not already exceed RAM.
    assert ami_gib <= mem_gib, (
        f"the too-small root is the AMI's own minimum, {ami_gib} GiB, but {_INSTANCE_TYPE} has "
        f"{mem_gib} GiB of RAM — a root that already exceeds RAM is not undersized, so this check "
        f"would be asserting nothing. Pick a smaller root or a larger type."
    )
    too_small = ami_gib
    big_enough = mem_gib * 2 + 20  # the RAM image, the filesystem it lands in, and the OS

    subnet = _own_vpc(ctx, ec2, az, scenario)

    def launch_kwargs(root_gib):
        return dict(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            HibernationOptions={"Configured": True},
            BlockDeviceMappings=[{"DeviceName": root_device,
                                  "Ebs": {"Encrypted": True, "VolumeSize": root_gib,
                                          "VolumeType": "gp3", "DeleteOnTermination": True}}],
            TagSpecifications=[
                {"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}
                for rt in ("instance", "volume")],
        )

    code, message = _refusal(ctx, ec2, launch_kwargs(too_small),
                    f"hibernation-enabled launch with a {too_small} GiB root")
    assert code == _ERR_HIBERNATION, (
        f"a hibernation-enabled {_INSTANCE_TYPE} launch with a {too_small} GiB encrypted root, "
        f"which cannot hold {mem_gib} GiB of RAM, must be refused with {_ERR_HIBERNATION!r}, but "
        f"RunInstances answered {code!r}"
    )
    assert message == (
        "The root device does not have the disk space required for hibernation. Increase the root "
        "device volume size so that it has enough free space to accommodate the total RAM for your "
        "instance type and your expected volume usage, and try again."), message

    live = _live_in_subnet(ec2, subnet)
    assert live == [], (
        f"the refused launch must leave no instance behind, but this check's own subnet {subnet} "
        f"holds {live!r}"
    )
    vols = _volumes_for(ec2, scenario)
    assert vols == [], (
        f"the refused launch must leave no volume behind, but volumes tagged sim2real={scenario} "
        f"exist: {vols!r}"
    )

    # Positive control: identical launch except the root size.
    resp = _call_with_retry(lambda: ec2.run_instances(**launch_kwargs(big_enough)))
    control_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, control_id))
    assert resp["Instances"][0].get("HibernationOptions") == {"Configured": True}, (
        f"the control launch with a {big_enough} GiB root was accepted but reports "
        f"HibernationOptions {resp['Instances'][0].get('HibernationOptions')!r}, so the refusal "
        f"above cannot be attributed to root size"
    )
    control = _poll(lambda: _describe(ec2, control_id),
                    lambda i: i is not None and bool(i.get("BlockDeviceMappings")),
                    timeout_s=300, interval_s=5.0,
                    what=f"control instance {control_id} reporting its root volume")
    root_vol = next(b["Ebs"]["VolumeId"] for b in control["BlockDeviceMappings"]
                    if b["DeviceName"] == root_device)
    vol = ec2.describe_volumes(VolumeIds=[root_vol])["Volumes"][0]
    assert vol["Encrypted"] is True, (
        f"the control's root {root_vol} must be encrypted, or the launch would have been refused "
        f"for a different reason than the one under test; DescribeVolumes reported {vol!r}"
    )
    assert vol["Size"] == big_enough, (
        f"the control's root {root_vol} came back at {vol['Size']} GiB, not the {big_enough} GiB "
        f"requested, so the size that was accepted is not the size under test"
    )
    assert vol["Size"] > mem_gib, (
        f"the accepted root is {vol['Size']} GiB against {mem_gib} GiB of RAM — the control must be "
        f"large enough to hold the memory image for the contrast with the refusal to mean anything"
    )
    live = _live_in_subnet(ec2, subnet)
    assert [i[0] for i in live] == [control_id], (
        f"only the control launch may have produced an instance in {subnet}; it holds {live!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
