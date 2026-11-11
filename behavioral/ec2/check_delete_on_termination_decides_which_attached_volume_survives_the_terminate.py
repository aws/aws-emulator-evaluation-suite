"""delete-on-termination-decides-which-attached-volume-survives-the-terminate."""
from __future__ import annotations

import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-on-termination-decides-which-attached-volume-survives-the-terminate"
GROUP = "ebs-lifecycle"
SERVICES = ["ec2"]

_VPC_CIDR = "10.77.0.0/16"
_SUBNET_CIDR = "10.77.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VOLUME_GIB = 1
_KEEP_DEVICE = "/dev/sdf"
_DROP_DEVICE = "/dev/sdg"
_CONVERGE_TIMEOUT_S = 420.0
_ERR_NO_VOLUME = "InvalidVolume.NotFound"
_GONE_CODES = (
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
    "InvalidVolume.NotFound",
    "InvalidSnapshot.NotFound",
)
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Two identical volumes on one instance diverge on terminate by DeleteOnTermination: the True one
    is gone (describe and snapshot both fail InvalidVolume.NotFound), the False one turns 'available'
    and can be snapshotted, and the root volume's True mapping deletes it too.
    """
    ec2 = ctx.client("ec2")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "volumes": [], "snapshots": []}
    try:
        _build(ctx, ec2, st)
        _legs(ctx, ec2, st)
    finally:
        _teardown(ctx, ec2, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, st) -> None:
    instance_id = st["instance"]
    keep_vol = st["keep_volume"]
    drop_vol = st["drop_volume"]

    # --- the measured default, before anything is written ---
    mappings = _mappings(ec2, instance_id)
    assert set(mappings) >= {_KEEP_DEVICE, _DROP_DEVICE, st["root_device"]}, (
        f"DescribeInstances must report a block device mapping for the root device "
        f"{st['root_device']!r} and both attached devices {_KEEP_DEVICE!r}/{_DROP_DEVICE!r}; it "
        f"reported {sorted(mappings)!r}"
    )
    for device in (_KEEP_DEVICE, _DROP_DEVICE):
        assert mappings[device]["DeleteOnTermination"] is False, (
            f"a volume attached with AttachVolume must default to DeleteOnTermination False; "
            f"{device} reports {mappings[device]!r}"
        )
    assert mappings[st["root_device"]]["DeleteOnTermination"] is True, (
        f"the AMI's root mapping must carry DeleteOnTermination True, so the root volume is the "
        f"third data point in this run; {st['root_device']} reports "
        f"{mappings[st['root_device']]!r}"
    )
    root_vol = mappings[st["root_device"]]["VolumeId"]
    st["root_volume"] = root_vol

    # --- break the symmetry on exactly one attachment ---
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        BlockDeviceMappings=[{"DeviceName": _DROP_DEVICE,
                              "Ebs": {"DeleteOnTermination": True}}],
    )
    settled = _poll(
        lambda: _mappings(ec2, instance_id),
        lambda m: m.get(_DROP_DEVICE, {}).get("DeleteOnTermination") is True,
        timeout_s=180.0, interval_s=2.0, ctx=ctx,
        what=(f"{STATE_MARKER}: DescribeInstances reporting DeleteOnTermination True for "
              f"{_DROP_DEVICE} on {instance_id}"),
    )
    assert settled[_DROP_DEVICE]["DeleteOnTermination"] is True, (
        f"expected DeleteOnTermination True on {_DROP_DEVICE}, got {settled[_DROP_DEVICE]!r}"
    )
    assert settled[_KEEP_DEVICE]["DeleteOnTermination"] is False, (
        f"writing {_DROP_DEVICE}'s flag must not touch {_KEEP_DEVICE}'s: expected False, got "
        f"{settled[_KEEP_DEVICE]!r}"
    )
    # a SECOND independent read of the same fact, at the volume rather than at the instance
    for vol, expected in ((drop_vol, True), (keep_vol, False)):
        attachment = _attachment(ec2, vol, instance_id)
        assert attachment["DeleteOnTermination"] is expected, (
            f"DescribeVolumes must agree with DescribeInstances about {vol}: expected "
            f"DeleteOnTermination {expected}, got {attachment!r}"
        )

    # --- one terminate, both volumes, the same instant ---
    ec2.terminate_instances(InstanceIds=[instance_id])
    _poll(lambda: _state(ec2, instance_id), lambda s: s in ("terminated", "__gone__"),
          timeout_s=600.0, interval_s=2.0, ctx=ctx,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'terminated'")

    # --- the True side is gone: a read AND a mutation on its id both fail not-found ---
    _poll(lambda: _volume_state(ec2, drop_vol), lambda s: s == "__gone__",
          timeout_s=_CONVERGE_TIMEOUT_S, interval_s=2.0, ctx=ctx,
          what=(f"volume {drop_vol} (DeleteOnTermination True on {_DROP_DEVICE}) disappearing "
                f"after {instance_id} terminated"))
    gone = _client_error(lambda: ec2.describe_volumes(VolumeIds=[drop_vol]))
    assert gone.get("Code") == _ERR_NO_VOLUME, (
        f"an independent read of the deleted volume {drop_vol} must fail with {_ERR_NO_VOLUME}, got "
        f"{gone.get('Code')!r} ({gone.get('Message')!r})"
    )
    assert gone.get("Message") == f"The volume '{drop_vol}' does not exist.", gone
    dead_write = _client_error(lambda: ec2.create_snapshot(
        VolumeId=drop_vol, Description="sim2real must not be creatable"))
    assert dead_write.get("Code") == _ERR_NO_VOLUME, (
        f"a MUTATION on the dead volume id {drop_vol} must also fail with {_ERR_NO_VOLUME} — a "
        f"target that merely hides it from DescribeVolumes has not deleted it; got "
        f"{dead_write.get('Code')!r}"
    )
    _poll(lambda: _volume_state(ec2, root_vol), lambda s: s == "__gone__",
          timeout_s=_CONVERGE_TIMEOUT_S, interval_s=2.0, ctx=ctx,
          what=(f"the root volume {root_vol}, whose mapping carried DeleteOnTermination True, "
                f"disappearing after {instance_id} terminated"))

    # --- the False side SURVIVED, is detached, and is still usable ---
    survivor = _poll(
        lambda: _volume(ec2, keep_vol),
        lambda v: v is not None and v["State"] == "available",
        timeout_s=_CONVERGE_TIMEOUT_S, interval_s=2.0, ctx=ctx,
        what=(f"{STATE_MARKER}: volume {keep_vol} (DeleteOnTermination False on {_KEEP_DEVICE}) "
              f"converging to 'available' after {instance_id} terminated"),
    )
    assert survivor["State"] == "available", (
        f"the surviving volume must be 'available', not still 'in-use': {survivor!r}"
    )
    assert survivor.get("Attachments") == [], (
        f"the surviving volume must carry no attachment after the instance terminated, got "
        f"{survivor.get('Attachments')!r}"
    )
    assert survivor["Size"] == _VOLUME_GIB, (
        f"the surviving volume must be the one this check created ({_VOLUME_GIB} GiB), got "
        f"{survivor!r}"
    )
    # The survivor is not merely listed, it is usable.
    snapshot_id = ec2.create_snapshot(
        VolumeId=keep_vol, Description="sim2real DeleteOnTermination survivor is usable",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": _tags_for(st["name"])}],
    )["SnapshotId"]
    st["snapshots"].append(snapshot_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_snapshot(SnapshotId=snapshot_id), "InvalidSnapshot.NotFound"))
    described = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
    assert len(described) == 1, (
        f"expected exactly one snapshot for {snapshot_id}, got {described!r}"
    )
    assert described[0]["VolumeId"] == keep_vol, (
        f"the snapshot must name the surviving volume {keep_vol} as its source, got "
        f"{described[0]!r}"
    )
    assert described[0]["VolumeSize"] == _VOLUME_GIB, (
        f"the snapshot must carry the survivor's size {_VOLUME_GIB} GiB, got {described[0]!r}"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, st) -> None:
    """A VPC, one private subnet, one instance and two identical volumes, all created here."""
    name = ctx.unique_name("sim2real-b1dot-")
    st["name"] = name

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = sorted(_zones_offering(ec2, _INSTANCE_TYPE))[0]
    st["az"] = az
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real DeleteOnTermination check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    images = ec2.describe_images(ImageIds=[ami])["Images"]
    assert len(images) == 1, f"expected exactly one image for {ami!r}, got {images!r}"
    st["root_device"] = images[0]["RootDeviceName"]

    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": _tags_for(name)},
            {"ResourceType": "volume", "Tags": _tags_for(name)},
        ],
    )["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)
    st["instance"] = instance_id
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600.0, interval_s=2.0, ctx=ctx,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'running'")

    # Two volumes created from the same parameters in the same AZ: the ONLY thing that will differ
    # between them is the DeleteOnTermination flag.
    for key, device in (("keep_volume", _KEEP_DEVICE), ("drop_volume", _DROP_DEVICE)):
        vol = ec2.create_volume(
            AvailabilityZone=az, Size=_VOLUME_GIB, VolumeType="gp3",
            TagSpecifications=[{"ResourceType": "volume", "Tags": _tags_for(name)}],
        )["VolumeId"]
        st[key] = vol
        st["volumes"].append(vol)
        ctx.on_cleanup(lambda v=vol: _unless_gone(
            lambda: ec2.delete_volume(VolumeId=v), "InvalidVolume.NotFound"))
        _poll(lambda v=vol: _volume_state(ec2, v), lambda s: s == "available",
              timeout_s=300.0, interval_s=2.0, ctx=ctx,
              what=f"{STATE_MARKER}: volume {vol} reaching 'available'")
        ec2.attach_volume(VolumeId=vol, InstanceId=instance_id, Device=device)
        _poll(lambda v=vol: _volume_state(ec2, v), lambda s: s == "in-use",
              timeout_s=300.0, interval_s=2.0, ctx=ctx,
              what=f"{STATE_MARKER}: volume {vol} reaching 'in-use' on {device}")


# ===== in-band teardown ======================================================


def _teardown(ctx, ec2, st) -> None:
    """Ordered in-band teardown with waits a registered cleanup cannot afford. Runs every step,
    then raises what it could not remove."""
    left: list[str] = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for snap in st.get("snapshots", []):
        _step(f"snapshot {snap}", lambda s=snap: _retry_dependency(
            lambda: ec2.delete_snapshot(SnapshotId=s)))
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=600.0, interval_s=2.0, ctx=ctx, what=f"instance {i} reaching 'terminated'"))
    for vol in st.get("volumes", []):
        # A volume this check deliberately let EC2 delete is already gone; _GONE_CODES absorbs it.
        _step(f"volume-detached {vol}", lambda v=vol: _poll(
            lambda: _volume_state(ec2, v), lambda s: s in ("available", "__gone__"),
            timeout_s=_CONVERGE_TIMEOUT_S, interval_s=2.0, ctx=ctx,
            what=f"volume {v} detaching before it can be deleted"))
        _step(f"volume {vol}", lambda v=vol: _retry_dependency(
            lambda: ec2.delete_volume(VolumeId=v)))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420.0, interval_s=2.0, ctx=ctx, what=f"every ENI in {st['vpc']!r} draining"))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - collected, raised after the loop
            left.append(f"{label}: {exc!r}")
    if st.get("vpc"):
        try:
            still = ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]
            left.append(f"vpc {st['vpc']} is still describable: {still!r}")
        except ClientError as exc:
            if _code(exc) != "InvalidVpcID.NotFound":
                raise
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


# ===== helpers ===============================================================


def _unless_gone(fn, *codes):
    """A backup cleanup the in-band teardown may already have done: only *codes* (the resource's
    own not-found) count as done; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, what, ctx):
    """Bounded retry, capped by the run's remaining time, that RAISES on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"{what} was not observed within {timeout_s:.0f}s; last saw {last!r}")


def _retry_dependency(fn, attempts=120, delay=2.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "VolumeInUse", "IncorrectState",
                                  "RequestLimitExceeded") or attempt == attempts - 1:
                raise
            time.sleep(delay)


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


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _mappings(ec2, instance_id):
    """{DeviceName: Ebs-block} from DescribeInstances — hard-subscripted, never .get-defaulted."""
    inst = _describe(ec2, instance_id)
    assert inst is not None, f"DescribeInstances no longer knows instance {instance_id!r}"
    out = {}
    for mapping in inst["BlockDeviceMappings"]:
        out[mapping["DeviceName"]] = mapping["Ebs"]
    return out


def _volume(ec2, volume_id):
    try:
        vols = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    except ClientError as exc:
        if _code(exc) == _ERR_NO_VOLUME:
            return None
        raise
    return vols[0] if vols else None


def _volume_state(ec2, volume_id):
    vol = _volume(ec2, volume_id)
    return "__gone__" if vol is None else vol["State"]


def _attachment(ec2, volume_id, instance_id):
    vol = _volume(ec2, volume_id)
    assert vol is not None, f"volume {volume_id!r} vanished before its attachment could be read"
    matching = [a for a in vol["Attachments"] if a["InstanceId"] == instance_id]
    assert len(matching) == 1, (
        f"volume {volume_id} must report exactly one attachment to {instance_id}, got "
        f"{vol['Attachments']!r}"
    )
    return matching[0]


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _zones_offering(ec2, instance_type):
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }
    assert usable, f"no available zone in this region offers {instance_type!r}"
    return usable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
