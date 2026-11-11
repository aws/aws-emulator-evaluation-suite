"""create-image-and-snapshots-from-instance."""
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


def _terminate_and_wait(ec2, instance_ids):
    """Best-effort teardown: terminate instances then wait for them to reach
    'terminated' so dependent SGs/subnets/VPC become deletable."""
    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise
    for iid in instance_ids:
        try:
            _wait_instance_state(ec2, iid, "terminated", timeout_s=120)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise


def _deregister_with_snapshots(ec2, image_id, timeout_s=120.0):
    """Teardown: deregister the AMI and delete the snapshots behind it. The block device mappings
    can still be empty right after CreateImage, so wait (bounded) for them before deregistering."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            images = ec2.describe_images(ImageIds=[image_id])["Images"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                raise
            images = []
        snapshot_ids = [
            m["Ebs"]["SnapshotId"]
            for image in images
            for m in image.get("BlockDeviceMappings", [])
            if "SnapshotId" in m.get("Ebs", {})
        ]
        if snapshot_ids or not images or time.monotonic() >= deadline:
            break
        time.sleep(5)
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise
    for snapshot_id in snapshot_ids:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise


def _error(fn):
    """Call *fn*; return its (code, message). An unexpected SUCCESS raises, because a target
    accepting what real AWS refuses is reported as that success, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "create-image-and-snapshots-from-instance"
GROUP = 'ami'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImage/CreateSnapshots derive from a live instance and validate duplicates."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.108.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.108.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    try:
        run_resp = ec2.run_instances(
            ImageId=_test_ami_id(ec2),
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        # A fresh/low-quota account may have no On-Demand vCPU or instance
        # headroom — a prerequisite gap for this check, not a fidelity failure.
        if code in {
            "VcpuLimitExceeded",
            "InstanceLimitExceeded",
            "InsufficientInstanceCapacity",
            "MaxSpotInstanceCountExceeded",
        }:
            raise AssertionError(f"cannot launch a test instance on this account ({code})")
        raise
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, [instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    image_name = ctx.unique_name("ami-")
    img = ec2.create_image(
        InstanceId=instance_id, Name=image_name, NoReboot=True, Description="behavioral check",
        TagSpecifications=[{"ResourceType": "image", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    image_id = img["ImageId"]
    ctx.on_cleanup(lambda: _deregister_with_snapshots(ec2, image_id))

    # Independent read at a different operation than the one that mutated: confirm the image
    # is actually registered under the account, not just that CreateImage's own response said so.
    described_images = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
    assert len(described_images) == 1 and described_images[0]["Name"] == image_name, (
        f"expected DescribeImages to show one image {image_id!r} named {image_name!r}, "
        f"got {described_images!r}"
    )

    dup, dup_message = _error(
        lambda: ec2.create_image(InstanceId=instance_id, Name=image_name, NoReboot=True)
    )
    assert dup == "InvalidAMIName.Duplicate", (
        f"expected InvalidAMIName.Duplicate, got {dup}"
    )
    assert dup_message == f"AMI name {image_name} is already in use by AMI {image_id}", dup_message

    # The target's own reported state, not an assumed count: CreateSnapshots must snapshot
    # exactly the volumes DescribeInstances says are attached, no more and no fewer.
    attached_volume_ids = {
        bdm["Ebs"]["VolumeId"]
        for bdm in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
            "BlockDeviceMappings", []
        )
        if "Ebs" in bdm
    }
    assert attached_volume_ids, "expected at least one attached EBS volume"

    # CreateSnapshots produces one snapshot per attached volume. CreateImage(NoReboot) above
    # already snapshotted the boot volume, so an immediate CreateSnapshots on the same volume
    # can hit the per-volume snapshot rate limit — AWS asks for an increasing/variable sleep,
    # so retry with backoff on SnapshotCreationPerVolumeRateExceeded.
    def _create_snapshots_with_backoff():
        delay = 15.0
        for attempt in range(6):
            try:
                return ec2.create_snapshots(
                    InstanceSpecification={"InstanceId": instance_id, "ExcludeBootVolume": False},
                    Description="behavioral multi-volume snapshot",
                    TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "SnapshotCreationPerVolumeRateExceeded" and attempt < 5:
                    time.sleep(delay)
                    delay *= 1.5
                    continue
                raise

    snaps = _create_snapshots_with_backoff()
    created = snaps["Snapshots"]
    for s in created:
        sid = s["SnapshotId"]
        ctx.on_cleanup(lambda sid=sid: ec2.delete_snapshot(SnapshotId=sid))

    snapped_volume_ids = {s["VolumeId"] for s in created}
    assert snapped_volume_ids == attached_volume_ids, (
        f"snapshot volume set {snapped_volume_ids!r} != attached volumes {attached_volume_ids!r}"
    )

    # Independent read at a different operation than the one that mutated: the snapshots must
    # actually be visible via DescribeSnapshots, not just present in CreateSnapshots' own response.
    snap_ids = [s["SnapshotId"] for s in created]
    described_snaps = ec2.describe_snapshots(SnapshotIds=snap_ids)["Snapshots"]
    assert {d["SnapshotId"] for d in described_snaps} == set(snap_ids), (
        f"expected DescribeSnapshots to show {snap_ids!r}, got "
        f"{[d['SnapshotId'] for d in described_snaps]!r}"
    )

    bad, bad_message = _error(
        lambda: ec2.create_snapshots(
            InstanceSpecification={"InstanceId": "i-0123456789abcdef0"}
        )
    )
    assert bad in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"), (
        f"expected InvalidInstanceID.NotFound/Malformed, got {bad}"
    )
    if bad == "InvalidInstanceID.Malformed":
        assert bad_message == "Unable to unobfuscate ID.", bad_message


# ===== helpers =====

# Network teardown: resources in the VPC delete asynchronously and leave AWS-managed ENIs behind,
# so DeleteSubnet / DeleteSecurityGroup / DeleteVpc can fail with DependencyViolation. Wait (bounded,
# one window shared by all of a check's network deletes) for the ENIs, retrying that error, then
# raise naming the ENIs still attached. Teardown-only; run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
