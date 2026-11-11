"""op-contract-create-snapshots."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-snapshots"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSnapshots snapshots exactly the instance's attached EBS volumes, which all complete;
    a fabricated InstanceId is rejected as InvalidInstanceID.Malformed."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-snaps-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})

    attached_volume_ids = {
        bdm["Ebs"]["VolumeId"]
        for bdm in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]["BlockDeviceMappings"]
        if "Ebs" in bdm
    }
    assert attached_volume_ids, "expected at least one attached EBS volume"

    resp = ec2.create_snapshots(
        InstanceSpecification={"InstanceId": instance_id, "ExcludeBootVolume": False},
        Description="sim2real behavioral check",
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-snaps-")}],
            }
        ],
    )
    snapshots = resp["Snapshots"]
    snap_ids = [s["SnapshotId"] for s in snapshots]
    for sid in snap_ids:
        ctx.on_cleanup(lambda sid=sid: ec2.delete_snapshot(SnapshotId=sid))

    assert snapshots, "expected at least one snapshot"
    snapped_volume_ids = {s["VolumeId"] for s in snapshots}
    assert snapped_volume_ids == attached_volume_ids, (
        f"snapshot volume set {snapped_volume_ids!r} != attached volumes {attached_volume_ids!r}"
    )
    for s in snapshots:
        assert s["State"] in ("pending", "completed"), (
            f"snapshot {s['SnapshotId']} in unexpected initial state {s['State']!r}"
        )

    final_states = _poll_until(
        lambda: {
            s["SnapshotId"]: s["State"]
            for s in ec2.describe_snapshots(SnapshotIds=snap_ids)["Snapshots"]
        },
        lambda states: all(v in ("completed", "error") for v in states.values()),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert all(v == "completed" for v in final_states.values()), (
        f"not all snapshots completed: {final_states!r}"
    )

    # EC2 validates the checksum embedded in long-format IDs, so a hand-crafted ID of the right
    # shape is reported as Malformed rather than NotFound.
    code, message = _error_of(
        lambda: ec2.create_snapshots(
            InstanceSpecification={"InstanceId": "i-0123456789abcdef0"}
        )
    )
    assert code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed, got {code!r}"
    )
    assert message == "Unable to unobfuscate ID.", message


def _error_of(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last saw {last!r}")


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:

        raise AssertionError("no al2023 AMI available in this region/account")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
