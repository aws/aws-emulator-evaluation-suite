"""op-contract-modify-snapshot-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-snapshot-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifySnapshotAttribute: granting createVolumePermission to an account is
    reflected by DescribeSnapshotAttribute, and modifying the non-modifiable
    'productCodes' attribute is rejected."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-snap-")
    volume = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3",
        TagSpecifications=[_tag_spec("volume", name)],
    )
    volume_id = volume["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snapshot = ec2.create_snapshot(VolumeId=volume_id, TagSpecifications=[_tag_spec("snapshot", name)])
    snapshot_id = snapshot["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    ec2.get_waiter("snapshot_completed").wait(
        SnapshotIds=[snapshot_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    # The owner implicitly has createVolumePermission, so granting it to the own account is
    # never listed; the "all" group is an observable change.
    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )
    ctx.on_cleanup(
        lambda: ec2.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            OperationType="remove",
            GroupNames=["all"],
        )
    )
    attrs = _poll_until(
        lambda: ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id, Attribute="createVolumePermission"
        )["CreateVolumePermissions"],
        lambda a: any(p.get("Group") == "all" for p in a),
        timeout_s=30,
    )
    assert any(p.get("Group") == "all" for p in attrs), attrs

    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="remove",
        GroupNames=["all"],
    )
    attrs_after_remove = _poll_until(
        lambda: ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id, Attribute="createVolumePermission"
        )["CreateVolumePermissions"],
        lambda a: not any(p.get("Group") == "all" for p in a),
        timeout_s=30,
    )
    assert not any(p.get("Group") == "all" for p in attrs_after_remove), attrs_after_remove

    # error boundary: productCodes is not a modifiable attribute for this operation
    err, err_msg = _client_error(
        lambda: ec2.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="productCodes",
            OperationType="add",
            UserIds=[account_id],
        )
    )
    assert err == "InvalidParameterValue", err
    assert err_msg == "Unrecognized attribute.", err_msg


def _client_error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
