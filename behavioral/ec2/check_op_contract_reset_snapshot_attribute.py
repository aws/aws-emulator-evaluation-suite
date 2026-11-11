"""op-contract-reset-snapshot-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-reset-snapshot-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetSnapshotAttribute clears a createVolumePermission grant added via
    ModifySnapshotAttribute; the documented placeholder snapshot id is rejected with
    InvalidSnapshotID.Malformed."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # A grant to the owner account never appears in DescribeSnapshotAttribute, so grant to a
    # different account id; the grantee need not exist for the grant to be recorded.
    grantee_account_id = "111111111111" if account_id != "111111111111" else "222222222222"

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-reset-snapattr-")
    volume_id = ec2.create_volume(
        Size=1, AvailabilityZone=az, VolumeType="gp3",
        TagSpecifications=[_tag_spec("volume", name)],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap_id = ec2.create_snapshot(
        VolumeId=volume_id, TagSpecifications=[_tag_spec("snapshot", name)]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ec2.modify_snapshot_attribute(
        SnapshotId=snap_id,
        Attribute="createVolumePermission",
        OperationType="add",
        UserIds=[grantee_account_id],
    )
    perms = _poll_until(
        lambda: ec2.describe_snapshot_attribute(
            SnapshotId=snap_id, Attribute="createVolumePermission"
        )["CreateVolumePermissions"],
        lambda perms: any(p.get("UserId") == grantee_account_id for p in perms),
        timeout_s=60,
        interval_s=3,
    )
    assert any(p.get("UserId") == grantee_account_id for p in perms), "grant did not take effect"

    ec2.reset_snapshot_attribute(SnapshotId=snap_id, Attribute="createVolumePermission")
    perms_after = _poll_until(
        lambda: ec2.describe_snapshot_attribute(
            SnapshotId=snap_id, Attribute="createVolumePermission"
        )["CreateVolumePermissions"],
        lambda perms: perms == [],
        timeout_s=60,
        interval_s=3,
    )
    assert perms_after == [], f"reset did not clear createVolumePermission grants: {perms_after}"

    # The documented placeholder id fails ResetSnapshotAttribute's id-format validation, so
    # it is rejected as Malformed before the NotFound existence check.
    code, message = _client_error(
        lambda: ec2.reset_snapshot_attribute(
            SnapshotId="snap-1234567890abcdef0", Attribute="createVolumePermission"
        )
    )
    assert code == "InvalidSnapshotID.Malformed", f"unexpected error code: {code}"
    expected_message = "The snapshot ID 'snap-1234567890abcdef0' is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last result: {result!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
