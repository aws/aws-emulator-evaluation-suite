"""start-snapshot-invalid-volume-size-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-invalid-volume-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["ebs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSnapshot with VolumeSize=0 (below the documented minimum of 1 GiB) is rejected (quota/range boundary)."""
    ebs = ctx.client("ebs")

    # VolumeSize=0 violates the documented minimum of 1, but botocore's own service model
    # already carries that minimum (min=1), so a normally-validated client raises
    # ParamValidationError locally and the request never reaches the target -- an assertion
    # that accepts that as evidence would pass against any target, correct or not. Send it
    # through an unvalidated client so the target itself has to reject it.
    unvalidated_ebs = ctx.client("ebs", config=Config(parameter_validation=False))
    code, msg = _error(lambda: unvalidated_ebs.start_snapshot(VolumeSize=0))
    assert code == "ValidationException", f"got code={code} msg={msg!r}"
    expected_msg = (
        "1 validation error detected: Value '0' at 'volumeSize' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert msg == expected_msg, f"ValidationException message: {msg!r}, expected {expected_msg!r}"

    # positive control: the minimum valid VolumeSize succeeds
    resp = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-invalid-volume-size"}],
    )
    snapshot_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))
    assert resp["VolumeSize"] == 1
    assert resp["Status"] == "pending"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting an out-of-range value must not be reported as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected StartSnapshot(VolumeSize=0) to be rejected, but it SUCCEEDED: {result!r}")


def _wait_for_snapshot_state(ctx, snapshot_id, states, timeout_s=120.0, interval_s=3.0):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
            last = resp["Snapshots"][0]["State"]
            if last in states:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} never reached {states} (last={last})")


def _finalize_and_delete_snapshot(ctx, snapshot_id, changed_blocks_count=0):
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    try:
        ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=changed_blocks_count)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=120.0)
    except AssertionError:
        pass
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
