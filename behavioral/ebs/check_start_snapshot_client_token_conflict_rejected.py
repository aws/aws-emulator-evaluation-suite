"""start-snapshot-client-token-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-client-token-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken with a different request payload is rejected with ConflictException,
    and once visible to DescribeSnapshots the original snapshot keeps its own size and description."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    token = ctx.unique_name("sim2real-ebs-tok-")
    tag_value = ctx.unique_name("ebs-behav-token-conflict-")

    first = ebs.start_snapshot(
        VolumeSize=1,
        Description="payload-A",
        ClientToken=token,
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )
    snapshot_id = first["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))

    code, msg = _error(lambda: ebs.start_snapshot(VolumeSize=2, Description="payload-B", ClientToken=token))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {msg!r}"
    expected_msg = "Current request does not match request stored with this token."
    assert msg == expected_msg, f"ConflictException message: {msg!r}, expected {expected_msg!r}"

    # effect-absent: the rejected payload-B request must not have touched the snapshot already
    # on record for this token. describe_snapshots is independent of start_snapshot.
    described = _describe_snapshot(ctx, ec2, snapshot_id)
    assert described["VolumeSize"] == 1, (
        f"conflicting StartSnapshot mutated VolumeSize to {described['VolumeSize']}, expected 1"
    )
    assert described["Description"] == "payload-A", (
        f"conflicting StartSnapshot mutated Description to {described['Description']!r}, expected 'payload-A'"
    )

    # restore: reusing the token with the ORIGINAL matching payload (Tags included — EBS
    # compares the full stored request) is still idempotent
    retry = ebs.start_snapshot(
        VolumeSize=1,
        Description="payload-A",
        ClientToken=token,
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )
    assert retry["SnapshotId"] == snapshot_id, (
        f"idempotent retry returned {retry['SnapshotId']!r}, expected {snapshot_id!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _describe_snapshot(ctx, ec2, snapshot_id, cap_s=60.0):
    """DescribeSnapshots, retried while the new id has not yet propagated to EC2."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        try:
            return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
            if time.monotonic() >= deadline:
                if budget_s < cap_s:
                    raise TimeoutError(
                        f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                        f"{cap_s}s wait ended with {snapshot_id} not yet visible; not graded"
                    )
                raise AssertionError(f"snapshot {snapshot_id} never became visible to DescribeSnapshots: {e}")
        time.sleep(2.0)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ClientError from the conflicting StartSnapshot, but it succeeded with {result!r}")


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
