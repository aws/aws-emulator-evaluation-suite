"""list-snapshot-blocks-maxresults-out-of-range-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-snapshot-blocks-maxresults-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSnapshotBlocks with MaxResults below the documented 100 minimum is rejected by EBS
    itself; the call goes through a parameter-validation-disabled client so botocore's own
    min:100 range check does not stop it before the wire."""
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-ebs-")}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    # MaxResults=50 violates the documented 100-10000 range. A normal client stops this
    # ParamValidationError before it ever leaves the SDK, which asserts nothing about the
    # target, so route it through a client with parameter validation disabled to observe the
    # server's own enforcement. The data plane can also transiently lag EC2's completed-state
    # signal with ResourceNotFoundException right after completion; that is not the boundary
    # under test, so retry through it.
    raw = ctx.client("ebs", config=Config(parameter_validation=False))
    code, msg = _error_code_with_lag_retry(
        lambda: raw.list_snapshot_blocks(SnapshotId=snapshot_id, MaxResults=50)
    )
    assert code == "ValidationException", f"got code={code}"
    assert msg == (
        "1 validation error detected: Value '50' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 100"
    ), f"got msg={msg!r}"

    # positive control: a MaxResults value inside the allowed 100-10000 range succeeds
    listing = _list_blocks_with_retry(ebs, snapshot_id, max_results=100)
    assert {b["BlockIndex"] for b in listing["Blocks"]} == {0}, f"got {listing['Blocks']!r}"


# ===== helpers =====
def _error_code_with_lag_retry(fn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "ResourceNotFoundException":
                return code, e.response["Error"].get("Message")
            last = code
            time.sleep(interval_s)
        else:
            raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
    raise AssertionError(f"ListSnapshotBlocks never resolved past ResourceNotFoundException lag (last={last})")


def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=180.0, interval_s=3.0, max_results=None):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = {"MaxResults": max_results} if max_results else {}
    while time.monotonic() < deadline:
        try:
            return ebs.list_snapshot_blocks(SnapshotId=snapshot_id, **kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListSnapshotBlocks never found completed snapshot {snapshot_id}: {last_err}")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


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


def _delete_snapshot(ctx, snapshot_id):
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
