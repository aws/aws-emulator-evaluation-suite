"""incremental-child-lists-and-serves-inherited-parent-blocks."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ListSnapshotBlocks on an incremental child lists every block of the volume image, including the
# blocks it inherited from its parent, not only its own increment (EBS direct APIs launch post:
# for the child Snap2 it "would return [T0 ... T7] with updated values for T0 and T4").
# Whether an unchanged index has the same BlockToken in parent and child listings is NOT
# asserted: tokens carry an ExpiryTime and may be issued per call.

CHECK = "incremental-child-lists-and-serves-inherited-parent-blocks"
GROUP = "data-plane"
# ec2 is used only to poll snapshot state (DescribeSnapshots) and for teardown (DeleteSnapshot).
SERVICES = ["ebs"]

#: Fixed EBS direct-API block size, 512 KiB — an API constant, not an account quota.
_BLOCK_SIZE = 524288
_VOLUME_GIB = 1

_INHERITED_INDEX = 0  # written to the parent; the child never touches it
_REWRITTEN_INDEX = 1  # written to BOTH, with different bytes
_NEVER_WRITTEN_INDEX = 2  # written to NEITHER; must appear in neither listing

#: Whole-check ceiling.
_CHECK_BUDGET_S = 700.0
#: One snapshot's pending -> terminal convergence, observed at EC2.
_CONVERGE_TIMEOUT_S = 180.0
#: The EBS direct-API read plane can lag EC2's `completed` signal; bounded retry, never a sleep.
_DATAPLANE_TIMEOUT_S = 60.0
#: StartSnapshot may transiently refuse a just-completed parent as "not complete".
_PARENT_READY_TIMEOUT_S = 60.0
#: Per-snapshot bound for leaving `pending` in teardown; two fit the suite's cleanup budget.
_CLEANUP_WAIT_S = 120.0
_POLL_INTERVAL_S = 3.0


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An incremental child lists the parent's untouched block and serves its exact bytes, while
    the parent still serves its own pre-overwrite bytes for the index the child rewrote.
    """
    ebs = ctx.client("ebs")
    end = time.monotonic() + _CHECK_BUDGET_S
    tag_value = ctx.unique_name("sim2real-ebs-inherit-")

    # Bytes generated here, so the expected values exist only in this process.
    parent_inherited = os.urandom(_BLOCK_SIZE)
    parent_rewritten = os.urandom(_BLOCK_SIZE)
    child_rewritten = os.urandom(_BLOCK_SIZE)
    assert child_rewritten != parent_rewritten, (
        f"the two 512 KiB os.urandom draws for index {_REWRITTEN_INDEX} collided, so 'the child "
        "overwrote it' would be indistinguishable from 'the child inherited it' and every "
        "assertion below would be vacuous"
    )

    parent_id = _start_snapshot(ebs, tag_value, "parent")
    ctx.on_cleanup(lambda sid=parent_id: _cleanup_snapshot(ctx, sid))
    _put(ebs, parent_id, _INHERITED_INDEX, parent_inherited)
    _put(ebs, parent_id, _REWRITTEN_INDEX, parent_rewritten)
    ebs.complete_snapshot(SnapshotId=parent_id, ChangedBlocksCount=2)
    _wait_completed(ctx, parent_id, _bounded(end, _CONVERGE_TIMEOUT_S))

    # The child writes ONE block. It never sends anything for _INHERITED_INDEX.
    child_id = _start_child_snapshot(ebs, parent_id, tag_value, _bounded(end, _PARENT_READY_TIMEOUT_S))
    ctx.on_cleanup(lambda sid=child_id: _cleanup_snapshot(ctx, sid))
    _put(ebs, child_id, _REWRITTEN_INDEX, child_rewritten)
    ebs.complete_snapshot(SnapshotId=child_id, ChangedBlocksCount=1)
    _wait_completed(ctx, child_id, _bounded(end, _CONVERGE_TIMEOUT_S))

    # The child's listing is the whole volume image, not just the child's increment.
    child_blocks = _list_blocks(ebs, child_id, _bounded(end, _DATAPLANE_TIMEOUT_S))
    expected_indexes = {_INHERITED_INDEX, _REWRITTEN_INDEX}
    assert set(child_blocks) == expected_indexes, (
        f"the incremental child wrote ONLY index {_REWRITTEN_INDEX} but must list the whole volume "
        f"image {sorted(expected_indexes)} (index {_INHERITED_INDEX} inherited from the parent, "
        f"index {_NEVER_WRITTEN_INDEX} written by nobody and so absent); got "
        f"{sorted(child_blocks)}"
    )

    parent_blocks = _list_blocks(ebs, parent_id, _bounded(end, _DATAPLANE_TIMEOUT_S))
    assert set(parent_blocks) == expected_indexes, (
        f"the parent must still list exactly {sorted(expected_indexes)} after the child rewrote "
        f"index {_REWRITTEN_INDEX}; got {sorted(parent_blocks)}"
    )

    # The inherited block serves the PARENT's bytes through the CHILD.
    _assert_bytes(
        ebs, child_id, _INHERITED_INDEX, child_blocks[_INHERITED_INDEX], parent_inherited,
        f"index {_INHERITED_INDEX} was written to the PARENT and never sent to the child, so the "
        "child must serve the parent's bytes",
    )

    # The child's own write is its own bytes, and NOT the parent's.
    _assert_bytes(
        ebs, child_id, _REWRITTEN_INDEX, child_blocks[_REWRITTEN_INDEX], child_rewritten,
        f"index {_REWRITTEN_INDEX} was overwritten in the child, so the child must serve the "
        "child's bytes",
    )

    # Read back at the PARENT through GetSnapshotBlock: the child's overwrite must not reach the
    # parent (a store keyed on index rather than (snapshot, index) fails here).
    _assert_bytes(
        ebs, parent_id, _REWRITTEN_INDEX, parent_blocks[_REWRITTEN_INDEX], parent_rewritten,
        f"the child overwrote index {_REWRITTEN_INDEX}; the PARENT must still serve its own "
        "pre-overwrite bytes",
    )
    _assert_bytes(
        ebs, parent_id, _INHERITED_INDEX, parent_blocks[_INHERITED_INDEX], parent_inherited,
        f"index {_INHERITED_INDEX} in the parent must be unaffected by the child entirely",
    )


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _bounded(check_end: float, timeout_s: float) -> float:
    """The earlier of this phase's own deadline and the whole check's ceiling."""
    return min(time.monotonic() + timeout_s, check_end)


def _start_snapshot(ebs, tag_value: str, role: str) -> str:
    return ebs.start_snapshot(
        VolumeSize=_VOLUME_GIB,
        Description=f"{CHECK} {role} {tag_value}",
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )["SnapshotId"]


def _start_child_snapshot(ebs, parent_id: str, tag_value: str, deadline: float) -> str:
    """StartSnapshot with a just-completed parent, retried while it transiently refuses it with
    ValidationException "not complete". Raises on timeout rather than returning a sentinel."""
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.start_snapshot(
                VolumeSize=_VOLUME_GIB,
                ParentSnapshotId=parent_id,
                Description=f"{CHECK} child {tag_value}",
                Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
            )["SnapshotId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationException" or "not complete" not in str(err.get("Message", "")):
                raise
            last_err = exc
            time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"StartSnapshot never accepted completed parent {parent_id} as a ParentSnapshotId within "
        f"the deadline; last refusal={last_err}"
    )


def _put(ebs, snapshot_id: str, index: int, data: bytes) -> None:
    resp = ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=index,
        BlockData=data,
        DataLength=len(data),
        Checksum=_sha256_b64(data),
        ChecksumAlgorithm="SHA256",
    )
    assert resp["Checksum"] == _sha256_b64(data), (
        f"PutSnapshotBlock({snapshot_id}, {index}) echoed Checksum={resp['Checksum']}, expected "
        f"the SHA256 of the bytes sent, {_sha256_b64(data)}"
    )


def _wait_completed(ctx, snapshot_id: str, deadline: float) -> None:
    """Poll EC2 until the snapshot is `completed`. The terminal set deliberately EXCLUDES `error`
    so a failed snapshot cannot satisfy the wait."""
    ec2 = ctx.client("ec2")
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
            last = "not-found"
        if last == "completed":
            return
        assert last != "error", (
            f"snapshot {snapshot_id} reached the terminal FAILURE state `error`; the check cannot "
            "continue and this is not a timeout"
        )
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"snapshot {snapshot_id} never reached `completed` within the deadline (last state={last})"
    )


def _list_blocks(ebs, snapshot_id: str, deadline: float) -> dict:
    """{BlockIndex: BlockToken} across every page, retried on ResourceNotFoundException while the
    read plane lags EC2's `completed` signal. Raises on timeout rather than returning partial."""
    last_err = None
    while time.monotonic() < deadline:
        try:
            out: dict = {}
            next_token = None
            while True:
                kwargs = {"SnapshotId": snapshot_id}
                if next_token:
                    kwargs["NextToken"] = next_token
                page = ebs.list_snapshot_blocks(**kwargs)
                assert page["VolumeSize"] == _VOLUME_GIB, (
                    f"ListSnapshotBlocks({snapshot_id}) reported VolumeSize={page['VolumeSize']}, "
                    f"expected the {_VOLUME_GIB} GiB the snapshot was started with"
                )
                assert page["BlockSize"] == _BLOCK_SIZE, (
                    f"ListSnapshotBlocks({snapshot_id}) reported BlockSize={page['BlockSize']}, "
                    f"expected the fixed EBS direct-API block size {_BLOCK_SIZE}"
                )
                for block in page["Blocks"]:
                    idx = block["BlockIndex"]
                    assert idx not in out, (
                        f"ListSnapshotBlocks reported block index {idx} on two pages of one "
                        f"listing of snapshot {snapshot_id}"
                    )
                    out[idx] = block["BlockToken"]
                next_token = page.get("NextToken")
                if not next_token:
                    return out
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = exc
            time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"ListSnapshotBlocks never found completed snapshot {snapshot_id} within the deadline; "
        f"last error={last_err}"
    )


def _assert_bytes(ebs, snapshot_id: str, index: int, token: str, expected: bytes, why: str) -> None:
    assert token, f"{why}: the listing for snapshot {snapshot_id} carried no token for index {index}"
    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=index, BlockToken=token)
    body = got["BlockData"].read()
    assert body == expected, (
        f"{why}: GetSnapshotBlock({snapshot_id}, {index}) served {len(body)} bytes with sha256 "
        f"{_sha256_b64(body)}, expected {len(expected)} bytes with sha256 {_sha256_b64(expected)}"
    )
    assert got["DataLength"] == len(expected), (
        f"{why}: DataLength={got['DataLength']}, expected {len(expected)}"
    )
    assert got["Checksum"] == _sha256_b64(expected), (
        f"{why}: Checksum={got['Checksum']}, expected {_sha256_b64(expected)}"
    )


def _cleanup_snapshot(ctx, snapshot_id: str) -> None:
    """Complete, wait out `pending`, then delete the snapshot this check created; only a
    not-found answer counts as already gone, every other error raises."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    try:
        # A snapshot still `pending` (the check failed before completing it) cannot be deleted.
        ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + _CLEANUP_WAIT_S
    try:
        while ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"] == "pending":
            if time.monotonic() >= deadline:
                raise AssertionError(f"snapshot {snapshot_id} still pending after {_CLEANUP_WAIT_S:.0f}s")
            time.sleep(2)
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
