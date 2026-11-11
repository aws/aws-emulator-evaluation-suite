"""list-snapshot-blocks-starting-block-index-windows-the-listing."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# API_ListSnapshotBlocks StartingBlockIndex: "The list in the response will start from this block
# index or the next valid block index in the snapshot." So for written indexes W, a listing from S
# is exactly {i in W : i >= S}, and a start past the last written index lists no blocks.
# Token VALUES are not compared across reads: ListSnapshotBlocks returns an ExpiryTime, so tokens
# may rotate per call.
CHECK = "list-snapshot-blocks-starting-block-index-windows-the-listing"
GROUP = "data-plane"
# ec2 is used only to poll snapshot state (DescribeSnapshots) and for teardown (DeleteSnapshot).
SERVICES = ["ebs"]

#: Fixed EBS direct-API block size, 512 KiB — an API constant, not an account quota.
_BLOCK_SIZE = 524288
_VOLUME_GIB = 1

#: Deliberately sparse. Index 0 is left UNWRITTEN so that S=0 exercises the "or the next valid
#: block index" clause rather than an exact hit.
_WRITTEN_INDEXES = (3, 9, 17)
#: Past the last written index but far inside a 1 GiB volume's 2048 blocks, so it cannot be
#: confused with an out-of-volume rejection.
_PROBE_PAST_END = 18
#: S values: before all, exactly on a written index, in the gap just after one, exactly on the
#: last one, and past the end.
_PROBES = (0, 3, 4, 9, 10, 17, _PROBE_PAST_END)
#: How many identical unwindowed reads must agree.
_FREEZE_READS = 3

#: Whole-check ceiling.
_CHECK_BUDGET_S = 400.0
#: The snapshot's pending -> terminal convergence, observed at EC2.
_CONVERGE_TIMEOUT_S = 180.0
#: The EBS direct-API read plane can lag EC2's `completed` signal; bounded retry, never a sleep.
_DATAPLANE_TIMEOUT_S = 60.0
#: Bound for leaving `pending` in teardown; it fits the suite's cleanup budget.
_CLEANUP_WAIT_S = 120.0
_POLL_INTERVAL_S = 3.0


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSnapshotBlocks(StartingBlockIndex=S) returns exactly the written indexes >= S, and a
    token from a windowed page still serves that index's exact bytes.
    """
    ebs = ctx.client("ebs")
    end = time.monotonic() + _CHECK_BUDGET_S
    tag_value = ctx.unique_name("sim2real-ebs-startindex-")

    written = {idx: os.urandom(_BLOCK_SIZE) for idx in _WRITTEN_INDEXES}
    snapshot_id = ebs.start_snapshot(
        VolumeSize=_VOLUME_GIB,
        Description=f"{CHECK} {tag_value}",
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda sid=snapshot_id: _cleanup_snapshot(ctx, sid))

    for idx in _WRITTEN_INDEXES:
        data = written[idx]
        ebs.put_snapshot_block(
            SnapshotId=snapshot_id,
            BlockIndex=idx,
            BlockData=data,
            DataLength=len(data),
            Checksum=_sha256_b64(data),
            ChecksumAlgorithm="SHA256",
        )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=len(_WRITTEN_INDEXES))
    _wait_completed(ctx, snapshot_id, _bounded(end, _CONVERGE_TIMEOUT_S))

    # Baseline: the unwindowed listing is the positive control for every window below.
    baseline = _list_blocks(ebs, snapshot_id, None, _bounded(end, _DATAPLANE_TIMEOUT_S))
    baseline_indexes = set(baseline)
    assert baseline_indexes == set(_WRITTEN_INDEXES), (
        f"unwindowed ListSnapshotBlocks must enumerate exactly the written indexes "
        f"{sorted(_WRITTEN_INDEXES)}, got {sorted(baseline_indexes)}"
    )

    # Three consecutive reads must not change what the snapshot contains.
    for read_n in range(2, _FREEZE_READS + 1):
        again = set(_list_blocks(ebs, snapshot_id, None, _bounded(end, _DATAPLANE_TIMEOUT_S)))
        assert again == baseline_indexes, (
            f"read {read_n} of {_FREEZE_READS} of the SAME completed snapshot returned index set "
            f"{sorted(again)}; reads must not change state, expected {sorted(baseline_indexes)}"
        )

    # The windowing rule, asserted as a rule over indexes this check chose.
    for start in _PROBES:
        expected = {i for i in _WRITTEN_INDEXES if i >= start}
        page = _list_blocks(ebs, snapshot_id, start, _bounded(end, _DATAPLANE_TIMEOUT_S))
        assert set(page) == expected, (
            f"StartingBlockIndex={start} must return exactly the written indexes >= {start}, i.e. "
            f"{sorted(expected)} out of written {sorted(_WRITTEN_INDEXES)}; got {sorted(page)}"
        )

    # Read back via GetSnapshotBlock using a token taken from a WINDOWED page, against bytes
    # generated in this process.
    window_after_first = _list_blocks(ebs, snapshot_id, 4, _bounded(end, _DATAPLANE_TIMEOUT_S))
    window_at_last = _list_blocks(ebs, snapshot_id, 17, _bounded(end, _DATAPLANE_TIMEOUT_S))
    for windowed, start, idx in ((window_after_first, 4, 9), (window_at_last, 17, 17)):
        token = windowed[idx]
        assert token, f"the StartingBlockIndex={start} page carried no BlockToken for index {idx}"
        got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=idx, BlockToken=token)
        body = got["BlockData"].read()
        assert body == written[idx], (
            f"the token returned for index {idx} in the StartingBlockIndex={start} page served "
            f"{len(body)} bytes with sha256 {_sha256_b64(body)}; expected the {_BLOCK_SIZE} bytes "
            f"written to index {idx}, sha256 {_sha256_b64(written[idx])} — a windowed listing must "
            "not shift the index-to-token pairing"
        )
        assert got["Checksum"] == _sha256_b64(written[idx]), (
            f"index {idx} via the StartingBlockIndex={start} page reported Checksum "
            f"{got['Checksum']}, expected {_sha256_b64(written[idx])}"
        )


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _bounded(check_end: float, timeout_s: float) -> float:
    """The earlier of this phase's own deadline and the whole check's ceiling."""
    return min(time.monotonic() + timeout_s, check_end)


def _list_blocks(ebs, snapshot_id: str, starting_block_index, deadline: float) -> dict:
    """{BlockIndex: BlockToken} across every page, optionally windowed by StartingBlockIndex, and
    retried on ResourceNotFoundException while the read plane lags EC2's `completed` signal.

    Reference: https://docs.aws.amazon.com/ebs/latest/APIReference/API_ListSnapshotBlocks.html
    """
    last_err = None
    while time.monotonic() < deadline:
        try:
            out: dict = {}
            next_token = None
            first_page = True
            while True:
                # NextToken overrides StartingBlockIndex, so the window is sent on the first page
                # only. MaxResults is never passed: its 100-10000 range cannot window 3 blocks.
                kwargs = {"SnapshotId": snapshot_id}
                if next_token:
                    kwargs["NextToken"] = next_token
                elif first_page and starting_block_index is not None:
                    kwargs["StartingBlockIndex"] = starting_block_index
                page = ebs.list_snapshot_blocks(**kwargs)
                assert page["VolumeSize"] == _VOLUME_GIB, (
                    f"ListSnapshotBlocks reported VolumeSize={page['VolumeSize']}, expected the "
                    f"{_VOLUME_GIB} GiB the snapshot was started with"
                )
                assert page["BlockSize"] == _BLOCK_SIZE, (
                    f"ListSnapshotBlocks reported BlockSize={page['BlockSize']}, expected the "
                    f"fixed EBS direct-API block size {_BLOCK_SIZE}"
                )
                # _PROBE_PAST_END expects an empty result, so a missing Blocks list means empty.
                for block in page.get("Blocks", []):
                    idx = block["BlockIndex"]
                    assert idx not in out, (
                        f"ListSnapshotBlocks reported block index {idx} on two pages of one "
                        f"listing of snapshot {snapshot_id}"
                    )
                    out[idx] = block["BlockToken"]
                first_page = False
                next_token = page.get("NextToken")
                if not next_token:
                    return out
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = exc
            time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"ListSnapshotBlocks never found completed snapshot {snapshot_id} within the deadline "
        f"(StartingBlockIndex={starting_block_index}); last error={last_err}"
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
