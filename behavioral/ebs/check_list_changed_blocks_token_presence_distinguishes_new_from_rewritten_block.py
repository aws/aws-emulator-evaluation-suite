"""list-changed-blocks-token-presence-distinguishes-new-from-rewritten-block."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ListChangedBlocks reports the blocks that differ between two snapshots of the same volume.
# API_ChangedBlock: FirstBlockToken "is absent if the first snapshot does not have the changed
# block that is on the second snapshot". The check asserts falsiness, so a missing key and an
# empty string both count as absent. ChangedBlocksCount is passed truthfully but not relied on:
# AWS does not validate it.

CHECK = "list-changed-blocks-token-presence-distinguishes-new-from-rewritten-block"
GROUP = "data-plane"
# ec2 is used only to poll snapshot state (DescribeSnapshots) and for teardown (DeleteSnapshot).
SERVICES = ["ebs"]

#: Fixed EBS direct-API block size, 512 KiB — an API constant, not an account quota.
_BLOCK_SIZE = 524288
_VOLUME_GIB = 1

_INHERITED_INDEX = 0  # written to the parent only; the child never touches it
_REWRITTEN_INDEX = 1  # present in BOTH snapshots with DIFFERENT bytes
_NEW_INDEX = 2  # present in the CHILD only — the index the parent does not have

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
    """ListChangedBlocks omits FirstBlockToken for an index the parent lacks, carries both tokens
    for a rewritten index, and every token it mints serves the exact bytes written to that snapshot.
    """
    ebs = ctx.client("ebs")
    end = time.monotonic() + _CHECK_BUDGET_S
    tag_value = ctx.unique_name("sim2real-ebs-changed-tokens-")

    # The parent: two blocks, bytes generated here so the expected values exist only in-process.
    parent_bytes = {
        _INHERITED_INDEX: os.urandom(_BLOCK_SIZE),
        _REWRITTEN_INDEX: os.urandom(_BLOCK_SIZE),
    }
    parent_id = _start_snapshot(ebs, tag_value, "parent")
    ctx.on_cleanup(lambda sid=parent_id: _cleanup_snapshot(ctx, sid))
    _write_blocks(ebs, parent_id, parent_bytes)
    ebs.complete_snapshot(SnapshotId=parent_id, ChangedBlocksCount=len(parent_bytes))
    _wait_completed(ctx, parent_id, _bounded(end, _CONVERGE_TIMEOUT_S))

    # The child: rewrites one index the parent has, adds one the parent does not.
    child_bytes = {
        _REWRITTEN_INDEX: os.urandom(_BLOCK_SIZE),
        _NEW_INDEX: os.urandom(_BLOCK_SIZE),
    }
    assert child_bytes[_REWRITTEN_INDEX] != parent_bytes[_REWRITTEN_INDEX], (
        f"the two 512 KiB os.urandom draws for index {_REWRITTEN_INDEX} collided, so 'rewritten' "
        "would be indistinguishable from 'unchanged' and the rest of this check would be vacuous"
    )
    child_id = _start_child_snapshot(ebs, parent_id, tag_value, _bounded(end, _PARENT_READY_TIMEOUT_S))
    ctx.on_cleanup(lambda sid=child_id: _cleanup_snapshot(ctx, sid))
    _write_blocks(ebs, child_id, child_bytes)
    ebs.complete_snapshot(SnapshotId=child_id, ChangedBlocksCount=len(child_bytes))
    _wait_completed(ctx, child_id, _bounded(end, _CONVERGE_TIMEOUT_S))

    # The diff is exactly the set arithmetic over blocks this check chose.
    changed = _list_all_changed_blocks(ebs, parent_id, child_id, _bounded(end, _DATAPLANE_TIMEOUT_S))
    by_index = {}
    for entry in changed:
        idx = entry["BlockIndex"]
        assert idx not in by_index, f"ListChangedBlocks reported block index {idx} twice: {changed}"
        by_index[idx] = entry
    expected_changed = {_REWRITTEN_INDEX, _NEW_INDEX}
    assert set(by_index) == expected_changed, (
        f"expected ChangedBlocks indexes {sorted(expected_changed)} (index {_REWRITTEN_INDEX} was "
        f"rewritten, index {_NEW_INDEX} is new, index {_INHERITED_INDEX} was inherited untouched), "
        f"got {sorted(by_index)}"
    )

    # Token PRESENCE is what tells "new in the child" from "rewritten in the child".
    rewritten = by_index[_REWRITTEN_INDEX]
    new_block = by_index[_NEW_INDEX]
    assert rewritten.get("FirstBlockToken"), (
        f"index {_REWRITTEN_INDEX} exists in the parent, so its ChangedBlock must carry a "
        f"FirstBlockToken; got entry {_redact(rewritten)}"
    )
    assert rewritten.get("SecondBlockToken"), (
        f"index {_REWRITTEN_INDEX} exists in the child, so its ChangedBlock must carry a "
        f"SecondBlockToken; got entry {_redact(rewritten)}"
    )
    assert new_block.get("SecondBlockToken"), (
        f"index {_NEW_INDEX} exists in the child, so its ChangedBlock must carry a "
        f"SecondBlockToken; got entry {_redact(new_block)}"
    )
    assert not new_block.get("FirstBlockToken"), (
        f"the parent does not have index {_NEW_INDEX}, so FirstBlockToken must be ABSENT for it "
        f"(API_ChangedBlock); got FirstBlockToken present in entry {_redact(new_block)}"
    )

    # Read back through GetSnapshotBlock using only the tokens ListChangedBlocks minted; the
    # expected bytes are the ones generated in memory.
    _assert_block_bytes(
        ebs, child_id, _NEW_INDEX, new_block["SecondBlockToken"], child_bytes[_NEW_INDEX],
        "the child's SecondBlockToken for the index only the child has",
    )
    _assert_block_bytes(
        ebs, child_id, _REWRITTEN_INDEX, rewritten["SecondBlockToken"],
        child_bytes[_REWRITTEN_INDEX],
        "the child's SecondBlockToken for the rewritten index",
    )
    _assert_block_bytes(
        ebs, parent_id, _REWRITTEN_INDEX, rewritten["FirstBlockToken"],
        parent_bytes[_REWRITTEN_INDEX],
        "the parent's FirstBlockToken for the rewritten index — the pre-overwrite bytes must "
        "still be served from the parent",
    )


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _redact(entry: dict) -> dict:
    """A ChangedBlock with token VALUES replaced by their presence, so a truncated failure detail
    is not consumed by two opaque base64 blobs."""
    return {
        "BlockIndex": entry.get("BlockIndex"),
        "FirstBlockToken": "<present>" if entry.get("FirstBlockToken") else "<absent>",
        "SecondBlockToken": "<present>" if entry.get("SecondBlockToken") else "<absent>",
    }


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


def _write_blocks(ebs, snapshot_id: str, blocks: dict) -> None:
    for idx in sorted(blocks):
        data = blocks[idx]
        resp = ebs.put_snapshot_block(
            SnapshotId=snapshot_id,
            BlockIndex=idx,
            BlockData=data,
            DataLength=len(data),
            Checksum=_sha256_b64(data),
            ChecksumAlgorithm="SHA256",
        )
        assert resp["Checksum"] == _sha256_b64(data), (
            f"PutSnapshotBlock({snapshot_id}, {idx}) echoed Checksum={resp['Checksum']}, expected "
            f"the SHA256 of the bytes sent ({_sha256_b64(data)})"
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


def _list_all_changed_blocks(ebs, first_id: str, second_id: str, deadline: float) -> list:
    """Every page of ListChangedBlocks, retried on ResourceNotFoundException while the read plane
    lags EC2's `completed` signal. Raises on timeout."""
    last_err = None
    while time.monotonic() < deadline:
        try:
            blocks: list = []
            next_token = None
            while True:
                kwargs = {"FirstSnapshotId": first_id, "SecondSnapshotId": second_id}
                if next_token:
                    kwargs["NextToken"] = next_token
                page = ebs.list_changed_blocks(**kwargs)
                assert page["VolumeSize"] == _VOLUME_GIB, (
                    f"ListChangedBlocks reported VolumeSize={page['VolumeSize']}, expected the "
                    f"{_VOLUME_GIB} GiB both snapshots were started with"
                )
                assert page["BlockSize"] == _BLOCK_SIZE, (
                    f"ListChangedBlocks reported BlockSize={page['BlockSize']}, expected the fixed "
                    f"EBS direct-API block size {_BLOCK_SIZE}"
                )
                blocks.extend(page["ChangedBlocks"])
                next_token = page.get("NextToken")
                if not next_token:
                    return blocks
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = exc
            time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"ListChangedBlocks never found the completed pair {first_id},{second_id} within the "
        f"deadline; last error={last_err}"
    )


def _assert_block_bytes(ebs, snapshot_id: str, index: int, token: str, expected: bytes, why: str) -> None:
    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=index, BlockToken=token)
    body = got["BlockData"].read()
    assert body == expected, (
        f"{why}: GetSnapshotBlock({snapshot_id}, {index}) returned {len(body)} bytes with sha256 "
        f"{_sha256_b64(body)}, expected the {len(expected)} bytes this check wrote with sha256 "
        f"{_sha256_b64(expected)}"
    )
    assert got["DataLength"] == len(expected), (
        f"{why}: DataLength={got['DataLength']}, expected {len(expected)}"
    )
    assert got["Checksum"] == _sha256_b64(expected), (
        f"{why}: Checksum={got['Checksum']}, expected the SHA256 of the written bytes "
        f"{_sha256_b64(expected)}"
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
