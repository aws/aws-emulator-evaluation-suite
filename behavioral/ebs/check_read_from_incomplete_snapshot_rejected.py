"""read-from-incomplete-snapshot-rejected."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "read-from-incomplete-snapshot-rejected"
GROUP = 'block-read-rejection'
SERVICES = ['ebs']

BLOCK_SIZE = 524288
READABLE_TIMEOUT_S = 150
#: A syntactically valid BlockToken (base64 of b"ABC") that the service never issued.
FOREIGN_BLOCK_TOKEN = "QUJD"


def _b64_sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _client_error(fn) -> ClientError:
    """Call fn() and return the ClientError it raises (Code and Reason); a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _delete_snapshot(ec2, snapshot_id: str) -> None:
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidSnapshot.NotFound":
            raise


def _list_all_blocks(ebs, snapshot_id: str) -> list[dict]:
    blocks: list[dict] = []
    token = None
    while True:
        kwargs = {"SnapshotId": snapshot_id}
        if token:
            kwargs["NextToken"] = token
        page = ebs.list_snapshot_blocks(**kwargs)
        blocks.extend(page.get("Blocks") or [])
        token = page.get("NextToken")
        if not token:
            return blocks


def _wait_readable(ebs, snapshot_id: str) -> None:
    deadline = time.time() + READABLE_TIMEOUT_S
    last = None
    while time.time() < deadline:
        try:
            ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "ResourceNotFoundException":
                raise
            time.sleep(3)
    raise AssertionError(
        f"snapshot {snapshot_id!r} never became readable within {READABLE_TIMEOUT_S}s "
        f"of CompleteSnapshot; ListSnapshotBlocks still answered {last!r}"
    )


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """While a snapshot is open, ListSnapshotBlocks and GetSnapshotBlock fail with
    ResourceNotFoundException (not-found wins over a bad token); after CompleteSnapshot the
    written block lists and reads back intact."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")

    data = bytes(range(256)) * (BLOCK_SIZE // 256)
    checksum = _b64_sha256(data)

    started = ebs.start_snapshot(
        VolumeSize=1,
        Description=ctx.unique_name("sim2real-behav-ebs-openread-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-behav-open-read"}],
    )
    snapshot_id = started["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))

    put = ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=data,
        DataLength=BLOCK_SIZE,
        Checksum=checksum,
        ChecksumAlgorithm="SHA256",
    )
    assert put["Checksum"] == checksum, (
        f"the write was not acknowledged as stored: echoed Checksum {put['Checksum']!r}, "
        f"expected {checksum!r}"
    )

    listed = _client_error(lambda: ebs.list_snapshot_blocks(SnapshotId=snapshot_id))
    assert listed.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"listing blocks of an OPEN snapshot answered "
        f"{listed.response['Error']['Code']!r}, expected ResourceNotFoundException"
    )
    assert listed.response["Error"].get("Message") == (
        f"The snapshot '{snapshot_id}' does not exist."
    ), f"listing an OPEN snapshot answered message {listed.response['Error'].get('Message')!r}"
    assert listed.response.get("Reason") == "SNAPSHOT_NOT_FOUND", (
        f"the denial carried Reason {listed.response.get('Reason')!r}, expected "
        f"'SNAPSHOT_NOT_FOUND' — an open snapshot is reported absent, not empty"
    )

    # A deliberately bad token: the missing snapshot must be reported ahead of it.
    fetched = _client_error(lambda: ebs.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken=FOREIGN_BLOCK_TOKEN
    ))
    assert fetched.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"reading a block out of an OPEN snapshot answered "
        f"{fetched.response['Error']['Code']!r}, expected ResourceNotFoundException — the "
        f"missing snapshot must be reported ahead of the bad block token"
    )
    assert fetched.response["Error"].get("Message") == (
        f"The snapshot '{snapshot_id}' does not exist."
    ), f"reading a block of an OPEN snapshot answered message {fetched.response['Error'].get('Message')!r}"

    # Positive control: the same snapshot id, the same reads, after completion.
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_readable(ebs, snapshot_id)

    blocks = _list_all_blocks(ebs, snapshot_id)
    assert [b["BlockIndex"] for b in blocks] == [0], (
        f"after completion the snapshot lists blocks {[b['BlockIndex'] for b in blocks]!r}, "
        f"expected the block 0 written while it was open"
    )
    got = ebs.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken=blocks[0]["BlockToken"]
    )
    assert got["BlockData"].read() == data, (
        "the block written before completion did not read back intact afterwards"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
