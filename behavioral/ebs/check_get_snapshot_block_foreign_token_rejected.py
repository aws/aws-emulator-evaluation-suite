"""get-snapshot-block-foreign-token-rejected."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-snapshot-block-foreign-token-rejected"
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """GetSnapshotBlock with a well-formed token the service never issued fails with
    ValidationException / INVALID_BLOCK_TOKEN; the issued token reads the same block intact."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")

    data = bytes(range(256)) * (BLOCK_SIZE // 256)

    started = ebs.start_snapshot(
        VolumeSize=1,
        Description=ctx.unique_name("sim2real-behav-ebs-badtok-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-behav-foreign-token"}],
    )
    snapshot_id = started["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))

    ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=data,
        DataLength=BLOCK_SIZE,
        Checksum=_b64_sha256(data),
        ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_readable(ebs, snapshot_id)

    blocks = _list_all_blocks(ebs, snapshot_id)
    assert [b["BlockIndex"] for b in blocks] == [0], (
        f"the completed snapshot lists blocks {[b['BlockIndex'] for b in blocks]!r}, expected "
        f"exactly block 0"
    )
    issued_token = blocks[0]["BlockToken"]
    assert issued_token != FOREIGN_BLOCK_TOKEN, (
        f"the service issued {issued_token!r} as the block token, which is the very value this "
        f"check uses as the foreign one — the negative would be vacuous"
    )

    refused = _client_error(lambda: ebs.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken=FOREIGN_BLOCK_TOKEN
    ))
    assert refused.response["Error"]["Code"] == "ValidationException", (
        f"reading block 0 with a foreign token answered "
        f"{refused.response['Error']['Code']!r}, expected ValidationException"
    )
    assert refused.response["Error"].get("Message") == (
        f"The block token {FOREIGN_BLOCK_TOKEN} is invalid."
    ), f"the denial carried message {refused.response['Error'].get('Message')!r}"
    assert refused.response.get("Reason") == "INVALID_BLOCK_TOKEN", (
        f"the denial carried Reason {refused.response.get('Reason')!r}, expected "
        f"'INVALID_BLOCK_TOKEN' — the token is what was refused, not the snapshot or the index"
    )

    # Positive control: the same block, the same index, the token the service issued.
    got = ebs.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken=issued_token
    )
    assert got["BlockData"].read() == data, (
        "the block that the foreign token was refused for did not read back intact under the "
        "issued token — the negative proved nothing about token handling"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
