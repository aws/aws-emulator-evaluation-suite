"""store-image-task-lifecycle-to-completion."""
from __future__ import annotations

import base64
import hashlib
import os
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "store-image-task-lifecycle-to-completion"
GROUP = "state-machine"
SERVICES = ["ec2"]

_BLOCK_SIZE = 524288  # fixed EBS direct API block size (512 KiB)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStoreImageTask progresses InProgress->Completed and the
    resulting AMI object becomes retrievable from the destination S3 bucket."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    ebs = ctx.client("ebs")
    name = ctx.unique_name("sim2real-storeimg-")

    # CreateStoreImageTask rejects a snapshot with no allocated blocks ("The AMI
    # snapshots do not contain any data"), which a freshly created, never-written
    # EBS volume produces. Write one real block via the EBS direct API instead of
    # provisioning a volume+instance just to dirty it.
    snap_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    block_data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snap_id,
        BlockIndex=0,
        BlockData=block_data,
        DataLength=len(block_data),
        Checksum=_sha256_b64(block_data),
        ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snap_id, ChangedBlocksCount=1)
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180,
        interval_s=5,
    )
    # The EBS direct-API data plane can lag EC2's completed-state signal: CreateStoreImageTask
    # calls ListSnapshotBlocks internally and rejects with "the snapshot does not exist" if
    # invoked too soon after EC2 reports the snapshot completed. Confirm the data plane caught up.
    _list_snapshot_blocks_with_retry(ebs, snap_id)

    image_id = ec2.register_image(
        Name=name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        VirtualizationType="hvm",
        EnaSupport=True,
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))
    _poll_until(
        lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=5,
    )

    bucket = name.replace("_", "-")
    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is S3's legacy default region: CreateBucket rejects an explicit
    # LocationConstraint of "us-east-1" (InvalidLocationConstraint), so the
    # configuration is omitted only for that one region.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    task = ec2.create_store_image_task(ImageId=image_id, Bucket=bucket)
    object_key = task["ObjectKey"]

    def _task_state():
        results = ec2.describe_store_image_tasks(ImageIds=[image_id])["StoreImageTaskResults"]
        return results[0] if results else None

    result = _poll_until(
        _task_state,
        lambda r: r is not None and r["StoreTaskState"] in ("Completed", "Failed"),
        timeout_s=900,
        interval_s=10,
    )
    assert result["StoreTaskState"] == "Completed", (
        f"expected StoreTaskState Completed, got {result['StoreTaskState']!r} "
        f"(failure reason: {result.get('StoreTaskFailureReason')!r})"
    )
    assert result["Bucket"] == bucket, f"expected Bucket {bucket!r}, got {result['Bucket']!r}"
    assert result["S3objectKey"] == object_key, (
        f"expected S3objectKey {object_key!r}, got {result['S3objectKey']!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=object_key)
    assert head["ContentLength"] > 0, (
        f"expected stored AMI object {object_key!r} in {bucket!r} to have nonzero length, "
        f"got ContentLength {head['ContentLength']!r}"
    )


def _list_snapshot_blocks_with_retry(ebs, snapshot_id: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListSnapshotBlocks never found completed snapshot {snapshot_id}: {last_err}")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
