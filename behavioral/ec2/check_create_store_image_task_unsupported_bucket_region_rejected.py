"""create-store-image-task-unsupported-bucket-region-rejected."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-store-image-task-unsupported-bucket-region-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_EBS_BLOCK_SIZE = 512 * 1024


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStoreImageTask with a bucket in another Region is refused with InvalidRequest naming that Region and
    creates no task or object, while a same-Region bucket completes the task with a non-empty object.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    ebs = ctx.client("ebs")

    # CreateStoreImageTask refuses an AMI whose snapshots hold no data, so the snapshot gets one real
    # block through the EBS direct APIs, which need no volume or instance.
    snap_id = ebs.start_snapshot(
        VolumeSize=1,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-storeimg-snap-")}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    block = bytes([0xAB]) * _EBS_BLOCK_SIZE
    checksum = base64.b64encode(hashlib.sha256(block).digest()).decode()
    ebs.put_snapshot_block(
        SnapshotId=snap_id,
        BlockIndex=0,
        BlockData=block,
        DataLength=_EBS_BLOCK_SIZE,
        Checksum=checksum,
        ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snap_id, ChangedBlocksCount=1)
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    # "completed" on the EC2 snapshot resource lags the EBS-direct block index it was written
    # through: CreateStoreImageTask internally calls ListSnapshotBlocks and, right after
    # completion, can still see "The snapshot '<id>' does not exist" until that index catches up.
    _wait_for_snapshot_indexed(ebs, snap_id)

    ami_name = ctx.unique_name("sim2real-storeimg-ami-")
    ami_id = ec2.register_image(
        Name=ami_name,
        Architecture="x86_64",
        VirtualizationType="hvm",
        RootDeviceName="/dev/xvda",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        EnaSupport=True,
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=ami_id))

    same_region_bucket = ctx.unique_name("sim2real-storeimg-same-").lower().replace("_", "-")
    cross_region_bucket = ctx.unique_name("sim2real-storeimg-cross-").lower().replace("_", "-")
    cross_region = _pick_other_region(ec2, exclude=ctx.region)
    # CreateBucket with a LocationConstraint must go to a client of that region
    # (IllegalLocationConstraintException otherwise); list/head/delete follow S3's redirects.
    s3_cross = ctx.client("s3", region=cross_region)

    _create_bucket(s3, same_region_bucket, ctx.region, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, same_region_bucket))
    _create_bucket(s3_cross, cross_region_bucket, cross_region, cross_region)
    ctx.on_cleanup(lambda: _delete_bucket(s3_cross, cross_region_bucket))

    # --- Negative: the bucket is in a different Region than the request ---
    code, message = _error(
        lambda: ec2.create_store_image_task(ImageId=ami_id, Bucket=cross_region_bucket)
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"
    # The S3 request ids inside the message differ per call; the text around them is stable.
    assert message.startswith(
        f"The bucket is in this region: {cross_region}. Please use this region to retry the request "
        "(Service: Amazon S3; Status Code: 301; Error Code: PermanentRedirect; Request ID: "
    ) and message.endswith("; Proxy: null)"), message

    # Effect absent: no store-image task was recorded for this AMI, and no object landed in either bucket.
    tasks = ec2.describe_store_image_tasks(ImageIds=[ami_id]).get("StoreImageTaskResults", [])
    assert tasks == [], f"a store task was recorded despite the cross-region bucket being rejected: {tasks}"
    key_count = s3_cross.list_objects_v2(Bucket=cross_region_bucket).get("KeyCount", 0)
    assert key_count == 0, f"expected no objects in the rejected cross-region bucket, found {key_count}"

    # --- Positive control: a same-Region bucket succeeds and the object is actually stored ---
    result = ec2.create_store_image_task(ImageId=ami_id, Bucket=same_region_bucket)
    object_key = result["ObjectKey"]
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=same_region_bucket, Key=object_key)))

    final = _poll_until(
        lambda: ec2.describe_store_image_tasks(ImageIds=[ami_id])["StoreImageTaskResults"][0],
        lambda t: t["StoreTaskState"] in ("Completed", "Failed"),
        timeout_s=300.0,
        interval_s=10.0,
        description="store image task reaching a terminal state",
    )
    assert final["StoreTaskState"] == "Completed", f"store image task did not complete: {final}"

    head = s3.head_object(Bucket=same_region_bucket, Key=object_key)
    assert head["ContentLength"] > 0, "stored AMI object in S3 is empty"


def _wait_for_snapshot_indexed(ebs, snapshot_id: str, *, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} did not become queryable via ListSnapshotBlocks within "
        f"{timeout_s}s: {last_exc}"
    )


def _pick_other_region(ec2, exclude: str) -> str:
    # These region literals name candidates for the cross-region bucket, which is deliberately
    # region-pinned: the check's subject is CreateStoreImageTask rejecting a bucket that is NOT
    # in ctx.region, so a concrete other region is the point, not an accident.
    regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"] if r["RegionName"] != exclude]
    # us-east-1 is not picked: S3 accepts a LocationConstraint of us-east-1 only at the us-east-1
    # endpoint, while any other region accepts its own constraint.
    for preferred in ("us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2"):
        if preferred in regions:
            return preferred
    non_use1 = [r for r in regions if r != "us-east-1"]
    return sorted(non_use1 or regions)[0]


def _create_bucket(s3, bucket: str, region: str, client_region: str) -> None:
    # CreateBucket with a LocationConstraint must go to a client of that same region
    # (IllegalLocationConstraintException otherwise); callers pass an `s3` client bound to `region`.
    if region == "us-east-1":
        assert client_region == "us-east-1", (
            f"cannot create a us-east-1 bucket from a client bound to {client_region!r}"
        )
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.get_waiter("bucket_exists").wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 50})


def _delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
