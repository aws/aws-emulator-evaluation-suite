"""bucket-delete-nonempty-without-force-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "bucket-delete-nonempty-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBucket without forceDelete on a bucket that still has objects and a live access key is
    rejected with 'Bucket is not empty: <name>'; the bucket and object survive. A live access key
    granting access is a separate block, independent of object presence."""
    ls = ctx.client("lightsail")
    bucket_name = ctx.unique_name("sim2real-ls-buk-").lower()
    control_bucket_name = ctx.unique_name("sim2real-ls-bukctl-").lower()
    bundle_id = _pick_bucket_bundle(ctx)

    _create_bucket_with_retry(ctx, bucket_name, bundle_id)
    key_resp = ls.create_bucket_access_key(bucketName=bucket_name)["accessKey"]
    s3 = ctx.client(
        "s3",
        creds={
            "aws_access_key_id": key_resp["accessKeyId"],
            "aws_secret_access_key": key_resp["secretAccessKey"],
        },
    )
    object_key = "blocking-object.txt"
    _put_object_with_retry(s3, bucket_name, object_key, b"still-here", timeout_s=60.0)

    code, message = _error(lambda: ls.delete_bucket(bucketName=bucket_name))
    assert code == "InvalidInputException", f"unexpected code deleting nonvacated bucket: {code!r}"
    assert message == f"Bucket is not empty: {bucket_name}", f"unexpected message deleting nonvacated bucket: {message!r}"

    # The bucket and its object are unaffected by the rejected delete.
    buckets = ls.get_buckets(bucketName=bucket_name)["buckets"]
    assert any(b["name"] == bucket_name for b in buckets), "bucket disappeared after rejected delete"
    still_there = s3.get_object(Bucket=bucket_name, Key=object_key)["Body"].read()
    assert still_there == b"still-here", f"blocking object body changed after rejected delete: {still_there!r}"

    # Restore: real AWS's own error names TWO independent blocks -- the object and the live
    # access key granting access -- so both must be cleared before the identical call (still
    # without forceDelete) succeeds on the SAME bucket. Lifting only one and retrying would still
    # 400.
    s3.delete_object(Bucket=bucket_name, Key=object_key)
    ls.delete_bucket_access_key(bucketName=bucket_name, accessKeyId=key_resp["accessKeyId"])
    _delete_bucket_with_retry(ls, bucket_name, force_delete=False)
    _assert_bucket_gone(ctx, bucket_name)

    # Positive control: deleting an empty bucket without forceDelete succeeds outright -- so the
    # rejection above was specific to the nonempty bucket, not every DeleteBucket call.
    _create_bucket_with_retry(ctx, control_bucket_name, bundle_id)
    _delete_bucket_with_retry(ls, control_bucket_name, force_delete=False)
    _assert_bucket_gone(ctx, control_bucket_name)


def _delete_bucket_with_retry(ls, bucket_name, force_delete, timeout_s=90.0, interval_s=5.0):
    """DeleteBucket can transiently 400 with 'a conflicting conditional operation is currently in
    progress' right after a prior mutating call (e.g. PutObject/DeleteObject) on the same bucket;
    retry until the conflict clears."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if force_delete:
                ls.delete_bucket(bucketName=bucket_name, forceDelete=True)
            else:
                ls.delete_bucket(bucketName=bucket_name)
            return
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "InvalidInputException" and "conflicting conditional operation" in err.get(
                "Message", ""
            ) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise
def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a delete real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected DeleteBucket to be rejected, but it SUCCEEDED and returned {result!r}")


def _pick_bucket_bundle(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_bucket_bundles()
    active = [b for b in resp["bundles"] if b.get("isActive", True)]
    active.sort(key=lambda b: b["price"])
    return active[0]["bundleId"]


def _create_bucket_with_retry(ctx, bucket_name, bundle_id, timeout_s=180.0, interval_s=10.0):
    ls = ctx.client("lightsail")
    from botocore.exceptions import ClientError

    def _safe_delete():
        try:
            ls.delete_bucket(bucketName=bucket_name, forceDelete=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_safe_delete)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ls.create_bucket(
                bucketName=bucket_name,
                bundleId=bundle_id,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "RegionSetupInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _put_object_with_retry(s3, bucket_name, key, body, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_object(Bucket=bucket_name, Key=key, Body=body)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _assert_bucket_gone(ctx, bucket_name, timeout_s=60.0, interval_s=2.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        buckets = ls.get_buckets()["buckets"]
        if not any(b["name"] == bucket_name for b in buckets):
            return
        time.sleep(interval_s)
    raise AssertionError(f"bucket {bucket_name} was not removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
