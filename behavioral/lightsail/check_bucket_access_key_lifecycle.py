"""bucket-access-key-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "bucket-access-key-lifecycle"
GROUP = "data-plane"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBucketAccessKey returns an Active key that GetBucketAccessKeys lists and that authenticates an S3
    ListObjectsV2 on the bucket; after DeleteBucketAccessKey the key is no longer listed.
    """
    ls = ctx.client("lightsail")
    bucket_name = ctx.unique_name("sim2real-ls-buk-").lower()
    bundle_id = _pick_bucket_bundle(ctx)

    _create_bucket_with_retry(ctx, bucket_name, bundle_id)
    ctx.on_cleanup(lambda: ls.delete_bucket(bucketName=bucket_name, forceDelete=True))

    key = ls.create_bucket_access_key(bucketName=bucket_name)["accessKey"]
    access_key_id = key["accessKeyId"]
    secret_access_key = key["secretAccessKey"]
    assert key["status"] == "Active"

    keys = ls.get_bucket_access_keys(bucketName=bucket_name)["accessKeys"]
    assert any(k["accessKeyId"] == access_key_id for k in keys), "created access key missing from list"
    assert next(k for k in keys if k["accessKeyId"] == access_key_id)["status"] == "Active"

    s3 = ctx.client(
        "s3",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )
    # The freshly-minted key must actually authenticate against the real S3-compatible data plane,
    # not just echo Active in Lightsail's own control-plane response.
    listing = _list_objects_with_retry(s3, bucket_name, timeout_s=60.0)
    assert listing["Name"] == bucket_name, f"S3 ListObjectsV2 answered for the wrong bucket: {listing!r}"

    ls.delete_bucket_access_key(bucketName=bucket_name, accessKeyId=access_key_id)
    keys_after = ls.get_bucket_access_keys(bucketName=bucket_name)["accessKeys"]
    assert not any(k["accessKeyId"] == access_key_id for k in keys_after), "deleted access key still listed"


def _pick_bucket_bundle(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_bucket_bundles()
    active = [b for b in resp["bundles"] if b.get("isActive", True)]
    active.sort(key=lambda b: b["price"])
    return active[0]["bundleId"]


def _create_bucket_with_retry(ctx, bucket_name, bundle_id, timeout_s=180.0, interval_s=10.0):
    ls = ctx.client("lightsail")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ls.create_bucket(bucketName=bucket_name, bundleId=bundle_id, tags=[{"key": "sim2real", "value": CHECK}])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "RegionSetupInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _list_objects_with_retry(s3, bucket_name, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3.list_objects_v2(Bucket=bucket_name)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
