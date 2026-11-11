"""bucket-object-put-get-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "bucket-object-put-get-roundtrip"
GROUP = "data-plane"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lightsail bucket's generated access key can PutObject/GetObject through the real S3-compatible data plane."""
    ls = ctx.client("lightsail")
    bucket_name = ctx.unique_name("sim2real-ls-buk-").lower()
    bundle_id = _pick_bucket_bundle(ctx)

    _create_bucket_with_retry(ctx, bucket_name, bundle_id)
    ctx.on_cleanup(lambda: ls.delete_bucket(bucketName=bucket_name, forceDelete=True))

    key_resp = ls.create_bucket_access_key(bucketName=bucket_name)["accessKey"]
    access_key_id = key_resp["accessKeyId"]
    secret_access_key = key_resp["secretAccessKey"]
    ctx.on_cleanup(lambda: ls.delete_bucket_access_key(bucketName=bucket_name, accessKeyId=access_key_id))

    s3 = ctx.client(
        "s3",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )
    body = b"sim2real-lightsail-bucket-roundtrip-payload"
    object_key = "roundtrip-test.txt"

    _put_object_with_retry(s3, bucket_name, object_key, body, timeout_s=60.0)

    got = s3.get_object(Bucket=bucket_name, Key=object_key)["Body"].read()
    assert got == body, f"round-tripped object body mismatch: {got!r} != {body!r}"

    s3.delete_object(Bucket=bucket_name, Key=object_key)
    from botocore.exceptions import ClientError

    try:
        s3.get_object(Bucket=bucket_name, Key=object_key)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "NoSuchKey", f"expected NoSuchKey after delete_object, got {code!r}"
        message = e.response["Error"].get("Message")
        assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"
    else:
        raise AssertionError("get_object succeeded for a key deleted by delete_object")


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
            ls.create_bucket(
                bucketName=bucket_name,
                bundleId=bundle_id,
                tags=[{"key": "sim2real", "value": CHECK}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
