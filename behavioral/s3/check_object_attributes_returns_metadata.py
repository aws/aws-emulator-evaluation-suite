"""object-attributes-returns-metadata."""
from __future__ import annotations

import base64
import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "object-attributes-returns-metadata"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes returns exact ETag/size/checksum for a real object, NoSuchKey for a missing one."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "data/payload.bin"
    body = b"x" * 12345

    put = s3.put_object(Bucket=bucket, Key=key, Body=body, ChecksumAlgorithm="SHA256")

    # A single-part, unencrypted upload's ETag is the plain MD5 hex digest of the bytes, and its
    # SHA256 checksum is the plain base64 digest — computed here from `body` independently of
    # anything either AWS response reports, so a target that echoes a self-consistent but wrong
    # value from both PutObject and GetObjectAttributes cannot pass by agreeing with itself.
    expected_etag = hashlib.md5(body).hexdigest()
    expected_sha256 = base64.b64encode(hashlib.sha256(body).digest()).decode()

    attrs = s3.get_object_attributes(
        Bucket=bucket,
        Key=key,
        ObjectAttributes=["ETag", "Checksum", "ObjectSize", "StorageClass"],
    )
    assert attrs["ObjectSize"] == len(body), f"expected size {len(body)}, got {attrs.get('ObjectSize')}"
    # GetObjectAttributes returns the ETag WITHOUT the surrounding quotes that PutObject's response
    # includes; normalize both sides before comparing.
    assert attrs["ETag"].strip('"') == expected_etag, f"expected ETag {expected_etag}, got {attrs['ETag']}"
    assert put["ETag"].strip('"') == expected_etag, f"PutObject's own ETag disagrees: {put['ETag']}"
    assert attrs["Checksum"]["ChecksumSHA256"] == expected_sha256, (
        f"expected checksum {expected_sha256}, got {attrs['Checksum']['ChecksumSHA256']}"
    )
    assert put["ChecksumSHA256"] == expected_sha256, f"PutObject's own checksum disagrees: {put['ChecksumSHA256']}"
    # STANDARD is the default storage class and is often omitted rather than echoed back.
    assert attrs.get("StorageClass") in (None, "STANDARD")

    # Positive control confirmed above; now break the one precondition (key existence).
    code, message = _error(
        lambda: s3.get_object_attributes(Bucket=bucket, Key="data/does-not-exist.bin", ObjectAttributes=["ETag"])
    )
    assert code == "NoSuchKey", f"expected NoSuchKey for a missing object, got {code}"
    assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"

    # The forbidden read did not fabricate a result: the real object's attributes are unchanged.
    attrs_again = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ETag"])
    assert attrs_again["ETag"].strip('"') == expected_etag, (
        f"expected ETag {expected_etag} unchanged after the failed lookup, got {attrs_again['ETag']}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-s3-behav-").lower()
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit"}]})

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
