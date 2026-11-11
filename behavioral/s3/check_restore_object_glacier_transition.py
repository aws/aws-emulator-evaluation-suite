"""restore-object-glacier-transition."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "restore-object-glacier-transition"
GROUP = 'storage_classes'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    return name


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _poll_until(fn, pred, *, timeout_s, interval_s, description=""):
    """Poll fn() until pred(result) is true; raise AssertionError on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"poll timed out after {timeout_s}s: {description} (last={last!r})")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject transitions a GLACIER object from unreadable -> ongoing-restore ->
    temporarily retrievable via GetObject/CopyObject."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    key = "archived.txt"
    body = b"cold-data"
    s3.put_object(Bucket=name, Key=key, Body=body, StorageClass="GLACIER")

    head = s3.head_object(Bucket=name, Key=key)
    assert head.get("StorageClass") == "GLACIER", f"expected GLACIER storage class, got {head.get('StorageClass')!r}"
    assert "Restore" not in head, f"unrestored object should have no Restore header, got {head.get('Restore')!r}"

    refusal = _error(lambda: s3.get_object(Bucket=name, Key=key))
    assert refusal == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"expected InvalidObjectState for an unrestored object, got {refusal!r}"
    )

    try:
        s3.restore_object(
            Bucket=name,
            Key=key,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}},
        )
    except ClientError as exc:
        raise AssertionError(f"RestoreObject rejected (transient expedited capacity?): {exc}") from exc

    head2 = s3.head_object(Bucket=name, Key=key)
    restore_hdr = head2.get("Restore", "")
    assert 'ongoing-request="true"' in restore_hdr, f"expected an ongoing-restore marker, got {restore_hdr!r}"

    def _poll():
        return s3.head_object(Bucket=name, Key=key).get("Restore", "")

    try:
        _poll_until(
            _poll,
            lambda hdr: 'ongoing-request="false"' in hdr,
            timeout_s=240,
            interval_s=10,
            description="GLACIER expedited restore completion",
        )
    except AssertionError as exc:
        raise AssertionError(
            "restore did not complete within the bounded poll window (real-AWS "
            "expedited retrieval latency, typically 1-5 min, exceeded it)"
        ) from exc

    restored = s3.get_object(Bucket=name, Key=key)
    assert restored["Body"].read() == body, "restored object must be readable with its original bytes"

    dest_key = "archived-copy.txt"
    s3.copy_object(Bucket=name, Key=dest_key, CopySource={"Bucket": name, "Key": key})
    copied = s3.get_object(Bucket=name, Key=dest_key)
    assert copied["Body"].read() == body, "CopyObject must work against the temporarily-restored object"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
