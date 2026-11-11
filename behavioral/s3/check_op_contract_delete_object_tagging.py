"""op-contract-delete-object-tagging."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-object-tagging"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteObjectTagging clears an object's tag set; a missing bucket is rejected with NoSuchBucket."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "tagged-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello")

    # --- success path: tag the object, delete tags, confirm the tag set is empty ---
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "team", "Value": "sim2real"}]})
    got = s3.get_object_tagging(Bucket=bucket, Key=key)
    assert got["TagSet"] == [{"Key": "team", "Value": "sim2real"}], f"expected tag set to be set, got {got['TagSet']!r}"

    s3.delete_object_tagging(Bucket=bucket, Key=key)
    got_after = s3.get_object_tagging(Bucket=bucket, Key=key)
    assert got_after["TagSet"] == [], f"expected empty tag set, got {got_after['TagSet']!r}"

    # --- error boundary: operating against a bucket that does not exist ---
    ghost_bucket = ctx.unique_name("sim2real-behav-ghost-")
    code, message = _client_error(lambda: s3.delete_object_tagging(Bucket=ghost_bucket, Key=key))
    assert code == "NoSuchBucket", f"expected NoSuchBucket, got {code!r}"
    assert message == "The specified bucket does not exist", f"unexpected message {message!r}"


def _client_error(fn):
    """The botocore (Error.Code, Error.Message) of fn(), the code falling back to the HTTP status
    for a code-less HEAD; RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code")
        if not code or code.isdigit():
            code = str(e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
        return code, err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, object_lock: bool = False) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's legacy default region: CreateBucket rejects an explicit
    # LocationConstraint there, so it must be omitted rather than pinned.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    if object_lock:
        kwargs["ObjectLockEnabledForBucket"] = True
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "op-contract-delete-object-tagging"}]}
    )
    ctx.on_cleanup(lambda: _force_delete_bucket(ctx, name, object_lock=object_lock))
    return name


def _force_delete_bucket(ctx, bucket: str, object_lock: bool = False) -> None:
    s3 = ctx.client("s3")
    # BypassGovernanceRetention requires s3:BypassGovernanceRetention even when the
    # request is a no-op, so only send it for buckets that actually enabled Object Lock.
    bypass_kwargs = {"BypassGovernanceRetention": True} if object_lock else {}
    try:
        try:
            for u in s3.list_multipart_uploads(Bucket=bucket).get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
                objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
                for i in range(0, len(objs), 1000):
                    batch = objs[i : i + 1000]
                    if not batch:
                        continue
                    try:
                        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}, **bypass_kwargs).get("Errors")
                        if failed:
                            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                    except ClientError:
                        for o in batch:
                            try:
                                s3.delete_object(
                                    Bucket=bucket,
                                    Key=o["Key"],
                                    VersionId=o["VersionId"],
                                    **bypass_kwargs,
                                )
                            except ClientError as exc:
                                if exc.response["Error"]["Code"] not in (
                                    "NoSuchBucket",
                                    "NoSuchKey",
                                ):
                                    raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
