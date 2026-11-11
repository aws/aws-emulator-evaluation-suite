"""bucket-website-config-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-website-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Static website hosting configuration can be created, retrieved exactly, and deleted,
    restoring the bucket to a non-website state."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-website-")
    _create_bucket(ctx, s3, bucket)

    code_before, message_before = _error(lambda: s3.get_bucket_website(Bucket=bucket))
    assert code_before == "NoSuchWebsiteConfiguration", code_before
    assert message_before == "The specified bucket does not have a website configuration", message_before

    s3.put_bucket_website(
        Bucket=bucket,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    got = s3.get_bucket_website(Bucket=bucket)
    assert got["IndexDocument"] == {"Suffix": "index.html"}, got.get("IndexDocument")
    assert got["ErrorDocument"] == {"Key": "error.html"}, got.get("ErrorDocument")
    assert "RedirectAllRequestsTo" not in got, got.get("RedirectAllRequestsTo")

    s3.delete_bucket_website(Bucket=bucket)
    code_after, message_after = _error(lambda: s3.get_bucket_website(Bucket=bucket))
    assert code_after == "NoSuchWebsiteConfiguration", code_after
    assert message_after == "The specified bucket does not have a website configuration", message_after


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
