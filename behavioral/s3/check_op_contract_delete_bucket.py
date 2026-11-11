"""op-contract-delete-bucket."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-bucket"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteBucket removes an empty bucket, and the deleted name is unusable for a further
    mutation; a non-empty bucket is rejected with BucketNotEmpty, the bucket is left standing,
    and once the object is removed the identical DeleteBucket call succeeds."""
    s3 = ctx.client("s3")

    # --- success path: empty bucket deletes cleanly, disappears, and is unusable ---
    empty_bucket = _create_bucket(ctx)
    # withdraw the registered cleanup: we delete it ourselves as part of the success assertion
    s3.delete_bucket(Bucket=empty_bucket)
    # A HEAD response carries no body, so there is no AWS message to compare.
    code, _ = _client_error(lambda: s3.head_bucket(Bucket=empty_bucket))
    assert code == "404", f"expected bucket gone, got code={code!r}"
    code, message = _client_error(lambda: s3.put_object(Bucket=empty_bucket, Key="ghost.txt", Body=b"x"))
    assert code == "NoSuchBucket", (
        f"expected a mutation against the deleted bucket to fail with NoSuchBucket, got {code!r}"
    )
    assert message == "The specified bucket does not exist", f"unexpected message {message!r}"

    # --- error boundary: non-empty bucket cannot be deleted, until it is emptied ---
    nonempty_bucket = _create_bucket(ctx)
    s3.put_object(Bucket=nonempty_bucket, Key="still-here.txt", Body=b"data")
    code, message = _client_error(lambda: s3.delete_bucket(Bucket=nonempty_bucket))
    assert code == "BucketNotEmpty", f"expected BucketNotEmpty, got {code!r}"
    assert message == "The bucket you tried to delete is not empty", f"unexpected message {message!r}"
    # effect absent: an independent read shows the refused delete left the bucket standing
    s3.head_bucket(Bucket=nonempty_bucket)
    # restore: remove the object that caused the refusal
    s3.delete_object(Bucket=nonempty_bucket, Key="still-here.txt")
    # the identical call now succeeds
    s3.delete_bucket(Bucket=nonempty_bucket)
    code, _ = _client_error(lambda: s3.head_bucket(Bucket=nonempty_bucket))
    assert code == "404", (
        f"expected bucket gone after emptying and retrying the delete, got code={code!r}"
    )


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
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    if object_lock:
        kwargs["ObjectLockEnabledForBucket"] = True
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _force_delete_bucket(ctx, name))
    return name


def _force_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
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
                        failed = s3.delete_objects(
                            Bucket=bucket, Delete={"Objects": batch}, BypassGovernanceRetention=True
                        ).get("Errors")
                        if failed:
                            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                    except ClientError:
                        for o in batch:
                            try:
                                s3.delete_object(
                                    Bucket=bucket,
                                    Key=o["Key"],
                                    VersionId=o["VersionId"],
                                    BypassGovernanceRetention=True,
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
