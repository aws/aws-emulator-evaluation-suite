"""op-contract-delete-bucket-metrics-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-bucket-metrics-configuration"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBucketMetricsConfiguration removes a named metrics filter; a missing bucket is rejected."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    metrics_id = "sim2real-metrics"

    # --- success path: put a metrics config, delete it, confirm it's gone ---
    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=metrics_id,
        MetricsConfiguration={"Id": metrics_id, "Filter": {"Prefix": "reports/"}},
    )
    got = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id)
    got_id = got["MetricsConfiguration"].get("Id")
    assert got_id == metrics_id, f"expected Id {metrics_id!r}, got {got_id!r}"

    s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id)
    code, message = _client_error(lambda: s3.get_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration, got {code!r}"
    assert message == "The specified configuration does not exist.", f"unexpected message {message!r}"

    # --- delete is NOT idempotent: deleting an already-absent Id is rejected too ---
    code, message = _client_error(lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration, got {code!r}"
    assert message == "The specified configuration does not exist.", f"unexpected message {message!r}"

    # --- error boundary: operating against a bucket that does not exist ---
    ghost_bucket = ctx.unique_name("sim2real-behav-ghost-")
    code, message = _client_error(lambda: s3.delete_bucket_metrics_configuration(Bucket=ghost_bucket, Id=metrics_id))
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
    if ctx.region != "us-east-1":  # CreateBucket rejects a LocationConstraint for the default region
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    if object_lock:
        kwargs["ObjectLockEnabledForBucket"] = True
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
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
