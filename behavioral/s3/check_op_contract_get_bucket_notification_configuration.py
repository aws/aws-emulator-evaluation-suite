"""op-contract-get-bucket-notification-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-bucket-notification-configuration"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBucketNotificationConfiguration reflects the configured EventBridge/queue/topic wiring."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # --- success path: an unconfigured bucket reports an empty configuration (no error) ---
    got_empty = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" not in got_empty, (
        f"expected no EventBridgeConfiguration on an unconfigured bucket, got {got_empty!r}"
    )
    assert not got_empty.get("QueueConfigurations"), (
        f"expected no QueueConfigurations on an unconfigured bucket, got {got_empty!r}"
    )
    assert not got_empty.get("TopicConfigurations"), (
        f"expected no TopicConfigurations on an unconfigured bucket, got {got_empty!r}"
    )
    assert not got_empty.get("LambdaFunctionConfigurations"), (
        f"expected no LambdaFunctionConfigurations on an unconfigured bucket, got {got_empty!r}"
    )

    # enabling EventBridge notifications requires no destination permissions, keeping this single-service
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    got = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in got, f"expected EventBridgeConfiguration present, got {got!r}"

    # --- error boundary: operating against a bucket that does not exist ---
    ghost_bucket = ctx.unique_name("sim2real-behav-ghost-")
    code = _error(lambda: s3.get_bucket_notification_configuration(Bucket=ghost_bucket))
    assert code == _NO_SUCH_BUCKET, f"expected NoSuchBucket, got {code!r}"


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, object_lock: bool = False) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default and rejects an explicit LocationConstraint for it
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
