"""op-contract-putBucketLifecycleConfiguration."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putBucketLifecycleConfiguration"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketLifecycleConfiguration persists rules (filter/transition/expiration); errors NoSuchBucket when missing."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    rules = [
        {
            "ID": "expire-logs",
            "Status": "Enabled",
            "Filter": {"Prefix": "logs/"},
            "Expiration": {"Days": 30},
        },
        {
            "ID": "abort-incomplete-uploads",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        },
    ]
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": rules})
    ctx.on_cleanup(lambda: s3.delete_bucket_lifecycle(Bucket=bucket))

    resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    got_by_id = {r["ID"]: r for r in resp["Rules"]}
    assert set(got_by_id) == {"expire-logs", "abort-incomplete-uploads"}, f"unexpected rule ids: {got_by_id.keys()}"
    expire_days = got_by_id["expire-logs"]["Expiration"]["Days"]
    assert expire_days == 30, f"expected expire-logs Expiration.Days == 30, got {expire_days}"
    expire_prefix = got_by_id["expire-logs"]["Filter"]["Prefix"]
    assert expire_prefix == "logs/", f"expected expire-logs Filter.Prefix == 'logs/', got {expire_prefix!r}"
    abort_days = got_by_id["abort-incomplete-uploads"]["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"]
    assert abort_days == 7, f"expected abort-incomplete-uploads DaysAfterInitiation == 7, got {abort_days}"

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(
        lambda: s3.put_bucket_lifecycle_configuration(
            Bucket=missing, LifecycleConfiguration={"Rules": rules}
        )
    )
    assert code == _NO_SUCH_BUCKET, f"expected NoSuchBucket, got {code}"


_BUCKET_PREFIX = "sim2real-behav-"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
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


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
