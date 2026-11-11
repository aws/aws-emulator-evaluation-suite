"""op-contract-putBucketCors."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putBucketCors"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketCors persists the exact CORS rule set; errors NoSuchBucket for a missing bucket."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    cors_config = {
        "CORSRules": [
            {
                "AllowedMethods": ["GET", "PUT"],
                "AllowedOrigins": ["https://example.com"],
                "AllowedHeaders": ["*"],
                "MaxAgeSeconds": 3000,
            }
        ]
    }
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration=cors_config)
    ctx.on_cleanup(lambda: s3.delete_bucket_cors(Bucket=bucket))

    resp = s3.get_bucket_cors(Bucket=bucket)
    rules = resp["CORSRules"]
    assert len(rules) == 1, f"expected 1 CORS rule, got {rules}"
    assert rules[0]["AllowedMethods"] == ["GET", "PUT"]
    assert rules[0]["AllowedOrigins"] == ["https://example.com"]
    assert rules[0]["MaxAgeSeconds"] == 3000

    # replacing the config fully overwrites the previous rule set (not a merge)
    cors_config2 = {"CORSRules": [{"AllowedMethods": ["POST"], "AllowedOrigins": ["*"]}]}
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration=cors_config2)
    resp2 = s3.get_bucket_cors(Bucket=bucket)
    assert len(resp2["CORSRules"]) == 1
    assert resp2["CORSRules"][0]["AllowedMethods"] == ["POST"]

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(lambda: s3.put_bucket_cors(Bucket=missing, CORSConfiguration=cors_config))
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
