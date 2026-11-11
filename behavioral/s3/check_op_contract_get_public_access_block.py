"""op-contract-getPublicAccessBlock."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getPublicAccessBlock"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket with no public access block, as real S3 returns it.
_NO_SUCH_PAB = ("NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPublicAccessBlock returns the exact configuration put; errors when none is set."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # new buckets are created with a default "block all public access" configuration
    # (S3's April 2023 secure-by-default change); clear it first so the "no
    # configuration set" boundary can actually be observed.
    try:
        s3.delete_public_access_block(Bucket=bucket)
    except Exception:
        pass

    # distinct error boundary: no configuration set yet
    code = _error(lambda: s3.get_public_access_block(Bucket=bucket))
    assert code == _NO_SUCH_PAB, f"expected NoSuchPublicAccessBlockConfiguration, got {code}"

    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=config)

    resp = s3.get_public_access_block(Bucket=bucket)
    got = resp["PublicAccessBlockConfiguration"]
    assert got == config, f"expected {config}, got {got}"

    # deleting the config restores the not-found boundary
    s3.delete_public_access_block(Bucket=bucket)
    code2 = _error(lambda: s3.get_public_access_block(Bucket=bucket))
    assert code2 == _NO_SUCH_PAB, f"expected NoSuchPublicAccessBlockConfiguration, got {code2}"


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
