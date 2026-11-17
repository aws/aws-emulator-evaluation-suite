"""bucket-policy-over-twenty-kb-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-policy-over-twenty-kb-rejected"
GROUP = "bucket-policy"
SERVICES = ["s3"]

#: Bucket policies are limited to a fixed, non-adjustable 20480-byte (20 KB) normalized size.
_MAX_BYTES = 20480

#: S3's refusal of a bucket policy document past that cap, naming the cap itself.
_POLICY_TOO_LARGE = (
    "MalformedPolicy",
    f"Normalized policy document exceeds the maximum allowed size of {_MAX_BYTES} bytes",
)

_BUCKET_PREFIX = "sim2real-behav-"


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _policy(ctx, bucket: str, *, filler_len: int = 0) -> str:
    """A valid self-granting bucket policy, optionally padded with a filler Sid."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "f" * filler_len,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    return json.dumps(doc, separators=(",", ":"))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketPolicy accepts a small policy and rejects one whose normalized size exceeds the
    fixed, non-adjustable 20480-byte cap, without replacing the policy already in place.
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    small = _policy(ctx, bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy=small)
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))
    stored = s3.get_bucket_policy(Bucket=bucket)["Policy"]
    assert json.loads(stored) == json.loads(small), f"a small policy did not round-trip: {stored!r}"

    # Comfortably past the 20480-byte cap, clear of AWS's own normalization of this request shape.
    oversized = _policy(ctx, bucket, filler_len=2 * _MAX_BYTES)
    got = _error(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=oversized))
    assert got == _POLICY_TOO_LARGE, f"expected {_POLICY_TOO_LARGE!r} for an oversized policy, got {got!r}"

    survived = s3.get_bucket_policy(Bucket=bucket)["Policy"]
    assert json.loads(survived) == json.loads(small), (
        f"the rejected oversized PutBucketPolicy must not have replaced the existing policy, got {survived!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
