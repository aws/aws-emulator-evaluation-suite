"""public-access-block-rejects-public-policy."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "public-access-block-rejects-public-policy"
GROUP = 'auth_enforcement'
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
    return name


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With BlockPublicPolicy enabled, a PutBucketPolicy that grants public (Principal="*") access must be
    REJECTED, not silently accepted; a policy that stays non-public must still be accepted under the
    same block, so the rejection is proven to be about publicness and not merely PutBucketPolicy itself."""
    s3 = ctx.client("s3")
    account_id = ctx.account
    bucket = _new_bucket(ctx, s3)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadAttempt",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    code = _error(lambda: s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(public_policy)))
    assert code == ("AccessDenied", (
        f"User: {caller_arn} is not authorized to perform: s3:PutBucketPolicy on resource: "
        f"\"arn:aws:s3:::{bucket}\" because public policies are prevented by the "
        f"BlockPublicPolicy setting in S3 Block Public Access."
    )), (
        f"expected AccessDenied for a public policy under BlockPublicPolicy, got {code}"
    )

    # The bucket must NOT have accidentally acquired the public policy.
    no_policy_code = _error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert no_policy_code == ("NoSuchBucketPolicy", "The bucket policy does not exist"), (
        f"expected no policy to have been stored, got {no_policy_code}"
    )

    # Positive control: a non-public policy (principal is this account, not "*") is still accepted
    # under the identical BlockPublicPolicy=True block — without this, a target that rejects every
    # PutBucketPolicy call regardless of content would pass the assertions above just as well.
    private_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountReadAttempt",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(private_policy))
    stored = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    assert stored == private_policy, f"expected the non-public policy to be stored as-is, got {stored}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
