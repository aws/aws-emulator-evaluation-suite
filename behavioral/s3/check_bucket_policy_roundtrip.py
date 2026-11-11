"""bucket-policy-roundtrip."""

from __future__ import annotations
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-policy-roundtrip"
GROUP = 'acls_policies'
SERVICES = ['s3']

def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketPolicy then GetBucketPolicy returns the statement verbatim, and after
    DeleteBucketPolicy an independent read confirms the policy is actually gone."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2real-test",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetBucketLogging",
                "Resource": f"arn:aws:s3:::{bucket}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    resp = s3.get_bucket_policy(Bucket=bucket)
    got = json.loads(resp["Policy"])
    assert got["Version"] == policy["Version"], f"expected Version {policy['Version']!r}, got {got.get('Version')!r}"
    assert len(got["Statement"]) == 1, f"expected exactly 1 statement, got {len(got['Statement'])}"
    got_stmt = got["Statement"][0]
    want_stmt = policy["Statement"][0]
    assert got_stmt == want_stmt, f"expected statement to roundtrip verbatim as {want_stmt!r}, got {got_stmt!r}"

    # Remove the policy, then prove the delete took effect via an independent read.
    s3.delete_bucket_policy(Bucket=bucket)
    code, message = _error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert code == "NoSuchBucketPolicy", f"expected NoSuchBucketPolicy after delete, got {code!r}"
    assert message == "The bucket policy does not exist", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
