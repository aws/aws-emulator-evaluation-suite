"""object-tagging-exceeds-limit-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-tagging-exceeds-limit-rejected"
GROUP = 'tagging'
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


def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectTagging with more than 10 tags must fail (overly-permissive boundary: S3 caps object tags at 10)."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "overtagged.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"x")

    # positive control: a tag set exactly at the limit (10) must be accepted, so a later
    # rejection of 11 is provably about the count, not a target that rejects every request
    at_limit = {f"k{i}": f"v{i}" for i in range(10)}
    s3.put_object_tagging(
        Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in at_limit.items()]}
    )
    control = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert control == at_limit, f"expected the at-limit tag set to be accepted, got {control}"

    # break exactly one thing: one tag beyond the limit
    too_many = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(11)]
    code, message = _client_error(lambda: s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": too_many}))
    assert code == "BadRequest", f"expected BadRequest for >10 tags, got {code!r}"
    assert message == "Object tags cannot be greater than 10", f"unexpected message {message!r}"

    # the rejected write must not have applied, merged or partially replaced the prior tag set
    after = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert after == at_limit, f"expected the at-limit tag set unchanged after rejection, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
