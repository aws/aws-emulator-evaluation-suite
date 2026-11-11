"""if-modified-since."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "if-modified-since"
GROUP = 'conditional'
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject honors If-Modified-Since in both directions: a date before the object's
    creation returns the object, and the object's own Last-Modified value — under which the
    object has, by definition, not been modified since — returns 304 Not Modified."""
    from datetime import datetime, timezone
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")

    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="mod.txt", Body=b"modified-since-test")
    # A date in the past — object was modified after this, so it SHOULD be returned
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    resp = s3.get_object(Bucket=bucket, Key="mod.txt", IfModifiedSince=past)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 for If-Modified-Since={past.isoformat()}, got {status}"
    body = resp["Body"].read()
    assert body == b"modified-since-test", f"expected 'modified-since-test', got {body!r}"
    last_modified = resp["LastModified"]

    # If-Modified-Since set to the object's own Last-Modified — it has not been modified since
    # itself, so this direction MUST 304. Without this leg, a target that ignores the header
    # entirely and always returns the object would pass the check above unchanged.
    try:
        s3.get_object(Bucket=bucket, Key="mod.txt", IfModifiedSince=last_modified)
        raise AssertionError(
            f"expected 304 for If-Modified-Since={last_modified.isoformat()} "
            "(the object's own Last-Modified), but the request succeeded"
        )
    except ClientError as exc:
        not_modified_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert not_modified_status == 304, (
            f"expected 304, got status {not_modified_status}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
