"""cors-delete."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cors-delete"
GROUP = 'cors'
SERVICES = ['s3']

_NO_CORS = ("NoSuchCORSConfiguration", 'The CORS configuration does not exist')

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
        # S3 requires CreateBucket to omit LocationConstraint when the target is us-east-1.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBucketCors removes CORS config; subsequent GET fails with NoSuchCORSConfiguration."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    cors_config = {
        "CORSRules": [
            {
                "AllowedMethods": ["GET"],
                "AllowedOrigins": ["*"],
            }
        ]
    }
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration=cors_config)

    # positive control: the config is actually there before we delete it
    before = s3.get_bucket_cors(Bucket=bucket)
    assert before["CORSRules"][0]["AllowedOrigins"] == ["*"], (
        f"expected the CORS rule just written, got {before.get('CORSRules')!r}"
    )

    s3.delete_bucket_cors(Bucket=bucket)
    gone = _error(lambda: s3.get_bucket_cors(Bucket=bucket))
    assert gone == _NO_CORS, f"expected {_NO_CORS!r} after CORS deletion, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
