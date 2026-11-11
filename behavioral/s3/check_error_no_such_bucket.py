"""error-no-such-bucket."""

from __future__ import annotations
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "error-no-such-bucket"
GROUP = 'errors'
SERVICES = ['s3']

ERR_NO_SUCH_BUCKET = "NoSuchBucket"

def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


def _delete_bucket(client, bucket):
    """Delete the check's probe object and bucket; raises unless gone."""
    try:
        client.delete_object(Bucket=bucket, Key="probe")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject on an existing bucket and key returns its bytes, and on a bucket that never existed
    fails with NoSuchBucket and its exact message."""
    s3 = ctx.client("s3")

    real_bucket = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": real_bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, real_bucket))
    s3.put_object(Bucket=real_bucket, Key="probe", Body=b"ok")

    control = s3.get_object(Bucket=real_bucket, Key="probe")
    assert control["Body"].read() == b"ok", "positive control: GetObject on a real bucket/key must succeed"

    ghost = f"sim2real-behav-ghost-{uuid.uuid4().hex[:8]}"
    err = _err(lambda: s3.get_object(Bucket=ghost, Key="any"), f"GetObject on never-created bucket {ghost!r}")
    assert err.get("Code") == ERR_NO_SUCH_BUCKET, f"expected {ERR_NO_SUCH_BUCKET}, got {err!r}"
    assert err.get("Message") == "The specified bucket does not exist", err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
