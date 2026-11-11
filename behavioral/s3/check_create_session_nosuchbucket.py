"""create-session-nosuchbucket."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-session-nosuchbucket"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSession on a bucket that does not exist fails with NoSuchBucket and its exact message,
    while the same call on an existing bucket raises nothing."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # Positive control: CreateSession against an existing bucket must not raise.
    s3.create_session(Bucket=bucket)

    missing_bucket = ctx.unique_name("sim2real-nobucket-")
    err = _error(lambda: s3.create_session(Bucket=missing_bucket))
    assert err == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"expected NoSuchBucket with AWS's exact message, got {err!r}"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _error(fn):
    """Call fn(); return the ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
