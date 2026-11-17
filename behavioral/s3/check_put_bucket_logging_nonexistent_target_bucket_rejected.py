"""put-bucket-logging-nonexistent-target-bucket-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bucket-logging-nonexistent-target-bucket-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketLogging naming a TargetBucket that does not exist is rejected rather than
    accepted and silently un-deliverable; the identical call naming a bucket this account
    owns is accepted."""
    s3 = ctx.client("s3")

    source = ctx.unique_name("sim2real-logsrc-")
    _create_bucket(ctx, source)

    ghost_target = ctx.unique_name("sim2real-logtgt-ghost-")
    code, message = _error(
        lambda: s3.put_bucket_logging(
            Bucket=source,
            BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": ghost_target, "TargetPrefix": "logs/"}},
        )
    )
    assert code == "InvalidTargetBucketForLogging", f"expected InvalidTargetBucketForLogging, got {code!r}: {message!r}"
    assert message == "The target bucket for logging does not exist", f"unexpected message {message!r}"

    # effect absent: the rejected PUT never set a logging configuration on the source
    unset = s3.get_bucket_logging(Bucket=source)
    assert "LoggingEnabled" not in unset, f"expected no LoggingEnabled after the rejected PUT, got {unset!r}"

    # positive control: the identical call naming a bucket this account actually owns is accepted
    real_target = ctx.unique_name("sim2real-logtgt-")
    _create_bucket(ctx, real_target)
    s3.put_bucket_logging(
        Bucket=source,
        BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": real_target, "TargetPrefix": "logs/"}},
    )
    enabled = s3.get_bucket_logging(Bucket=source)["LoggingEnabled"]
    assert enabled["TargetBucket"] == real_target, f"expected TargetBucket {real_target!r}, got {enabled!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
