"""put-bucket-accelerate-configuration-dotted-bucket-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bucket-accelerate-configuration-dotted-bucket-name-rejected"
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
    """PutBucketAccelerateConfiguration is rejected on a bucket whose name contains a period,
    because Transfer Acceleration requires a DNS-compliant name; a sibling bucket without a
    period accepts the identical call."""
    s3 = ctx.client("s3")

    dotted = f"{ctx.unique_name('sim2real-accel-')}.dotted"
    _create_bucket(ctx, dotted)

    code, message = _error(
        lambda: s3.put_bucket_accelerate_configuration(
            Bucket=dotted, AccelerateConfiguration={"Status": "Enabled"}
        )
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}: {message!r}"
    assert message == (
        "S3 Transfer Acceleration is not supported for buckets with periods (.) in their names"
    ), f"unexpected message {message!r}"

    # effect absent: the rejected PUT never set a status on the dotted bucket
    unset = s3.get_bucket_accelerate_configuration(Bucket=dotted)
    assert "Status" not in unset, f"expected no Status after the rejected PUT, got {unset!r}"

    # positive control: the identical call on a sibling bucket with no period is accepted
    plain = ctx.unique_name("sim2real-accel-")
    _create_bucket(ctx, plain)
    s3.put_bucket_accelerate_configuration(Bucket=plain, AccelerateConfiguration={"Status": "Enabled"})
    enabled = s3.get_bucket_accelerate_configuration(Bucket=plain)
    assert enabled["Status"] == "Enabled", f"expected Enabled on the plain bucket, got {enabled!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
