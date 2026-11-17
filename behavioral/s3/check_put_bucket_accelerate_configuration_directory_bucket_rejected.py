"""put-bucket-accelerate-configuration-directory-bucket-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from botocore.config import Config
from behavioral_harness import tags

CHECK = "put-bucket-accelerate-configuration-directory-bucket-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

# S3 Express One Zone directory buckets are Zonal: the AZ segment is part of the bucket name
# and must be a real AZ ID in the region under test.
_S3EXPRESS_AZ_BY_REGION = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


def _s3_control(ctx):
    """S3 for a directory bucket's control calls, which AWS serves without an S3 Express session."""
    return ctx.client("s3", config=Config(s3={"disable_s3_express_session_auth": True}))


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_directory_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    azs = _S3EXPRESS_AZ_BY_REGION.get(ctx.region)
    assert azs, f"no known S3 Express One Zone AZ id for region {ctx.region!r}"
    base = ctx.unique_name("sim2real-accdir-").lower().rstrip("-")
    last_error = None
    for az in azs:
        bucket = f"{base}--{az}--x-s3"
        try:
            _s3_control(ctx).create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last_error = exc
            continue
        ctx.on_cleanup(lambda name=bucket: _s3_control(ctx).delete_bucket(Bucket=name))
        return bucket
    raise AssertionError(f"could not create a directory bucket in any AZ of {ctx.region}: {last_error}")


def _create_general_purpose_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-accgp-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    _s3_control(ctx).create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _s3_control(ctx).delete_bucket(Bucket=name))
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketAccelerateConfiguration is rejected on a directory bucket, which has no
    Transfer Acceleration concept; the identical call on a general purpose bucket is accepted."""
    s3 = ctx.client("s3")

    directory_bucket = _create_directory_bucket(ctx)
    code, message = _error(
        lambda: _s3_control(ctx).put_bucket_accelerate_configuration(
            Bucket=directory_bucket, AccelerateConfiguration={"Status": "Enabled"}
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}: {message!r}"
    assert message == (
        "AccelerateConfiguration is not valid, expected CreateBucketConfiguration"
    ), f"unexpected message {message!r}"

    # effect absent: a directory bucket carries no accelerate status at all
    unset_code, unset_message = _error(lambda: _s3_control(ctx).get_bucket_accelerate_configuration(Bucket=directory_bucket))
    assert unset_code == "MethodNotAllowed", (
        f"expected GetBucketAccelerateConfiguration to be refused, got {unset_code!r}: {unset_message!r}"
    )
    assert unset_message == "The specified method is not allowed against this resource.", (
        f"unexpected message {unset_message!r}"
    )

    # positive control: the identical PutBucketAccelerateConfiguration on a general purpose
    # bucket is accepted and reads back through GetBucketAccelerateConfiguration.
    general_bucket = _create_general_purpose_bucket(ctx)
    _s3_control(ctx).put_bucket_accelerate_configuration(
        Bucket=general_bucket, AccelerateConfiguration={"Status": "Enabled"}
    )
    enabled = _s3_control(ctx).get_bucket_accelerate_configuration(Bucket=general_bucket)
    assert enabled["Status"] == "Enabled", f"expected Enabled on the general purpose bucket, got {enabled!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
