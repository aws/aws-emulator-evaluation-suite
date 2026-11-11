"""xsvc-s3control-tag-resource-visible-through-s3-get-bucket-tagging."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-s3control-tag-resource-visible-through-s3-get-bucket-tagging"
GROUP = "representation"
SERVICES = ["s3", "s3control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags written with S3Control's generic TagResource on a bucket ARN are visible, value for
    value, through S3 GetBucketTagging, which reported NoSuchTagSet before the write.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_TagResource.html
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-xsvc-s3ctagwrite-")

    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    arn = f"arn:aws:s3:::{bucket}"

    # Before the write: S3's own tagging API has nothing to read.
    err = _error(lambda: s3.get_bucket_tagging(Bucket=bucket))
    want = ("NoSuchTagSet", "The TagSet does not exist")
    assert err == want, f"GetBucketTagging on an untagged bucket returned {err!r}, expected {want!r}"

    s3c.tag_resource(
        AccountId=account,
        ResourceArn=arn,
        Tags=[
            {"Key": "Team", "Value": "platform"},
            {"Key": "CostCenter", "Value": "engineering"},
        ],
    )

    tagging = s3.get_bucket_tagging(Bucket=bucket)
    seen = {t["Key"]: t["Value"] for t in tagging["TagSet"]}
    assert len(seen) == 2, f"after s3control.tag_resource, s3.get_bucket_tagging sees {seen!r}"
    assert seen.get("Team") == "platform", (
        f"s3.get_bucket_tagging read Team={seen.get('Team')!r}, expected 'platform'"
    )
    assert seen.get("CostCenter") == "engineering", (
        f"s3.get_bucket_tagging read CostCenter={seen.get('CostCenter')!r}, expected 'engineering'"
    )


def _error(fn) -> tuple:
    """(code, message) of the AWS error ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _error_code(fn):
    """The AWS error code raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("call unexpectedly succeeded; an error code was expected")


def _delete_bucket(s3, name: str) -> None:
    """Delete the bucket; one that is already gone is not an error, any other failure raises."""
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
