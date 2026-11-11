"""xsvc-s3-bucket-tags-visible-through-s3control-generic-tagging."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-s3-bucket-tags-visible-through-s3control-generic-tagging"
GROUP = "representation"
SERVICES = ["s3", "s3control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags written with S3 PutBucketTagging are visible, value for value, through S3Control's
    generic ListTagsForResource on the bucket's ARN, so both APIs share one tag store.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_ListTagsForResource.html
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-xsvc-s3ctagread-")

    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    arn = f"arn:aws:s3:::{bucket}"

    # Before the write: s3control sees no tags on a bucket S3 never tagged.
    before = _tags_dict(s3c, account, arn)
    assert before == {}, f"an untagged bucket's s3control tags read back as {before!r}"

    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [
            {"Key": "Environment", "Value": "dev"},
            {"Key": "ManagedBy", "Value": "terraform"},
        ]},
    )

    after = _tags_dict(s3c, account, arn)
    assert len(after) == 2, f"after s3.put_bucket_tagging, s3control sees {after!r}"
    assert after.get("Environment") == "dev", (
        f"s3control read Environment={after.get('Environment')!r}, expected 'dev'"
    )
    assert after.get("ManagedBy") == "terraform", (
        f"s3control read ManagedBy={after.get('ManagedBy')!r}, expected 'terraform'"
    )


def _tags_dict(s3c, account: str, arn: str) -> dict:
    resp = s3c.list_tags_for_resource(AccountId=account, ResourceArn=arn)
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}


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
