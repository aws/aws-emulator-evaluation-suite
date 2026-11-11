"""untag-resource-removes-specific-bucket-tag-keys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-specific-bucket-tag-keys"
GROUP = "tagging"
SERVICES = ["s3control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the named keys from a bucket's tag set; every other key keeps
    its original value.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-s3cuntag-")

    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    arn = f"arn:aws:s3:::{bucket}"

    s3c.tag_resource(
        AccountId=account,
        ResourceArn=arn,
        Tags=[{"Key": "Keep", "Value": "me"}, {"Key": "Remove", "Value": "me"}],
    )

    before = _tags_dict(s3c, account, arn)
    assert before == {"Keep": "me", "Remove": "me"}, (
        f"baseline tag set before untagging read back as {before!r}"
    )

    s3c.untag_resource(AccountId=account, ResourceArn=arn, TagKeys=["Remove"])

    after = _tags_dict(s3c, account, arn)
    assert "Remove" not in after, f"UntagResource(['Remove']) left tags {after!r}"
    assert after.get("Keep") == "me", (
        f"the untouched key Keep read back as {after.get('Keep')!r} after untagging a sibling key"
    )
    assert len(after) == 1, f"expected exactly one surviving tag, got {after!r}"


# ===== helpers =====

def _tags_dict(s3c, account: str, arn: str) -> dict:
    resp = s3c.list_tags_for_resource(AccountId=account, ResourceArn=arn)
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}


def _delete_bucket(s3, name: str) -> None:
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
