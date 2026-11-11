"""tag-resource-upserts-existing-bucket-tags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-upserts-existing-bucket-tags"
GROUP = "tagging"
SERVICES = ["s3control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a general-purpose bucket upserts: it adds a new key, updates an existing
    key's value, and leaves untouched keys alone rather than replacing the whole tag set.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-s3ctag-")

    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    arn = f"arn:aws:s3:::{bucket}"

    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [
            {"Key": "Environment", "Value": "dev"},
            {"Key": "ManagedBy", "Value": "terraform"},
        ]},
    )

    before = _tags_dict(s3c, account, arn)
    assert before == {"Environment": "dev", "ManagedBy": "terraform"}, (
        f"baseline tag set read back as {before!r}"
    )

    # Update one existing key and add one new key; ManagedBy is deliberately untouched.
    s3c.tag_resource(
        AccountId=account,
        ResourceArn=arn,
        Tags=[
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Brand", "Value": "new"},
        ],
    )

    after = _tags_dict(s3c, account, arn)
    assert len(after) == 3, (
        f"after an upsert touching 2 of 3 keys, ListTagsForResource holds {len(after)} "
        f"keys ({after!r}); expected exactly 3"
    )
    assert after["Brand"] == "new", f"the new key Brand read back as {after.get('Brand')!r}"
    assert after["Environment"] == "prod", (
        f"the updated key Environment read back as {after.get('Environment')!r}, expected 'prod'"
    )
    assert after["ManagedBy"] == "terraform", (
        f"the untouched key ManagedBy read back as {after.get('ManagedBy')!r}; "
        "a replace semantics would have dropped it"
    )


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
