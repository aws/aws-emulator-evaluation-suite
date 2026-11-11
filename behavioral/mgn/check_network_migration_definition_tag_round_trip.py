"""network-migration-definition-tag-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-definition-tag-round-trip"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a NetworkMigrationDefinition, visible via
    ListTagsForResource, and UntagResource removes them again."""
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-tag-")

    created = mgn.create_network_migration_definition(
        name=name,
        sourceConfigurations=[
            {
                "sourceEnvironment": "LOGICAL_MODEL",
                "sourceS3Configuration": {
                    "s3Bucket": src_bucket,
                    "s3BucketOwner": account_id,
                    "s3Key": src_key,
                },
            }
        ],
        targetS3Configuration={"s3Bucket": src_bucket, "s3BucketOwner": account_id},
        targetNetwork={
            "topology": "ISOLATED_VPC",
            "inboundCidr": "10.0.0.0/24",
            "outboundCidr": "10.0.1.0/24",
            "inspectionCidr": "10.0.2.0/24",
        },
    )
    nmd_id = created["networkMigrationDefinitionID"]
    nmd_arn = created["arn"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))

    mgn.tag_resource(resourceArn=nmd_arn, tags={"sim2real-key": "sim2real-value"})
    tags = mgn.list_tags_for_resource(resourceArn=nmd_arn)["tags"]
    assert tags.get("sim2real-key") == "sim2real-value", (
        f"ListTagsForResource must reflect the tag just applied by TagResource, got {tags!r}"
    )

    mgn.untag_resource(resourceArn=nmd_arn, tagKeys=["sim2real-key"])
    tags = mgn.list_tags_for_resource(resourceArn=nmd_arn)["tags"]
    assert "sim2real-key" not in tags, (
        f"ListTagsForResource must no longer show the tag after UntagResource, got {tags!r}"
    )


def _make_source_object(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mgn-nmd-src-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    key = "sim2real/source-model.json"
    s3.put_object(Bucket=bucket, Key=key, Body=b"{}")

    def _cleanup():
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket, key


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
