"""network-migration-definition-partial-update-preserves-other-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-definition-partial-update-preserves-other-fields"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNetworkMigrationDefinition with only 'description' set must change the
    description in place while leaving unrelated fields (name, targetNetwork) untouched --
    a partial-update/upsert semantics check distinct from the full create/rename roundtrip."""
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-partial-")

    created = mgn.create_network_migration_definition(
        name=name,
        description="original description",
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
        tags={"sim2real": CHECK},
    )
    nmd_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))

    updated = mgn.update_network_migration_definition(
        networkMigrationDefinitionID=nmd_id, description="updated description only"
    )
    assert updated["description"] == "updated description only"
    assert updated["name"] == name, "an update touching only description must not clear name"
    assert updated["targetNetwork"]["topology"] == "ISOLATED_VPC", (
        "an update touching only description must not clear targetNetwork"
    )
    assert updated["targetNetwork"]["inboundCidr"] == "10.0.0.0/24"

    fetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert fetched["description"] == "updated description only"
    assert fetched["name"] == name
    assert fetched["targetNetwork"]["inboundCidr"] == "10.0.0.0/24"


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
