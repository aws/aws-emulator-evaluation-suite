"""update-network-migration-definition-full-overwrite."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-network-migration-definition-full-overwrite"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNetworkMigrationDefinition with a complete targetNetwork block sets every nested field;
    with only topology, it merges into the existing block and leaves the omitted CIDRs unchanged.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-overwrite-")

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
        tags={"sim2real": "1"},
    )
    nmd_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))
    assert created["targetNetwork"]["topology"] == "ISOLATED_VPC", (
        f"expected created topology ISOLATED_VPC, got {created['targetNetwork'].get('topology')!r}"
    )

    updated = mgn.update_network_migration_definition(
        networkMigrationDefinitionID=nmd_id,
        targetNetwork={
            "topology": "HUB_AND_SPOKE",
            "inboundCidr": "192.168.0.0/24",
            "outboundCidr": "192.168.1.0/24",
            "inspectionCidr": "192.168.2.0/24",
        },
    )
    assert updated["targetNetwork"]["topology"] == "HUB_AND_SPOKE", (
        f"expected updated topology HUB_AND_SPOKE, got {updated['targetNetwork'].get('topology')!r}"
    )
    assert updated["targetNetwork"]["inboundCidr"] == "192.168.0.0/24", (
        f"expected updated inboundCidr 192.168.0.0/24, got {updated['targetNetwork'].get('inboundCidr')!r}"
    )
    assert updated["targetNetwork"]["outboundCidr"] == "192.168.1.0/24", (
        f"expected updated outboundCidr 192.168.1.0/24, got {updated['targetNetwork'].get('outboundCidr')!r}"
    )
    assert updated["targetNetwork"]["inspectionCidr"] == "192.168.2.0/24", (
        f"expected updated inspectionCidr 192.168.2.0/24, got {updated['targetNetwork'].get('inspectionCidr')!r}"
    )
    # name must be unaffected by an update that only sets targetNetwork.
    assert updated["name"] == name, f"expected name unaffected ({name!r}), got {updated.get('name')!r}"

    fetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert fetched["targetNetwork"]["topology"] == "HUB_AND_SPOKE", (
        f"expected fetched topology HUB_AND_SPOKE, got {fetched['targetNetwork'].get('topology')!r}"
    )
    assert fetched["targetNetwork"]["inboundCidr"] == "192.168.0.0/24", (
        f"expected fetched inboundCidr 192.168.0.0/24, got {fetched['targetNetwork'].get('inboundCidr')!r}"
    )

    # The decisive leg: a *partial* targetNetwork (topology
    # only) on a second update merges into the existing nested object -- the prior CIDRs
    # from the first update must survive untouched, not come back cleared.
    reupdated = mgn.update_network_migration_definition(
        networkMigrationDefinitionID=nmd_id,
        targetNetwork={"topology": "ISOLATED_VPC"},
    )
    assert reupdated["targetNetwork"]["topology"] == "ISOLATED_VPC", (
        f"expected re-updated topology ISOLATED_VPC, got {reupdated['targetNetwork'].get('topology')!r}"
    )
    assert reupdated["targetNetwork"]["inboundCidr"] == "192.168.0.0/24", (
        "a partial targetNetwork (topology only) must merge into the existing nested object, "
        f"preserving the prior inboundCidr -- got {reupdated['targetNetwork'].get('inboundCidr')!r}"
    )
    assert reupdated["targetNetwork"]["outboundCidr"] == "192.168.1.0/24", (
        "a partial targetNetwork (topology only) must preserve the prior outboundCidr -- "
        f"got {reupdated['targetNetwork'].get('outboundCidr')!r}"
    )
    assert reupdated["targetNetwork"]["inspectionCidr"] == "192.168.2.0/24", (
        "a partial targetNetwork (topology only) must preserve the prior inspectionCidr -- "
        f"got {reupdated['targetNetwork'].get('inspectionCidr')!r}"
    )

    refetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert refetched["targetNetwork"]["topology"] == "ISOLATED_VPC", (
        f"expected refetched topology ISOLATED_VPC, got {refetched['targetNetwork'].get('topology')!r}"
    )
    assert refetched["targetNetwork"]["inboundCidr"] == "192.168.0.0/24", (
        "the merged (preserved) inboundCidr from a partial targetNetwork update must persist "
        f"across an independent read, got {refetched['targetNetwork'].get('inboundCidr')!r}"
    )


def _make_source_object(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mgn-nmd-src-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint on CreateBucket.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "1"}]})
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
