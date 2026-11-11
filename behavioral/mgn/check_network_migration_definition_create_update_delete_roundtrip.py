"""network-migration-definition-create-update-delete-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-definition-create-update-delete-roundtrip"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkMigrationDefinition persists its network and S3 configuration, the update changes
    name and description in place, and the delete removes it, each visible through
    GetNetworkMigrationDefinition and ListNetworkMigrationDefinitions.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-")

    created = mgn.create_network_migration_definition(
        name=name,
        description="sim2real behavioral check",
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
        tags={"sim2real-key": "sim2real-value"},
    )
    nmd_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: _delete_if_present(mgn, nmd_id))
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["targetNetwork"]["topology"] == "ISOLATED_VPC", (
        f"expected targetNetwork.topology ISOLATED_VPC, got {created['targetNetwork']['topology']!r}"
    )
    assert created["networkMigrationDefinitionID"].startswith("nmd-"), (
        f"expected networkMigrationDefinitionID to start with 'nmd-', got {nmd_id!r}"
    )

    fetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert fetched["name"] == name, f"expected fetched name {name!r}, got {fetched['name']!r}"
    assert fetched["targetNetwork"]["inboundCidr"] == "10.0.0.0/24", (
        f"expected inboundCidr 10.0.0.0/24, got {fetched['targetNetwork']['inboundCidr']!r}"
    )

    new_name = name + "-renamed"
    updated = mgn.update_network_migration_definition(
        networkMigrationDefinitionID=nmd_id, name=new_name, description="updated description"
    )
    assert updated["name"] == new_name, f"expected updated name {new_name!r}, got {updated['name']!r}"
    assert updated["description"] == "updated description", (
        f"expected updated description 'updated description', got {updated['description']!r}"
    )

    listed = mgn.list_network_migration_definitions(
        filters={"networkMigrationDefinitionIDs": [nmd_id]}
    )["items"]
    assert len(listed) == 1, f"expected exactly 1 listed item for {nmd_id}, got {len(listed)}"
    assert listed[0]["name"] == new_name, (
        f"expected list to reflect renamed name {new_name!r}, got {listed[0]['name']!r}"
    )

    mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    remaining = mgn.list_network_migration_definitions(
        filters={"networkMigrationDefinitionIDs": [nmd_id]}
    )["items"]
    assert remaining == [], f"deleted network migration definition must not appear in the list, got {remaining!r}"

    expected_message = f"NetworkMigrationDefinition with Id: '{nmd_id}' was not found"
    code, message = None, None
    try:
        mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ResourceNotFoundException", (
        f"GetNetworkMigrationDefinition on a deleted id must raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert message == expected_message, (
        f"GetNetworkMigrationDefinition on a deleted id must answer {expected_message!r}, "
        f"got {message!r}"
    )

    update_code, update_message = None, None
    try:
        mgn.update_network_migration_definition(networkMigrationDefinitionID=nmd_id, name=new_name + "-again")
    except ClientError as exc:
        update_code = exc.response.get("Error", {}).get("Code")
        update_message = exc.response.get("Error", {}).get("Message")
    assert update_code == "ResourceNotFoundException", (
        f"UpdateNetworkMigrationDefinition on a deleted id must raise ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"UpdateNetworkMigrationDefinition on a deleted id must answer {expected_message!r}, "
        f"got {update_message!r}"
    )


def _delete_if_present(mgn, nmd_id):
    try:
        mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _make_source_object(ctx):
    """CreateNetworkMigrationDefinition validates that sourceS3Configuration points at a
    real, existing S3 object ('Source S3 object not found' otherwise), so this creates
    a small real bucket+object and registers its teardown."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mgn-nmd-src-").lower()
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this branches on API mechanics, not on pinning the check to a region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-key", "Value": "sim2real-value"}]})
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
