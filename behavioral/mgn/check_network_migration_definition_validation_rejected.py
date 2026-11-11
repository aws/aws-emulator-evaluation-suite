"""network-migration-definition-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-definition-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNetworkMigrationDefinition refuses a targetNetwork CIDR outside the dotted-quad /16-/28
    pattern with BadRequestException and creates nothing, while the well-formed request succeeds.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-badcidr-")

    def _source_config() -> dict:
        return {
            "sourceEnvironment": "LOGICAL_MODEL",
            "sourceS3Configuration": {
                "s3Bucket": src_bucket,
                "s3BucketOwner": account_id,
                "s3Key": src_key,
            },
        }

    code, message = None, None
    try:
        mgn.create_network_migration_definition(
            name=name,
            sourceConfigurations=[_source_config()],
            targetS3Configuration={"s3Bucket": src_bucket, "s3BucketOwner": account_id},
            targetNetwork={
                "topology": "ISOLATED_VPC",
                "inboundCidr": "not-a-cidr",
                "outboundCidr": "10.0.1.0/24",
                "inspectionCidr": "10.0.2.0/24",
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "BadRequestException", (
        f"CreateNetworkMigrationDefinition with a malformed inboundCidr must raise "
        f"BadRequestException, got {code!r}"
    )
    assert message == "Invalid request body", (
        f"CreateNetworkMigrationDefinition with a malformed inboundCidr must answer "
        f"'Invalid request body', got {message!r}"
    )

    listed = mgn.list_network_migration_definitions(filters={})["items"]
    assert not any(item["name"] == name for item in listed), (
        "a request rejected with BadRequestException must not have created a definition"
    )

    # Positive control: the same shape with a valid CIDR succeeds and cleans up.
    good_name = ctx.unique_name("sim2real-mgn-nmd-goodcidr-")
    created = mgn.create_network_migration_definition(
        name=good_name,
        sourceConfigurations=[_source_config()],
        targetS3Configuration={"s3Bucket": src_bucket, "s3BucketOwner": account_id},
        targetNetwork={
            "topology": "ISOLATED_VPC",
            "inboundCidr": "10.0.0.0/24",
            "outboundCidr": "10.0.1.0/24",
            "inspectionCidr": "10.0.2.0/24",
        },
        tags={"sim2real-check": "network-migration-definition-validation-rejected"},
    )
    nmd_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))
    assert created["name"] == good_name

    # Terminal assertion is an independent read (GetNetworkMigrationDefinition), not the
    # CreateNetworkMigrationDefinition response that produced it.
    fetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert fetched["name"] == good_name, (
        f"an independent read of the created definition must show name {good_name!r}, "
        f"got {fetched.get('name')!r}"
    )
    assert fetched["targetNetwork"]["inboundCidr"] == "10.0.0.0/24", (
        "an independent read of the created definition must show the well-formed inboundCidr "
        f"that was accepted, got {fetched.get('targetNetwork', {}).get('inboundCidr')!r}"
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
