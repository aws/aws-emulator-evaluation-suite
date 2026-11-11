"""update-network-migration-definition-blank-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-network-migration-definition-blank-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateNetworkMigrationDefinition with a whitespace-only name fails with BadRequestException
    and leaves the definition's stored name unchanged.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-blankname-")

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
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))

    positive_description = "sim2real audit positive control"
    positive = mgn.update_network_migration_definition(
        networkMigrationDefinitionID=nmd_id, description=positive_description
    )
    assert positive["description"] == positive_description, (
        "a valid UpdateNetworkMigrationDefinition call (description-only) must succeed before "
        f"the whitespace-name rejection is exercised, got description={positive.get('description')!r}"
    )

    code, message = None, None
    try:
        mgn.update_network_migration_definition(networkMigrationDefinitionID=nmd_id, name="   ")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "BadRequestException", (
        f"UpdateNetworkMigrationDefinition with a whitespace-only name must raise "
        f"BadRequestException, got {code!r}"
    )
    assert message == "Invalid request body", (
        f"UpdateNetworkMigrationDefinition with a whitespace-only name must answer "
        f"'Invalid request body', got {message!r}"
    )

    fetched = mgn.get_network_migration_definition(networkMigrationDefinitionID=nmd_id)
    assert fetched["name"] == name, "a rejected update must not have changed the stored name"


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
