"""get-network-migration-definition-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-network-migration-definition-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetNetworkMigrationDefinition on an id never created fails with ResourceNotFoundException,
    while the same call on a definition the check created returns it.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-getnf-")

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
        tags={"sim2real-check": CHECK},
    )
    real_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=real_id))

    # Positive control: the real id, on the same operation under test, must be readable.
    positive = mgn.get_network_migration_definition(networkMigrationDefinitionID=real_id)
    assert positive["networkMigrationDefinitionID"] == real_id, (
        f"positive control: GetNetworkMigrationDefinition on a real id must return that id, "
        f"got {positive.get('networkMigrationDefinitionID')!r}"
    )

    fake_id = "nmd-" + "0" * 17
    assert fake_id != real_id, "fabricated id collided with the real one -- pick a different filler"

    code, message = None, None
    result = None
    try:
        result = mgn.get_network_migration_definition(networkMigrationDefinitionID=fake_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert result is None, f"a nonexistent networkMigrationDefinitionID must not return a body, got {result!r}"
    assert code == "ResourceNotFoundException", (
        f"GetNetworkMigrationDefinition on a nonexistent id must raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected_message = f"NetworkMigrationDefinition with Id: '{fake_id}' was not found"
    assert message == expected_message, (
        f"GetNetworkMigrationDefinition on a nonexistent id must answer {expected_message!r}, "
        f"got {message!r}"
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
